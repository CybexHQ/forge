#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char *message) {
    fprintf(stderr, "cybex-forge-secure-input: %s\n", message);
    exit(EXIT_FAILURE);
}

static void fail_errno(const char *message) {
    fprintf(stderr, "cybex-forge-secure-input: %s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static bool same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static bool same_stable_metadata(const struct stat *left, const struct stat *right) {
    return same_identity(left, right) && left->st_mode == right->st_mode
        && left->st_uid == right->st_uid && left->st_gid == right->st_gid
        && left->st_nlink == right->st_nlink && left->st_size == right->st_size
        && left->st_mtim.tv_sec == right->st_mtim.tv_sec
        && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
        && left->st_ctim.tv_sec == right->st_ctim.tv_sec
        && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static uint64_t parse_u64(const char *value, const char *label) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fail(label);
    }
    return (uint64_t)parsed;
}

static bool allowed_mode(mode_t mode, bool secret) {
    mode &= 0777;
    if (secret) {
        return mode == 0400 || mode == 0600;
    }
    return mode == 0400 || mode == 0440 || mode == 0444 || mode == 0600
        || mode == 0640 || mode == 0644;
}

static void validate_source(const struct stat *metadata, uint64_t maximum, bool secret) {
    if (!S_ISREG(metadata->st_mode)) {
        fail("source is not a regular file");
    }
    if (metadata->st_uid != geteuid()) {
        fail("source is not owned by the effective user");
    }
    if (metadata->st_nlink != 1) {
        fail("source must have exactly one hard link");
    }
    if (!allowed_mode(metadata->st_mode, secret)) {
        fail("source permissions are unsafe");
    }
    if (metadata->st_size < 0 || (uint64_t)metadata->st_size > maximum) {
        fail("source exceeds its size limit");
    }
}

static int open_protected_parent(const char *path, char name[NAME_MAX + 1]) {
    size_t length = strlen(path);
    if (length == 0 || length >= PATH_MAX) {
        fail("source path length is invalid");
    }
    const char *slash = strrchr(path, '/');
    const char *base = slash == NULL ? path : slash + 1;
    size_t name_length = strlen(base);
    if (name_length == 0 || name_length > NAME_MAX
        || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        fail("source filename is invalid");
    }
    memcpy(name, base, name_length + 1);

    char parent[PATH_MAX];
    if (slash == NULL) {
        strcpy(parent, ".");
    } else if (slash == path) {
        strcpy(parent, "/");
    } else {
        size_t parent_length = (size_t)(slash - path);
        if (parent_length >= sizeof(parent)) {
            fail("source parent path length is invalid");
        }
        memcpy(parent, path, parent_length);
        parent[parent_length] = '\0';
    }

    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        fail_errno("open protected source parent");
    }
    struct stat metadata;
    if (fstat(directory, &metadata) != 0) {
        fail_errno("inspect protected source parent");
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid()
        || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        fail("source parent must be effective-user-owned and not group/other writable");
    }
    return directory;
}

static void print_identity(const struct stat *metadata) {
    printf("%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
           ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX "\n",
        (uintmax_t)metadata->st_dev, (uintmax_t)metadata->st_ino,
        (uintmax_t)metadata->st_size, (uintmax_t)metadata->st_mtim.tv_sec,
        (uintmax_t)metadata->st_mtim.tv_nsec, (uintmax_t)metadata->st_ctim.tv_sec,
        (uintmax_t)metadata->st_ctim.tv_nsec);
}

static void identify(const char *source, uint64_t maximum, bool secret) {
    int source_parent = -1;
    char source_name[NAME_MAX + 1] = {0};
    struct stat before_path;
    if (secret) {
        source_parent = open_protected_parent(source, source_name);
    }
    int inspect_result = secret
        ? fstatat(source_parent, source_name, &before_path, AT_SYMLINK_NOFOLLOW)
        : lstat(source, &before_path);
    if (inspect_result != 0 || S_ISLNK(before_path.st_mode)) {
        fail("could not inspect a regular source");
    }
    int input = secret
        ? openat(source_parent, source_name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        : open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (input < 0) {
        fail_errno("open source");
    }
    struct stat opened;
    struct stat after_path;
    int reinspect_result = secret
        ? fstatat(source_parent, source_name, &after_path, AT_SYMLINK_NOFOLLOW)
        : lstat(source, &after_path);
    if (fstat(input, &opened) != 0 || reinspect_result != 0) {
        fail_errno("inspect opened source");
    }
    validate_source(&opened, maximum, secret);
    if (!same_stable_metadata(&before_path, &opened)
        || !same_identity(&opened, &after_path) || S_ISLNK(after_path.st_mode)) {
        fail("source changed while its identity was bound");
    }
    print_identity(&opened);
    if (close(input) != 0
        || (source_parent >= 0 && close(source_parent) != 0)) {
        fail_errno("close identified source");
    }
}

static void snapshot(const char *source, const char *destination, uint64_t maximum, bool secret) {
    int source_parent = -1;
    char source_name[NAME_MAX + 1] = {0};
    struct stat before_path;
    if (secret) {
        source_parent = open_protected_parent(source, source_name);
    }
    int inspect_result = secret
        ? fstatat(source_parent, source_name, &before_path, AT_SYMLINK_NOFOLLOW)
        : lstat(source, &before_path);
    if (inspect_result != 0) {
        fail_errno("inspect source");
    }
    if (S_ISLNK(before_path.st_mode)) {
        fail("source must not be a symbolic link");
    }

    int input = secret
        ? openat(source_parent, source_name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        : open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (input < 0) {
        fail_errno("open source");
    }
    struct stat before_fd;
    if (fstat(input, &before_fd) != 0) {
        fail_errno("inspect opened source");
    }
    validate_source(&before_fd, maximum, secret);
    if (!same_identity(&before_path, &before_fd)) {
        fail("source changed while it was opened");
    }

    int output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) {
        fail_errno("create protected snapshot");
    }
    unsigned char buffer[4096];
    uint64_t copied = 0;
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count < 0) {
            fail_errno("read source");
        }
        if (count == 0) {
            break;
        }
        copied += (uint64_t)count;
        if (copied > maximum) {
            fail("source grew beyond its size limit");
        }
        for (ssize_t offset = 0; offset < count;) {
            ssize_t written = write(output, buffer + offset, (size_t)(count - offset));
            if (written < 0) {
                fail_errno("write protected snapshot");
            }
            offset += written;
        }
    }
    if (copied != (uint64_t)before_fd.st_size) {
        fail("source size changed while it was copied");
    }
    if (fsync(output) != 0 || close(output) != 0) {
        fail_errno("persist protected snapshot");
    }

    struct stat after_fd;
    struct stat after_path;
    int reinspect_result = secret
        ? fstatat(source_parent, source_name, &after_path, AT_SYMLINK_NOFOLLOW)
        : lstat(source, &after_path);
    if (fstat(input, &after_fd) != 0 || reinspect_result != 0) {
        fail_errno("reinspect source");
    }
    if (!same_stable_metadata(&before_fd, &after_fd)
        || !same_identity(&after_fd, &after_path) || S_ISLNK(after_path.st_mode)) {
        fail("source changed while it was copied");
    }
    if (close(input) != 0) {
        fail_errno("close source");
    }
    if (source_parent >= 0 && close(source_parent) != 0) {
        fail_errno("close protected source parent");
    }
    print_identity(&before_fd);
}

static void erase_if_same(const char *source, const char *identity) {
    uintmax_t expected_device;
    uintmax_t expected_inode;
    uintmax_t expected_size;
    uintmax_t expected_mtime_sec;
    uintmax_t expected_mtime_nsec;
    uintmax_t expected_ctime_sec;
    uintmax_t expected_ctime_nsec;
    char trailing;
    if (sscanf(identity,
            "%" SCNuMAX ":%" SCNuMAX ":%" SCNuMAX ":%" SCNuMAX
            ":%" SCNuMAX ":%" SCNuMAX ":%" SCNuMAX "%c",
            &expected_device, &expected_inode, &expected_size,
            &expected_mtime_sec, &expected_mtime_nsec,
            &expected_ctime_sec, &expected_ctime_nsec, &trailing) != 7) {
        fail("source identity is invalid");
    }

    char source_name[NAME_MAX + 1] = {0};
    int directory = open_protected_parent(source, source_name);
    struct stat path_metadata;
    if (fstatat(directory, source_name, &path_metadata, AT_SYMLINK_NOFOLLOW) != 0
        || S_ISLNK(path_metadata.st_mode)
        || (uintmax_t)path_metadata.st_dev != expected_device
        || (uintmax_t)path_metadata.st_ino != expected_inode) {
        fail("refusing to erase a replaced source path");
    }
    int fd = openat(directory, source_name,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        fail_errno("open source for erasure");
    }
    struct stat opened;
    if (fstat(fd, &opened) != 0) {
        fail_errno("inspect source for erasure");
    }
    if (!S_ISREG(opened.st_mode) || opened.st_uid != geteuid() || opened.st_nlink != 1
        || (uintmax_t)opened.st_dev != expected_device
        || (uintmax_t)opened.st_ino != expected_inode
        || opened.st_size < 0 || (uintmax_t)opened.st_size != expected_size
        || (uintmax_t)opened.st_mtim.tv_sec != expected_mtime_sec
        || (uintmax_t)opened.st_mtim.tv_nsec != expected_mtime_nsec
        || (uintmax_t)opened.st_ctim.tv_sec != expected_ctime_sec
        || (uintmax_t)opened.st_ctim.tv_nsec != expected_ctime_nsec) {
        fail("refusing to erase a source whose identity changed");
    }

    unsigned char zeros[4096] = {0};
    off_t offset = 0;
    while ((uintmax_t)offset < expected_size) {
        size_t remaining = (size_t)(expected_size - (uintmax_t)offset);
        size_t amount = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
        ssize_t written = pwrite(fd, zeros, amount, offset);
        if (written <= 0) {
            fail_errno("overwrite source");
        }
        offset += written;
    }
    if (fsync(fd) != 0) {
        fail_errno("persist source erasure");
    }
    struct stat final_fd;
    struct stat final_path;
    if (fstat(fd, &final_fd) != 0
        || fstatat(directory, source_name, &final_path, AT_SYMLINK_NOFOLLOW) != 0
        || !same_identity(&final_fd, &final_path)
        || (uintmax_t)final_fd.st_dev != expected_device
        || (uintmax_t)final_fd.st_ino != expected_inode) {
        fail("refusing to unlink a replaced source path");
    }
    if (unlinkat(directory, source_name, 0) != 0) {
        fail_errno("unlink erased source");
    }
    if (fsync(directory) != 0) {
        fail_errno("persist source unlink");
    }
    if (close(fd) != 0 || close(directory) != 0) {
        fail_errno("close erased source");
    }
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "identity") == 0) {
        uint64_t maximum = parse_u64(argv[3], "size limit is invalid");
        bool secret;
        if (strcmp(argv[4], "secret") == 0) {
            secret = true;
        } else if (strcmp(argv[4], "public") == 0) {
            secret = false;
        } else {
            fail("input class must be public or secret");
        }
        identify(argv[2], maximum, secret);
        return EXIT_SUCCESS;
    }
    if (argc == 6 && strcmp(argv[1], "snapshot") == 0) {
        uint64_t maximum = parse_u64(argv[4], "size limit is invalid");
        bool secret;
        if (strcmp(argv[5], "secret") == 0) {
            secret = true;
        } else if (strcmp(argv[5], "public") == 0) {
            secret = false;
        } else {
            fail("input class must be public or secret");
        }
        snapshot(argv[2], argv[3], maximum, secret);
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "erase-if-same") == 0) {
        erase_if_same(argv[2], argv[3]);
        return EXIT_SUCCESS;
    }
    fprintf(stderr,
        "usage: cybex-forge-secure-input identity SOURCE MAX public|secret\n"
        "       cybex-forge-secure-input snapshot SOURCE DEST MAX public|secret\n"
        "       cybex-forge-secure-input erase-if-same "
        "SOURCE DEVICE:INODE:SIZE:MTIME_SEC:MTIME_NSEC:CTIME_SEC:CTIME_NSEC\n");
    return EXIT_FAILURE;
}
