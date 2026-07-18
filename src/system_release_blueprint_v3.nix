{ config, lib, pkgs, ... }:

let
  cfg = config.cybex.desktop or { };
  environment = cfg.environment or "";
  profile = cfg.profile or "auto";
  envLower = lib.toLower environment;
  tilingCfg = cfg.tiling or { };
  taskbarCfg = cfg.taskbar or { };
  dockCfg = cfg.dock or { };
  kioskCfg = cfg.kiosk or { };
  minimalCfg = cfg.minimal or { };
  loginCfg = cfg.login or { };
  configuredGreeter = cfg.greeter or "auto";
  wallpaperCfg = cfg.wallpaper or { };
  restrictionsCfg = cfg.restrictions or { };
  enableTaskbar =
    profile == "taskbar"
    || profile == "plasma"
    || lib.hasInfix "kde" envLower
    || lib.hasInfix "plasma" envLower
    || lib.hasInfix "taskbar" envLower;
  enableDock =
    profile == "dock"
    || lib.hasInfix "dock" envLower;
  enableKiosk =
    profile == "kiosk"
    || lib.hasInfix "kiosk" envLower;
  enableMinimal =
    profile == "minimal"
    || lib.hasInfix "minimal" envLower;
  enableTiling =
    (tilingCfg.enable or false)
    || profile == "tiling"
    || lib.hasInfix "hyprland" envLower
    || lib.hasInfix "tiling" envLower;
  managedDesktop =
    profile != "auto"
    || environment != ""
    || (tilingCfg.enable or false);
  graphicalLogin = managedDesktop && profile != "server" && (loginCfg.mode or "greeter") != "none";
  greeter =
    if configuredGreeter != "auto" then configuredGreeter
    else if profile == "server" then "none"
    else if enableTaskbar then "sddm"
    else if enableTiling || profile == "sway" then "greetd"
    else "gdm";
  defaultSessionCommand =
    if enableTiling then "${hyprlandSession}/bin/cybex-hyprland-session"
    else if profile == "sway" then "${pkgs.sway}/bin/sway"
    else if enableTaskbar then "${pkgs.kdePackages.plasma-workspace}/bin/startplasma-wayland"
    else "${pkgs.dbus}/bin/dbus-run-session ${pkgs.gnome-session}/bin/gnome-session";

  hasPackage = name: builtins.hasAttr name pkgs;
  optionalPackage = name: lib.optional (hasPackage name) (builtins.getAttr name pkgs);

  firstAvailablePackage = names:
    let available = builtins.filter hasPackage names;
    in if available == [ ] then null else builtins.getAttr (builtins.head available) pkgs;

  shellName = tilingCfg.shell or "lumen";
  enableLumenShell = shellName == "lumen";
  lumenPackage = firstAvailablePackage [ "lumen" ];
  shellMarker = if enableLumenShell then "lumen" else "cybex";

  terminalName = tilingCfg.terminal or "kitty";
  terminalPackage =
    if terminalName == "foot" then pkgs.foot
    else if terminalName == "alacritty" then pkgs.alacritty
    else if terminalName == "konsole" then pkgs.kdePackages.konsole
    else pkgs.kitty;
  terminalCommand =
    if terminalName == "foot" then "${pkgs.foot}/bin/foot"
    else if terminalName == "alacritty" then "${pkgs.alacritty}/bin/alacritty"
    else if terminalName == "konsole" then "${pkgs.kdePackages.konsole}/bin/konsole"
    else "${pkgs.kitty}/bin/kitty";

  launcherName = tilingCfg.launcher or "walker";
  launcherPackage =
    if launcherName == "wofi" then pkgs.wofi
    else if launcherName == "rofi" then pkgs.rofi
    else if launcherName == "walker" then firstAvailablePackage [ "walker" ]
    else firstAvailablePackage [ "walker" "wofi" ];
  useWalkerLauncher =
    launcherPackage != null
    && (launcherPackage.pname or "") == "walker"
    && hasPackage "walker";
  launcherCommand =
    if launcherName == "wofi" || launcherPackage == pkgs.wofi then "${pkgs.wofi}/bin/wofi --conf /etc/xdg/wofi/config --style /etc/xdg/wofi/style.css --show drun"
    else if launcherName == "rofi" then "${pkgs.rofi}/bin/rofi -show drun"
    else if launcherPackage != null && hasPackage "walker" then "${launcherPackage}/bin/walker --width 640 --maxheight 460"
    else "${pkgs.wofi}/bin/wofi --conf /etc/xdg/wofi/config --style /etc/xdg/wofi/style.css --show drun";
  walkerServiceLine = lib.optionalString useWalkerLauncher ''
    exec-once = ${launcherPackage}/bin/walker --gapplication-service
  '';

  browserCommand = tilingCfg.browserCommand or null;
  browserEnabled = browserCommand != null;
  browserExecCommand = if browserEnabled then browserCommand else "${pkgs.coreutils}/bin/false";
  fileManagerCommand = tilingCfg.fileManagerCommand or "${pkgs.nautilus}/bin/nautilus --new-window";
  lockTimeoutSeconds = tilingCfg.lockTimeoutSeconds or 900;
  dpmsTimeoutSeconds = tilingCfg.dpmsTimeoutSeconds or 1200;
  screenshotDir = ''"$HOME/Pictures/Screenshots"'';
  digitalPalsColors = {
    mError = "#f38ba8";
    mHover = "#94e2d5";
    mOnError = "#11111b";
    mOnHover = "#11111b";
    mOnPrimary = "#11111b";
    mOnSecondary = "#11111b";
    mOnSurface = "#cdd6f4";
    mOnSurfaceVariant = "#a3b4eb";
    mOnTertiary = "#11111b";
    mOutline = "#4c4f69";
    mPrimary = "#cba6f7";
    mSecondary = "#fab387";
    mShadow = "#11111b";
    mSurface = "#1e1e2e";
    mSurfaceVariant = "#313244";
    mTertiary = "#94e2d5";
  };
  hexNoHash = value: lib.removePrefix "#" value;
  rgb = value: "rgb(${hexNoHash value})";
  rgba = value: alpha: "rgba(${hexNoHash value}${alpha})";
  digitalPalsWallpaper = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/DigitalPals/nixos-config/main/wallpapers/snow-capped-mountains-with-full-moon-lo.jpg";
    hash = "sha256-FTvH6pnM0U5wIDOXp1nawNia+ymTetIVzn0xsXeMAhc=";
  };
  lumenConfig = ''
    [styling]
    scale = 0.90

    [bar]
    scale = 0.82
    padding = 0.18
    padding-ends = 0.30
    module-gap = 0.25
    button-icon-size = 0.85
    button-icon-padding = 0.55
    button-label-size = 0.85
    button-label-padding = 0.55
    button-gap = 0.45
    button-group-module-gap = 0.15
  '';
  lumenRuntimeConfig = ''
    [bar]
    inset-edge = 0.5
    inset-ends = 0.5
    padding-ends = 1.2999999523162842
    module-gap = 0.75
    rounding = "md"

    [[bar.layout]]
    monitor = "*"
    show = true
    left = [
        "hyprland-workspaces",
        "media",
    ]
    center = ["clock"]
    right = [
        "idle-inhibit",
        "battery",
        "network",
        "dashboard",
    ]

    [modules.bluetooth]
    label-show = false

    [modules.clock]
    format = "%e %b %Y %H:%M"
    time-format = "24h"
    icon-show = false
    button-bg-color = "transparent"

    [modules.dashboard]
    dropdown-lock-command = "${pkgs.hyprlock}/bin/hyprlock --config /etc/cybex/hypr/hyprlock.conf --immediate-render --no-fade-in"

    [modules.media]
    icon-type = "default"
    hide-when-nothing-playing = true

    [wallpaper]
    cycling-directory = "$HOME/Pictures/Wallpapers"

    [[wallpaper.monitors]]
    name = "*"
    fit-mode = "fill"
    wallpaper = "${digitalPalsWallpaper}"
  '';
  lumenStyle = ''
    .model-usage.ok menubutton.bar-button {
      color: #46b576;
    }

    .model-usage.warning menubutton.bar-button {
      color: #e0a93e;
    }

    .model-usage.critical menubutton.bar-button {
      color: #e2604f;
    }

    .model-usage.offline menubutton.bar-button {
      opacity: 0.65;
    }
  '';
  lumenPathPackages = [
    pkgs.awww
    pkgs.bash
    pkgs.coreutils
    pkgs.elephant
    pkgs.fuzzel
    pkgs.hyprlock
    pkgs.matugen
    pkgs.python3
    pkgs.wofi
    terminalPackage
  ] ++ lib.optional (lumenPackage != null) lumenPackage;
  lumenExec = if lumenPackage == null then "${pkgs.coreutils}/bin/false" else "${lumenPackage}/bin/lumen shell";
  shellExecLine =
    if enableLumenShell then ''
      exec-once = systemctl --user restart cybex-lumen.service
    '' else ''
      exec-once = ${pkgs.waybar}/bin/waybar -c /etc/cybex/waybar/config -s /etc/cybex/waybar/style.css
    '';
  taskbarLockTimeoutMinutes = builtins.div (taskbarCfg.lockTimeoutSeconds or 600) 60;
  taskbarLaunchers = lib.concatMapStringsSep "," (desktopFile: "applications:${desktopFile}") (taskbarCfg.favorites or [
    "org.kde.dolphin.desktop"
    "firefox.desktop"
    "systemsettings.desktop"
    "org.kde.konsole.desktop"
  ]);
  dockFavorites = dockCfg.favorites or [
    "org.gnome.Nautilus.desktop"
    "firefox.desktop"
    "org.gnome.Geary.desktop"
    "org.gnome.Calendar.desktop"
    "org.gnome.Settings.desktop"
  ];
  minimalFavorites = minimalCfg.favorites or [
    "org.gnome.Nautilus.desktop"
    "firefox.desktop"
  ];
  kioskUrl = kioskCfg.url or "about:blank";
  kioskUser = kioskCfg.user or "cybex-kiosk";
  kioskCommand = kioskCfg.command or "${pkgs.firefox-esr}/bin/firefox --kiosk \"$CYBEX_KIOSK_URL\"";
  disableTerminal = restrictionsCfg.terminal or false;
  disableScreenshots = restrictionsCfg.screenshots or false;
  keybindingPreset = tilingCfg.keybindingPreset or "cybex";

  hyprlandSession = pkgs.writeShellScriptBin "cybex-hyprland-session" ''
    export XDG_SESSION_TYPE=wayland
    export XDG_CURRENT_DESKTOP=Hyprland
    export DESKTOP_SHELL=${shellMarker}
    export NIXOS_OZONE_WL=1
    export MOZ_ENABLE_WAYLAND=1

    mkdir -p "$XDG_RUNTIME_DIR"
    echo "${shellMarker}" > "$XDG_RUNTIME_DIR/desktop-shell"

    if [ "${shellMarker}" = "lumen" ]; then
      config_home="''${XDG_CONFIG_HOME:-$HOME/.config}"
      mkdir -p "$config_home/lumen/styles" "$HOME/Pictures/Wallpapers"
      seed_mutable_config() {
        source_file="$1"
        target_file="$2"
        if [ -L "$target_file" ] || [ ! -e "$target_file" ]; then
          mkdir -p "$(dirname "$target_file")"
          rm -f "$target_file"
          cp "$source_file" "$target_file"
          chmod u+w "$target_file"
        fi
      }
      seed_mutable_config /etc/cybex/lumen/config.toml.default "$config_home/lumen/config.toml"
      seed_mutable_config /etc/cybex/lumen/runtime.toml.default "$config_home/lumen/runtime.toml"
      cp /etc/cybex/lumen/styles/index.scss "$config_home/lumen/styles/index.scss"
      ln -sf ${digitalPalsWallpaper} "$HOME/Pictures/Wallpapers/snow-capped-mountains-with-full-moon-lo.jpg"
    fi

    state_dir="''${XDG_STATE_HOME:-$HOME/.local/state}/hyprland"
    mkdir -p "$state_dir"
    exec ${pkgs.hyprland}/bin/start-hyprland -- -c /etc/cybex/hypr/hyprland.conf > "$state_dir/session.log" 2>&1
  '';

  hyprlandSessionPackage = pkgs.stdenvNoCC.mkDerivation {
    pname = "cybex-hyprland-session";
    version = "1.0.0";
    dontUnpack = true;
    passthru.providedSessions = [ "cybex-hyprland" ];
    installPhase = ''
      mkdir -p $out/bin $out/share/wayland-sessions
      ln -s ${hyprlandSession}/bin/cybex-hyprland-session $out/bin/cybex-hyprland-session
      cat > $out/share/wayland-sessions/cybex-hyprland.desktop <<EOF
      [Desktop Entry]
      Name=Hyprland (Lumen)
      Comment=Hyprland with Lumen desktop shell
      Exec=$out/bin/cybex-hyprland-session
      Type=Application
      DesktopNames=Hyprland
      EOF
    '';
  };

  screenshotTool = pkgs.writeShellScriptBin "cybex-screenshot" ''
    set -eu
    mode="''${1:-region}"
    output_dir=${screenshotDir}
    mkdir -p "$output_dir"
    pkill slurp 2>/dev/null && exit 0

    raw_file="$output_dir/screenshot-$(date +%Y-%m-%d_%H-%M-%S)-raw.png"
    output_file="''${raw_file%-raw.png}.png"
    freeze_pid=""
    cleanup_freeze() {
      if [ -n "$freeze_pid" ]; then
        kill "$freeze_pid" 2>/dev/null || true
        wait "$freeze_pid" 2>/dev/null || true
      fi
    }
    trap cleanup_freeze EXIT

    case "$mode" in
      fullscreen)
        selection="$(hyprctl monitors -j | jq -r '.[] | select(.focused == true) | "\(.x),\(.y) \((.width / .scale) | floor)x\((.height / .scale) | floor)"' | head -n 1)"
        [ -n "$selection" ] || exit 0
        grim -g "$selection" "$raw_file"
        ;;
      *)
        if command -v wayfreeze >/dev/null 2>&1; then
          wayfreeze &
          freeze_pid="$!"
          sleep 0.1
        fi
        selection="$(slurp 2>/dev/null || true)"
        [ -n "$selection" ] || exit 0
        grim -g "$selection" "$raw_file"
        cleanup_freeze
        freeze_pid=""
        ;;
    esac
    if command -v satty >/dev/null 2>&1; then
      satty --filename "$raw_file" --output-filename "$output_file" --early-exit --copy-command wl-copy
      [ -f "$output_file" ] && rm -f "$raw_file"
    else
      cp "$raw_file" "$output_file"
      wl-copy < "$output_file" || true
      rm -f "$raw_file"
    fi
  '';

  screenRecordTool = pkgs.writeShellScriptBin "cybex-screen-record" ''
    set -eu
    output_dir="$HOME/Videos/Screen Recordings"
    state_dir="''${XDG_RUNTIME_DIR:-/tmp}/cybex-screen-record"
    pid_file="$state_dir/wf-recorder.pid"
    output_file_state="$state_dir/output-file"
    mkdir -p "$output_dir"

    notify() {
      notify-send "$@" 2>/dev/null || true
    }

    if [ -f "$pid_file" ]; then
      pid="$(cat "$pid_file" 2>/dev/null || true)"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        output_file="$(cat "$output_file_state" 2>/dev/null || true)"
        notify "Screen Recording" "Saved to $output_file"
        rm -f "$pid_file" "$output_file_state"
        exit 0
      fi
      rm -f "$pid_file" "$output_file_state"
    fi

    output_file="$output_dir/screen-record-$(date +%Y-%m-%d_%H-%M-%S).mp4"
    if ! command -v wf-recorder >/dev/null 2>&1; then
      notify "Screen recording unavailable" "wf-recorder is not installed."
      exit 1
    fi

    pkill slurp 2>/dev/null && exit 0
    freeze_pid=""
    cleanup_freeze() {
      if [ -n "$freeze_pid" ]; then
        kill "$freeze_pid" 2>/dev/null || true
      fi
    }
    trap cleanup_freeze EXIT

    if command -v wayfreeze >/dev/null 2>&1; then
      wayfreeze &
      freeze_pid="$!"
      sleep 0.1
    fi

    selection="$(slurp 2>/dev/null || true)"
    [ -n "$selection" ] || exit 0
    cleanup_freeze
    freeze_pid=""

    mkdir -p "$state_dir"
    wf-recorder -g "$selection" -f "$output_file" >/tmp/cybex-wf-recorder.log 2>&1 &
    pid="$!"
    sleep 0.2
    if ! kill -0 "$pid" 2>/dev/null; then
      notify "Screen Recording" "Failed to start recording"
      exit 1
    fi
    printf '%s\n' "$pid" > "$pid_file"
    printf '%s\n' "$output_file" > "$output_file_state"
    notify "Screen Recording" "Recording selected area. Press Super+Shift+~ to stop."
  '';

# Stable command aliases keep managed bind lines free of Nix store paths so
  # Blueprint-authored keybinds (cybex.desktop.tiling.keybinds) can invoke the
  # same commands the defaults use.
  hyprBindAliases = ''
    $cybexTerminal = ${terminalCommand}
    $cybexLauncher = ${launcherCommand}
    $cybexBrowser = ${browserExecCommand}
    $cybexFileManager = ${fileManagerCommand}
    $cybexLock = ${pkgs.hyprlock}/bin/hyprlock -c /etc/cybex/hypr/hyprlock.conf --immediate-render --no-fade-in
    $cybexScreenshotRegion = ${screenshotTool}/bin/cybex-screenshot region
    $cybexScreenshotFull = ${screenshotTool}/bin/cybex-screenshot fullscreen
    $cybexScreenRecord = ${screenRecordTool}/bin/cybex-screen-record
  '';

  # Managed default keybinds. Keep in sync with DEFAULT_HYPR_BINDS in
  # web/src/screens/blueprints/hyprBinds.ts — the manage-server contract test
  # hyprland_default_keybinds_contract compares the two lists literally.
  cybexDefaultKeybinds = [
    "bind = $mod, Return, exec, $cybexTerminal"
    "bind = $mod, Space, exec, $cybexLauncher"
    "bind = $mod, B, exec, $cybexBrowser"
    "bind = $mod SHIFT, B, exec, $cybexBrowser --private-window"
    "bind = $mod, E, exec, $cybexFileManager"
    "bind = $mod, L, exec, $cybexLock"
    "bind = $mod, Q, killactive"
    "bind = $mod, F, togglefloating"
    "bind = $mod, J, layoutmsg, togglesplit"
    "bind = $mod SHIFT, M, exit"
    "bind = $mod, left, movefocus, l"
    "bind = $mod, right, movefocus, r"
    "bind = $mod, up, movefocus, u"
    "bind = $mod, down, movefocus, d"
    "bind = $mod SHIFT, left, movewindow, l"
    "bind = $mod SHIFT, right, movewindow, r"
    "bind = $mod SHIFT, up, movewindow, u"
    "bind = $mod SHIFT, down, movewindow, d"
    "bind = $mod, 1, workspace, 1"
    "bind = $mod, 2, workspace, 2"
    "bind = $mod, 3, workspace, 3"
    "bind = $mod, 4, workspace, 4"
    "bind = $mod, 5, workspace, 5"
    "bind = $mod, 6, workspace, 6"
    "bind = $mod, 7, workspace, 7"
    "bind = $mod, 8, workspace, 8"
    "bind = $mod, 9, workspace, 9"
    "bind = $mod, 0, workspace, 10"
    "bind = $mod SHIFT, 1, movetoworkspace, 1"
    "bind = $mod SHIFT, 2, movetoworkspace, 2"
    "bind = $mod SHIFT, 3, movetoworkspace, 3"
    "bind = $mod SHIFT, 4, movetoworkspace, 4"
    "bind = $mod SHIFT, 5, movetoworkspace, 5"
    "bind = $mod SHIFT, 6, movetoworkspace, 6"
    "bind = $mod SHIFT, 7, movetoworkspace, 7"
    "bind = $mod SHIFT, 8, movetoworkspace, 8"
    "bind = $mod SHIFT, 9, movetoworkspace, 9"
    "bind = $mod SHIFT, 0, movetoworkspace, 10"
    "bind = $mod, grave, exec, $cybexScreenshotRegion"
    "bind = , Print, exec, $cybexScreenshotRegion"
    "bind = SHIFT, Print, exec, $cybexScreenshotFull"
    "bind = $mod SHIFT, grave, exec, $cybexScreenRecord"
    "bindel = , XF86AudioRaiseVolume, exec, wpctl set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 5%+"
    "bindel = , XF86AudioLowerVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"
    "bindl = , XF86AudioMute, exec, wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"
    "bindl = , XF86AudioPlay, exec, playerctl play-pause"
    "bindl = , XF86AudioNext, exec, playerctl next"
    "bindl = , XF86AudioPrev, exec, playerctl previous"
    "bindm = $mod, mouse:272, movewindow"
    "bindm = $mod, mouse:273, resizewindow"
    "bindm = $mod SHIFT, mouse:272, resizewindow"
  ];

  bindUsesTerminal = bind: lib.hasInfix "$cybexTerminal" bind;
  bindUsesScreenshots = bind:
    lib.hasInfix "$cybexScreenshotRegion" bind
    || lib.hasInfix "$cybexScreenshotFull" bind
    || lib.hasInfix "$cybexScreenRecord" bind;
  bindUsesBrowser = bind: lib.hasInfix "$cybexBrowser" bind;
  allowedKeybind = bind:
    !(disableTerminal && bindUsesTerminal bind)
    && !(disableScreenshots && bindUsesScreenshots bind)
    && (browserEnabled || !(bindUsesBrowser bind));
  authoredKeybinds = tilingCfg.keybinds or [ ];
  effectiveKeybinds = builtins.filter allowedKeybind
    (if authoredKeybinds == [ ] then cybexDefaultKeybinds else authoredKeybinds);
  authoredExtraSettings = tilingCfg.extraSettings or "";

  hyprlandConfig = ''
    autogenerated = 0

    monitor=,preferred,auto,auto,vrr,1

    env = XCURSOR_SIZE,24
    env = NIXOS_OZONE_WL,1
    env = MOZ_ENABLE_WAYLAND,1
    env = GDK_SCALE,2

    input {
      kb_layout = us
      kb_variant = mac
      kb_options = compose:caps,lv3:alt_switch
      follow_mouse = 1
      natural_scroll = true
      repeat_rate = 40
      repeat_delay = 600
      numlock_by_default = true
      touchpad {
        natural_scroll = true
        disable_while_typing = true
        tap-to-click = true
        scroll_factor = 0.4
      }
    }

    general {
      gaps_in = 5
      gaps_out = 10
      border_size = 1
      layout = dwindle
      col.active_border = ${rgb digitalPalsColors.mPrimary}
      col.inactive_border = ${rgb digitalPalsColors.mSurface}
    }

    cursor {
      no_hardware_cursors = false
    }

    dwindle {
      preserve_split = true
      split_width_multiplier = 1.0
    }

    decoration {
      rounding = 10
      blur {
        enabled = true
        size = 3
        passes = 1
      }
      shadow {
        enabled = true
        range = 4
        render_power = 3
        color = rgba(1a1a1aee)
      }
    }

    animations {
      enabled = true
      bezier = cybex, 0.05, 0.9, 0.1, 1.05
      animation = windows, 1, 7, cybex
      animation = windowsOut, 1, 7, default, popin 80%
      animation = border, 1, 10, default
      animation = borderangle, 1, 8, default
      animation = fade, 1, 7, default
      animation = workspaces, 1, 6, default
    }

    misc {
      disable_hyprland_logo = true
      disable_splash_rendering = true
      force_default_wallpaper = 0
      focus_on_activate = false
    }

    xwayland {
      force_zero_scaling = true
    }

    group {
      col.border_active = ${rgb digitalPalsColors.mSecondary}
      col.border_inactive = ${rgb digitalPalsColors.mSurface}
      col.border_locked_active = ${rgb digitalPalsColors.mError}
      col.border_locked_inactive = ${rgb digitalPalsColors.mSurface}
      groupbar {
        col.active = ${rgb digitalPalsColors.mSecondary}
        col.inactive = ${rgb digitalPalsColors.mSurface}
        col.locked_active = ${rgb digitalPalsColors.mError}
        col.locked_inactive = ${rgb digitalPalsColors.mSurface}
      }
    }

    exec-once = systemctl --user import-environment WAYLAND_DISPLAY XDG_CURRENT_DESKTOP HYPRLAND_INSTANCE_SIGNATURE XDG_SESSION_TYPE
    exec-once = dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP HYPRLAND_INSTANCE_SIGNATURE XDG_SESSION_TYPE
    exec-once = ${pkgs.swaybg}/bin/swaybg -i ${digitalPalsWallpaper} -m fill
    exec-once = sleep 1 && ${pkgs.xdg-desktop-portal-gtk}/libexec/xdg-desktop-portal-gtk
    exec-once = sleep 2 && systemctl --user restart xdg-desktop-portal-hyprland xdg-desktop-portal
    exec-once = ${pkgs.hypridle}/bin/hypridle -c /etc/cybex/hypr/hypridle.conf
    ${shellExecLine}
    exec-once = ${pkgs.mako}/bin/mako --config /etc/cybex/mako/config
    ${walkerServiceLine}
    exec-once = ${pkgs.polkit_gnome}/libexec/polkit-gnome-authentication-agent-1
    exec-once = ${pkgs.networkmanagerapplet}/bin/nm-applet --indicator
    exec-once = ${pkgs.blueman}/bin/blueman-applet

    $mod = SUPER
    ${hyprBindAliases}
    ${lib.concatStringsSep "\n" effectiveKeybinds}

    windowrule = suppress_event maximize, match:class .*
    windowrule = opacity 1.0 1.0, match:class .*
    windowrule = float on, match:class ^(xdg-desktop-portal-gtk)$
    windowrule = float on, match:class ^(org.gnome.Nautilus)$, match:title ^(Properties|Open.*|Save.*)$
    windowrule = float on, center on, size 60% 70%, match:class ^(org.gnome.NautilusPreviewer)$
    windowrule = float on, match:class ^(org.gnome.Calculator)$
    windowrule = float on, match:class ^(imv|mpv)$
    windowrule = center on, match:class ^(imv|mpv)$
    windowrule = opacity 1 1, match:class ^(vlc|mpv|imv|zoom)$
    ${lib.optionalString (authoredExtraSettings != "") ''

      # Blueprint-authored system settings (last assignment wins)
      ${authoredExtraSettings}''}
  '';

  hypridleConfig = ''
    general {
      lock_cmd = ${pkgs.hyprlock}/bin/hyprlock -c /etc/cybex/hypr/hyprlock.conf --immediate-render --no-fade-in
      before_sleep_cmd = ${pkgs.hyprlock}/bin/hyprlock -c /etc/cybex/hypr/hyprlock.conf --immediate-render --no-fade-in
      after_sleep_cmd = ${pkgs.hyprland}/bin/hyprctl dispatch dpms on
    }

    listener {
      timeout = ${toString lockTimeoutSeconds}
      on-timeout = ${pkgs.hyprlock}/bin/hyprlock -c /etc/cybex/hypr/hyprlock.conf --immediate-render --no-fade-in
    }

    listener {
      timeout = ${toString dpmsTimeoutSeconds}
      on-timeout = ${pkgs.hyprland}/bin/hyprctl dispatch dpms off
      on-resume = ${pkgs.hyprland}/bin/hyprctl dispatch dpms on
    }
  '';

  waybarConfig = builtins.toJSON {
    layer = "top";
    position = "top";
    height = 34;
    modules-left = [ "hyprland/workspaces" "hyprland/window" ];
    modules-center = [ "clock" ];
    modules-right = [ "network" "pulseaudio" "battery" "tray" ];
    "hyprland/workspaces" = {
      disable-scroll = true;
      all-outputs = true;
    };
    clock = {
      format = "{:%a %d %b  %H:%M}";
      tooltip-format = "{:%Y-%m-%d %H:%M:%S}";
    };
    network = {
      format-wifi = "{essid} {signalStrength}%";
      format-ethernet = "wired";
      format-disconnected = "offline";
      tooltip = false;
    };
    pulseaudio = {
      format = "vol {volume}%";
      format-muted = "muted";
      tooltip = false;
    };
    battery = {
      format = "bat {capacity}%";
      states = {
        warning = 30;
        critical = 15;
      };
    };
  };
in
{
  options.cybex.desktop.profile = lib.mkOption {
    type = lib.types.enum [ "auto" "gnome" "plasma" "taskbar" "dock" "minimal" "tiling" "sway" "kiosk" "server" ];
    default = "auto";
    description = "Cybex desktop profile selector. The generated blueprint can also drive this from cybex.desktop.environment.";
  };

  options.cybex.desktop.greeter = lib.mkOption {
    type = lib.types.enum [ "auto" "gdm" "sddm" "greetd" "none" ];
    default = "auto";
    description = "Display manager selected by the assigned Blueprint. Explicit selections are authoritative and mutually exclusive.";
  };

  options.cybex.desktop.login.mode = lib.mkOption {
    type = lib.types.enum [ "greeter" "autologin" "none" ];
    default = "greeter";
    description = "Login posture for managed blueprints.";
  };

  options.cybex.desktop.login.user = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    description = "Optional user for managed desktop autologin.";
  };

  options.cybex.desktop.wallpaper = {
    name = lib.mkOption {
      type = lib.types.str;
      default = "DigitalPals snow moon";
      description = "Managed wallpaper identity selected by the assigned blueprint.";
    };
  };

  options.cybex.desktop.restrictions = {
    terminal = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Disable managed terminal launch affordances where the desktop module controls them.";
    };
    screenshots = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Disable managed screenshot and screen recording affordances where the desktop module controls them.";
    };
    printing = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Disable managed printing affordances where the desktop module controls them.";
    };
  };

  options.cybex.desktop.taskbar = {
    favorites = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "org.kde.dolphin.desktop"
        "firefox.desktop"
        "systemsettings.desktop"
        "org.kde.konsole.desktop"
      ];
      description = "KDE desktop files pinned to the managed bottom taskbar.";
    };
    lockTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 600;
      description = "Idle seconds before Plasma locks the session.";
    };
  };

  options.cybex.desktop.dock = {
    favorites = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "org.gnome.Nautilus.desktop"
        "firefox.desktop"
        "org.gnome.Geary.desktop"
        "org.gnome.Calendar.desktop"
        "org.gnome.Settings.desktop"
      ];
      description = "GNOME desktop files pinned to the managed bottom dock.";
    };
  };

  options.cybex.desktop.minimal = {
    favorites = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "org.gnome.Nautilus.desktop"
        "firefox.desktop"
      ];
      description = "GNOME desktop files kept in the minimal favorites list.";
    };
  };

  options.cybex.desktop.kiosk = {
    user = lib.mkOption {
      type = lib.types.str;
      default = "cybex-kiosk";
      description = "Local user that owns the managed kiosk session.";
    };
    url = lib.mkOption {
      type = lib.types.str;
      default = "about:blank";
      description = "URL opened by the managed kiosk browser.";
    };
    command = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Command launched for managed kiosk sessions. Defaults to Firefox ESR kiosk mode.";
    };
  };

  options.cybex.desktop.tiling = {
    enable = lib.mkEnableOption "Cybex managed tiling desktop";
    shell = lib.mkOption {
      type = lib.types.enum [ "cybex" "lumen" ];
      default = "lumen";
      description = "Desktop shell style for the tiling profile. The Lumen shell requires pkgs.lumen from the generated blueprint overlay or another nixpkgs overlay.";
    };
    terminal = lib.mkOption {
      type = lib.types.enum [ "kitty" "konsole" "foot" "alacritty" ];
      default = "kitty";
      description = "Default terminal launched by the tiling desktop shortcuts.";
    };
    launcher = lib.mkOption {
      type = lib.types.enum [ "walker-fallback" "walker" "wofi" "rofi" ];
      default = "walker";
      description = "Default application launcher for the tiling desktop.";
    };
    keybindingPreset = lib.mkOption {
      type = lib.types.enum [ "cybex" "digitalpals" "minimal" ];
      default = "cybex";
      description = "Managed keybinding preset metadata for the tiling desktop.";
    };
    browserCommand = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Browser command launched by the tiling desktop shortcut. Null removes the managed browser shortcuts.";
    };
    fileManagerCommand = lib.mkOption {
      type = lib.types.str;
      default = "${pkgs.nautilus}/bin/nautilus --new-window";
      description = "File manager command launched by the tiling desktop shortcut.";
    };
    lockTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 900;
      description = "Idle seconds before Hyprlock locks the session.";
    };
    dpmsTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1200;
      description = "Idle seconds before displays are powered down.";
    };
    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Additional packages installed with the tiling desktop.";
    };
    extraSettings = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Blueprint-authored Hyprland settings (flat \"section:key = value\" lines) appended after the managed configuration so they win on conflict.";
    };
    keybinds = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Blueprint-authored Hyprland bind lines. When non-empty this list replaces the managed default keybinds; terminal/screenshot restrictions still filter it.";
    };
  };

  config = lib.mkMerge [
    (lib.mkIf managedDesktop {
      assertions = [
        {
          assertion = graphicalLogin == (greeter != "none");
          message = "The Blueprint greeter must be None exactly when graphical login is disabled.";
        }
        {
          assertion = (loginCfg.mode or "greeter") != "autologin" || loginCfg.user != null;
          message = "Blueprint autologin requires cybex.desktop.login.user.";
        }
      ];

      services.xserver.enable = lib.mkIf (graphicalLogin && (greeter == "gdm" || greeter == "sddm")) (lib.mkForce true);
      services.displayManager.gdm.enable = lib.mkForce (graphicalLogin && greeter == "gdm");
      services.displayManager.sddm.enable = lib.mkForce (graphicalLogin && greeter == "sddm");
      services.displayManager.sddm.wayland.enable = lib.mkForce (graphicalLogin && greeter == "sddm");
      services.greetd.enable = lib.mkForce (graphicalLogin && greeter == "greetd");
      services.displayManager.autoLogin.enable = lib.mkForce (
        graphicalLogin
        && greeter != "greetd"
        && (loginCfg.mode or "greeter") == "autologin"
        && loginCfg.user != null
      );
      services.displayManager.autoLogin.user = lib.mkIf (loginCfg.user != null) (lib.mkDefault loginCfg.user);
    })

    (lib.mkIf (managedDesktop && graphicalLogin && greeter == "greetd") {
      services.greetd.settings = {
        default_session = {
          command =
            if (loginCfg.mode or "greeter") == "autologin" && loginCfg.user != null then
              defaultSessionCommand
            else
              "${pkgs.tuigreet}/bin/tuigreet --time --remember --remember-session --sessions ${config.services.displayManager.sessionData.desktops}/share/wayland-sessions --xsessions ${config.services.displayManager.sessionData.desktops}/share/xsessions --cmd "
              + lib.escapeShellArg defaultSessionCommand;
          user = if (loginCfg.mode or "greeter") == "autologin" && loginCfg.user != null then loginCfg.user else "greeter";
        };
      };
    })

    (lib.mkIf enableTaskbar {
      services.xserver.enable = lib.mkDefault true;
      services.displayManager.defaultSession = lib.mkDefault "plasma";
      services.desktopManager.plasma6.enable = lib.mkDefault true;

      xdg.portal = {
        enable = lib.mkDefault true;
        extraPortals = lib.mkDefault [ pkgs.kdePackages.xdg-desktop-portal-kde ];
        config.common.default = lib.mkDefault [ "kde" ];
      };

      environment.systemPackages = with pkgs; [
        kdePackages.ark
        kdePackages.dolphin
        kdePackages.kate
        kdePackages.kcalc
        kdePackages.kio-extras
        kdePackages.konsole
        kdePackages.okular
        kdePackages.plasma-systemmonitor
        kdePackages.spectacle
        kdePackages.systemsettings
      ];

      environment.etc."xdg/kdeglobals".text = lib.mkDefault ''
        [General]
        TerminalApplication=konsole
        SingleClick=false
        BrowserApplication=firefox.desktop

        [KDE]
        LookAndFeelPackage=org.kde.breeze.desktop
        ShowDeleteCommand=false

        [KFileDialog Settings]
        Show Hidden Files=false
      '';
      environment.etc."xdg/kscreenlockerrc".text = lib.mkDefault ''
        [Daemon]
        Autolock=true
        Timeout=${toString taskbarLockTimeoutMinutes}
        LockOnResume=true
      '';
      environment.etc."xdg/plasmarc".text = lib.mkDefault ''
        [Theme]
        name=breeze

        [OSD]
        Enabled=true
      '';
      environment.etc."xdg/plasma-org.kde.plasma.desktop-appletsrc".text = lib.mkDefault ''
        [Containments][1]
        activityId=
        formfactor=0
        immutability=1
        lastScreen=0
        location=0
        plugin=org.kde.plasma.folder
        wallpaperplugin=org.kde.image

        [Containments][2]
        activityId=
        formfactor=2
        immutability=1
        lastScreen=0
        location=4
        plugin=org.kde.panel

        [Containments][2][Applets][1]
        immutability=1
        plugin=org.kde.plasma.kickoff

        [Containments][2][Applets][2]
        immutability=1
        plugin=org.kde.plasma.icontasks

        [Containments][2][Applets][2][Configuration][General]
        launchers=${taskbarLaunchers}

        [Containments][2][Applets][3]
        immutability=1
        plugin=org.kde.plasma.marginsseparator

        [Containments][2][Applets][4]
        immutability=1
        plugin=org.kde.plasma.systemtray

        [Containments][2][Applets][5]
        immutability=1
        plugin=org.kde.plasma.digitalclock

        [Containments][2][General]
        AppletOrder=1;2;3;4;5
      '';
    })

    (lib.mkIf enableDock {
      services.xserver.enable = lib.mkDefault true;
      services.desktopManager.gnome.enable = lib.mkDefault true;
      programs.dconf.enable = lib.mkDefault true;

      environment.systemPackages = with pkgs; [
        geary
        gnome-calendar
        gnome-text-editor
        gnomeExtensions.dash-to-dock
        nautilus
      ];

      programs.dconf.profiles.user.databases = lib.mkDefault [{
        settings = {
          "org/gnome/desktop/interface" = {
            clock-show-weekday = true;
            enable-hot-corners = false;
          };
          "org/gnome/desktop/screensaver" = {
            lock-enabled = true;
            lock-delay = lib.gvariant.mkUint32 0;
          };
          "org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 600;
          "org/gnome/desktop/wm/preferences".button-layout = "appmenu:minimize,maximize,close";
          "org/gnome/shell" = {
            enabled-extensions = [ "dash-to-dock@micxgx.gmail.com" ];
            favorite-apps = dockFavorites;
          };
          "org/gnome/shell/extensions/dash-to-dock" = {
            dock-position = "BOTTOM";
            extend-height = false;
            intellihide = true;
            show-mounts = false;
            show-trash = false;
          };
        };
      }];
    })

    (lib.mkIf enableMinimal {
      services.xserver.enable = lib.mkDefault true;
      services.desktopManager.gnome.enable = lib.mkDefault true;
      programs.dconf.enable = lib.mkDefault true;

      environment.systemPackages = with pkgs; [
        nautilus
      ];

      programs.dconf.profiles.user.databases = lib.mkDefault [{
        settings = {
          "org/gnome/desktop/interface".clock-show-weekday = true;
          "org/gnome/desktop/screensaver" = {
            lock-enabled = true;
            lock-delay = lib.gvariant.mkUint32 0;
          };
          "org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 600;
          "org/gnome/shell".favorite-apps = minimalFavorites;
        };
      }];
    })

    (lib.mkIf enableKiosk {
      services.xserver.enable = lib.mkDefault true;
      services.desktopManager.gnome.enable = lib.mkDefault true;
      programs.dconf.enable = lib.mkDefault true;

      users.users.${kioskUser} = {
        isNormalUser = true;
        description = "Cybex kiosk session";
        extraGroups = [ "networkmanager" "video" "audio" ];
        hashedPassword = "!";
      };

      environment.systemPackages = with pkgs; [
        firefox-esr
      ];
      environment.sessionVariables.CYBEX_KIOSK_URL = kioskUrl;
      environment.etc."xdg/autostart/cybex-kiosk-browser.desktop".text = lib.mkDefault ''
        [Desktop Entry]
        Type=Application
        Name=Cybex Kiosk Browser
        Exec=${pkgs.bash}/bin/bash -lc 'if [ "$USER" = "${kioskUser}" ]; then exec ${kioskCommand}; fi'
        X-GNOME-Autostart-enabled=true
        NoDisplay=true
      '';

      programs.firefox.enable = lib.mkDefault true;
      programs.firefox.policies = {
        DisableTelemetry = lib.mkDefault true;
        DisableFirefoxStudies = lib.mkDefault true;
        DisableDeveloperTools = lib.mkDefault true;
        DisableProfileImport = lib.mkDefault true;
        BlockAboutConfig = lib.mkDefault true;
        OfferToSaveLogins = lib.mkDefault false;
      };

      programs.dconf.profiles.user.databases = lib.mkDefault [{
        settings = {
          "org/gnome/desktop/interface" = {
            clock-show-weekday = true;
            enable-hot-corners = false;
          };
          "org/gnome/desktop/screensaver" = {
            lock-enabled = true;
            lock-delay = lib.gvariant.mkUint32 0;
          };
          "org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 300;
          "org/gnome/desktop/lockdown" = {
            disable-command-line = true;
            disable-log-out = true;
            disable-user-switching = true;
            disable-lock-screen = false;
          };
          "org/gnome/settings-daemon/plugins/power" = {
            sleep-inactive-ac-type = "nothing";
            power-button-action = "nothing";
          };
          "org/gnome/shell".favorite-apps = [ "firefox.desktop" ];
        };
      }];
    })

    (lib.mkIf enableTiling {
    assertions = [
      {
        assertion = !enableLumenShell || lumenPackage != null;
        message = "cybex.desktop.tiling.shell = \"lumen\" requires a pkgs.lumen package. Use the generated Tiling Desktop blueprint overlay or provide pkgs.lumen through nixpkgs.overlays.";
      }
      {
        assertion = launcherPackage != null;
        message = "The selected cybex.desktop.tiling.launcher is unavailable in this nixpkgs revision.";
      }
    ];

    programs.hyprland = {
      enable = true;
      xwayland.enable = true;
    };

    services.displayManager.sessionPackages = [ hyprlandSessionPackage ];

    systemd.user.services.cybex-lumen = lib.mkIf enableLumenShell {
      description = "Lumen desktop shell";
      after = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];
      serviceConfig = {
        ExecStart = lumenExec;
        Restart = "on-failure";
        RestartSec = "2s";
      };
      path = lumenPathPackages;
    };

    xdg.portal = {
      enable = true;
      extraPortals = [
        pkgs.xdg-desktop-portal-hyprland
        pkgs.xdg-desktop-portal-gtk
      ];
      config.common.default = [ "hyprland" "gtk" ];
    };

    security.polkit.enable = true;
    programs.dconf.enable = true;
    services.gvfs.enable = true;
    services.udisks2.enable = true;
    services.upower.enable = lib.mkDefault true;
    services.blueman.enable = lib.mkDefault true;

    environment.sessionVariables = {
      NIXOS_OZONE_WL = "1";
      MOZ_ENABLE_WAYLAND = "1";
      XDG_CURRENT_DESKTOP = "Hyprland";
    };

    environment.systemPackages =
      [
        pkgs.blueman
        pkgs.hypridle
        pkgs.hyprlock
        pkgs.imv
        pkgs.jq
        pkgs.libnotify
        pkgs.mako
        pkgs.nautilus
        pkgs.networkmanagerapplet
        pkgs.playerctl
        pkgs.polkit_gnome
        pkgs.pulseaudio
        pkgs.swaybg
        pkgs.wireplumber
        pkgs.wl-clipboard
        pkgs.wofi
        hyprlandSession
      ]
      ++ lib.optional (!disableTerminal) terminalPackage
      ++ lib.optionals (!disableScreenshots) [
        pkgs.grim
        pkgs.slurp
        screenshotTool
        screenRecordTool
      ]
      ++ lib.optional (!enableLumenShell) pkgs.waybar
      ++ lib.optional (enableLumenShell && lumenPackage != null) lumenPackage
      ++ lib.optionals enableLumenShell [
        pkgs.awww
        pkgs.elephant
        pkgs.fuzzel
        pkgs.matugen
      ]
      ++ lib.optional (launcherPackage != null && launcherPackage != pkgs.wofi) launcherPackage
      ++ lib.optionals (!disableScreenshots) (optionalPackage "satty")
      ++ lib.optionals (!disableScreenshots) (optionalPackage "wf-recorder")
      ++ lib.optionals (!disableScreenshots) (optionalPackage "wayfreeze")
      ++ optionalPackage "sushi"
      ++ optionalPackage "gnome-calculator"
      ++ tilingCfg.extraPackages;

    fonts.packages = with pkgs; [
      noto-fonts
      noto-fonts-color-emoji
      liberation_ttf
      nerd-fonts.jetbrains-mono
    ];

    environment.etc."cybex/hypr/hyprland.conf".text = hyprlandConfig;
    environment.etc."cybex/desktop/keybinding-preset".text = "${keybindingPreset}\n";
    environment.etc."cybex/desktop/wallpaper".text = "${wallpaperCfg.name or "DigitalPals snow moon"}\n";
    environment.etc."cybex/hypr/hypridle.conf".text = hypridleConfig;
    environment.etc."cybex/lumen/config.toml.default".text = lumenConfig;
    environment.etc."cybex/lumen/runtime.toml.default".text = lumenRuntimeConfig;
    environment.etc."cybex/lumen/styles/index.scss".text = lumenStyle;
    environment.etc."cybex/hypr/hyprlock.conf".text = ''
      background {
        color = ${rgba digitalPalsColors.mSurface "ff"}
      }

      input-field {
        size = 280, 52
        position = 0, -20
        monitor =
        dots_center = true
        fade_on_empty = false
        outline_thickness = 1
        rounding = 10
        outer_color = ${rgba digitalPalsColors.mPrimary "ff"}
        inner_color = ${rgba digitalPalsColors.mSurfaceVariant "ff"}
        font_color = ${rgba digitalPalsColors.mOnSurface "ff"}
        placeholder_text = Password
      }

      label {
        monitor =
        text = Hyprland (Lumen)
        color = ${rgba digitalPalsColors.mOnSurface "ff"}
        font_size = 26
        position = 0, 80
        halign = center
        valign = center
      }
    '';
    environment.etc."xdg/kitty/kitty.conf".text = ''
      font_family JetBrainsMono Nerd Font
      font_size 12.0
      term xterm-256color
      scrollback_lines 10000
      window_padding_width 14
      background_opacity 0.95

      cursor_shape underline
      cursor_blink_interval 0
      cursor_trail 3
      cursor_trail_decay 0.1 0.4
      cursor_trail_start_threshold 2

      enable_audio_bell no
      visual_bell_duration 0
      window_alert_on_bell yes
      mouse_hide_wait 1

      map ctrl+insert copy_to_clipboard
      map ctrl+shift+c copy_to_clipboard
      map shift+insert paste_from_clipboard
      map ctrl+shift+v paste_from_clipboard

      foreground #cdd6f4
      background #1e1e2e
      selection_foreground #cdd6f4
      selection_background #585b70
      cursor #f5e0dc
      cursor_text_color #1e1e2e

      color0 #45475a
      color1 #f38ba8
      color2 #a6e3a1
      color3 #f9e2af
      color4 #89b4fa
      color5 #f5c2e7
      color6 #94e2d5
      color7 #a6adc8

      color8 #585b70
      color9 #f37799
      color10 #89d88b
      color11 #ebd391
      color12 #74a8fc
      color13 #f2aede
      color14 #6bd7ca
      color15 #bac2de
    '';
    environment.etc."xdg/walker/config.toml".text = ''
      theme = "lumen"
      close_when_open = true
      click_to_close = true
      single_click_activation = true
      selection_wrap = true
      hide_quick_activation = true
      hide_action_hints = true
      keybind_symbols = true
      resume_last_query = false
      ext_background_effect_blur = false

      [placeholders]
      "default" = { input = "Search apps and commands", list = "No results" }
      "desktopapplications" = { input = "Search apps", list = "No apps found" }
      "calc" = { input = "Calculate", list = "Type an expression" }
      "websearch" = { input = "Search the web", list = "Type a search" }

      [providers]
      default = ["desktopapplications", "runner", "calc", "websearch"]
      empty = ["desktopapplications"]
      max_results = 16
      ignore_preview = ["desktopapplications", "runner", "calc", "websearch"]

      [[providers.prefixes]]
      prefix = ">"
      provider = "runner"

      [[providers.prefixes]]
      prefix = "="
      provider = "calc"
    '';
    environment.etc."xdg/walker/themes/lumen/style.css".text = ''
      @define-color window_bg_color rgba(14, 18, 24, 0.86);
      @define-color panel_bg_color rgba(21, 27, 36, 0.78);
      @define-color field_bg_color rgba(245, 247, 250, 0.08);
      @define-color accent_bg_color rgba(203, 166, 247, 0.45);
      @define-color accent_strong_color #cba6f7;
      @define-color border_color rgba(232, 236, 243, 0.20);
      @define-color theme_fg_color #cdd6f4;
      @define-color muted_fg_color #a3b4eb;
      @define-color error_bg_color rgba(243, 139, 168, 0.70);
      @define-color error_fg_color #11111b;

      * {
        all: unset;
        font-family: Inter, "JetBrainsMono Nerd Font", sans-serif;
        font-size: 14px;
      }

      popover {
        background: @panel_bg_color;
        border: 1px solid @border_color;
        border-radius: 12px;
        padding: 8px;
      }

      scrollbar {
        opacity: 0;
      }

      .box-wrapper {
        background: @window_bg_color;
        border: 1px solid @border_color;
        border-radius: 16px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.42), 0 6px 20px rgba(0, 0, 0, 0.30);
        padding: 16px;
      }

      .search-container {
        background: @field_bg_color;
        border: 1px solid rgba(232, 236, 243, 0.14);
        border-radius: 12px;
      }

      .input {
        background: transparent;
        color: @theme_fg_color;
        caret-color: @accent_strong_color;
        padding: 13px 15px;
        font-size: 16px;
      }

      .input placeholder {
        color: @muted_fg_color;
        opacity: 0.62;
      }

      .item {
        border-radius: 11px;
        color: @theme_fg_color;
        padding: 10px 12px;
      }

      .item:selected {
        background: @accent_bg_color;
        color: @theme_fg_color;
      }
    '';
    environment.etc."xdg/satty/config.toml".text = ''
      [general]
      early-exit = true
      corner-roundness = 12
      initial-tool = "pointer"
      copy-command = "wl-copy"
      disable-notifications = true
      actions-on-enter = ["save-to-file"]
      actions-on-escape = ["exit"]
      actions-on-right-click = ["save-to-clipboard", "exit"]
    '';
    environment.etc."xdg/wofi/config".text = ''
      width=640
      height=460
      prompt=Search apps and commands
      allow_images=true
      insensitive=true
      no_actions=true
      matching=fuzzy
      term=kitty
    '';
    environment.etc."xdg/wofi/style.css".text = ''
      window {
        margin: 0;
        border: 1px solid rgba(205, 214, 244, 0.22);
        border-radius: 16px;
        background-color: rgba(30, 30, 46, 0.88);
        color: ${digitalPalsColors.mOnSurface};
        font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace;
        font-size: 14px;
      }

      #input {
        margin: 16px;
        padding: 12px 14px;
        border: 1px solid rgba(205, 214, 244, 0.16);
        border-radius: 12px;
        background-color: rgba(49, 50, 68, 0.72);
        color: ${digitalPalsColors.mOnSurface};
      }

      #inner-box {
        margin: 0 12px 12px 12px;
      }

      #entry {
        padding: 10px 12px;
        border-radius: 11px;
      }

      #entry:selected {
        background-color: rgba(203, 166, 247, 0.42);
      }

      #text {
        color: ${digitalPalsColors.mOnSurface};
      }
    '';
    environment.etc."cybex/waybar/config".text = waybarConfig;
    environment.etc."cybex/waybar/style.css".text = ''
      * {
        border: none;
        border-radius: 0;
        font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace;
        font-size: 12px;
        min-height: 0;
      }

      window#waybar {
        background: rgba(30, 30, 46, 0.88);
        border-bottom: 1px solid rgba(76, 79, 105, 0.62);
        color: ${digitalPalsColors.mOnSurface};
      }

      #workspaces button {
        color: ${digitalPalsColors.mOnSurfaceVariant};
        padding: 0 9px;
      }

      #workspaces button.active {
        color: ${digitalPalsColors.mOnPrimary};
        background: ${digitalPalsColors.mPrimary};
      }

      #window,
      #clock,
      #network,
      #pulseaudio,
      #battery,
      #tray {
        padding: 0 10px;
      }

      #battery.warning {
        color: ${digitalPalsColors.mSecondary};
      }

      #battery.critical {
        color: ${digitalPalsColors.mError};
      }
    '';
    environment.etc."cybex/mako/config".text = ''
      background-color=${digitalPalsColors.mSurface}ee
      text-color=${digitalPalsColors.mOnSurface}
      border-color=${digitalPalsColors.mPrimary}
      border-size=1
      border-radius=10
      padding=12
      default-timeout=6500
      font=JetBrainsMono Nerd Font 10
    '';
    })
  ];
}
