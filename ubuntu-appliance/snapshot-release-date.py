#!/usr/bin/env python3
"""Render a James Ubuntu snapshot ID as a deterministic Debian Release date."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import sys


SNAPSHOT_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def snapshot_moment(snapshot_id: str) -> datetime:
    if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise ValueError("Ubuntu snapshot ID must use YYYYMMDDTHHMMSSZ")
    try:
        return datetime.strptime(snapshot_id, "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError("Ubuntu snapshot ID is not a real UTC timestamp") from error


def release_date(snapshot_id: str) -> str:
    moment = snapshot_moment(snapshot_id)
    return (
        f"{WEEKDAYS[moment.weekday()]}, {moment.day:02d} "
        f"{MONTHS[moment.month - 1]} {moment.year:04d} "
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} +0000"
    )


def main() -> None:
    epoch = False
    if len(sys.argv) == 2:
        snapshot_id = sys.argv[1]
    elif len(sys.argv) == 3 and sys.argv[1] == "--epoch":
        epoch = True
        snapshot_id = sys.argv[2]
    else:
        raise SystemExit(f"usage: {sys.argv[0]} [--epoch] SNAPSHOT_ID")
    try:
        rendered = (
            str(int(snapshot_moment(snapshot_id).timestamp()))
            if epoch
            else release_date(snapshot_id)
        )
    except ValueError as error:
        raise SystemExit(f"error: {error}") from None
    print(rendered)


if __name__ == "__main__":
    main()
