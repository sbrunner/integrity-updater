# Copyright (c) 2024, Stéphane Brunner
"""Update the copyright header of the files."""

import argparse
import base64
import datetime
import hashlib
import os.path
import re
import subprocess  # nosec
import sys
from typing import Optional

import requests
from bs4 import BeautifulSoup

CURRENT_YEAR = str(datetime.datetime.now().year)


_DEFAULT_ALGORITHM = "sha384"

_RECOGNIZED_ALGORITHMS = ("sha512", "sha384", "sha256")

_INTEGRITY_PATTERN = re.compile(
    r"""
    [ \t]*                                  # RFC 5234 (ABNF): WSP
    (?P<algorithm>{})                       # W3C CSP2: hash-algo
    -
    (?P<b64digest>[a-zA-Z0-9+/]+[=]{{0,2}})   # W3C CSP2: base64-value
    (?P<options>\?[\041-\176]*)?            # RFC 5234 (ABNF): VCHAR
    [ \t]*                                  # RFC 5234 (ABNF): WSP
    """.format(
        "|".join(_RECOGNIZED_ALGORITHMS)
    ),
    re.VERBOSE,
)


def _update_tag(
    tag: BeautifulSoup,
    src_attribute: str,
    cross_origin: bool,
    referrer_policy: bool,
    blacklist: Optional[re.Pattern[str]] = None,
) -> tuple[bool, bool]:
    changed = False
    if tag.has_attr(src_attribute) and tag[src_attribute].startswith("https://"):
        if blacklist and blacklist.match(tag[src_attribute]):
            return False, True

        algorithm = _DEFAULT_ALGORITHM
        if tag.has_attr("integrity"):
            match = _INTEGRITY_PATTERN.match(tag["integrity"])
            if match is not None and match.group("algorithm") in _RECOGNIZED_ALGORITHMS:
                algorithm = match.group("algorithm")

        response = requests.get(tag[src_attribute], timeout=30)
        if not response.ok:
            print("Error while fetching", tag[src_attribute])
            return False, False

        hasher = hashlib.new(algorithm, response.content)
        digest = hasher.digest()
        integrity = f"{algorithm}-{base64.standard_b64encode(digest).decode()}"
        if tag.get("integrity") != integrity:
            tag["integrity"] = integrity
            changed = True

        if tag.get("crossorigin") is None and cross_origin:
            changed = True
            tag["crossorigin"] = "anonymous"

        if tag.get("referrerpolicy") is None and referrer_policy:
            changed = True
            tag["referrerpolicy"] = "no-referrer"
    return changed, True


_SCRIPT_RE = re.compile(r"<script[^>]*src=[\"'][^\"']*[\"'][^>]*>[^<]*</script>")
_LINK_RE = re.compile(r"<link[^>]*href=[\"'][^\"']*[\"'][^>]*>")


def main() -> None:
    """Update the copyright header of the files."""
    args_parser = argparse.ArgumentParser("Update the integrity of the scrypt and link HTML tags")
    args_parser.add_argument(
        "--no-crossorigin",
        action="store_false",
        dest="cross_origin",
        default=True,
        help="Do not add the cross origin attribute",
    )
    args_parser.add_argument(
        "--no-referrerpolicy",
        action="store_false",
        dest="referrer_policy",
        default=True,
        help="Do not add the referrer policy attribute",
    )
    args_parser.add_argument("--pre-commit", action="store_true", help="Run pre-commit on the updated files")
    args_parser.add_argument("--blacklist", help="Regular expression to blacklist some URL")
    args_parser.add_argument("files", nargs=argparse.REMAINDER, help="The files to update")
    args = args_parser.parse_args()

    if not args.files:
        print("No files to update")
        sys.exit(1)

    for file in args.files:
        if not os.path.isfile(file):
            print(f"The file {file} does not exist")
            sys.exit(1)

    all_success = True
    blacklist = re.compile(args.blacklist) if args.blacklist else None
    for file in args.files:
        with open(file, encoding="utf-8") as destination_file:
            content = destination_file.read()
        scripts = _SCRIPT_RE.findall(content, re.MULTILINE)
        replace = {}
        for script in scripts:
            tag = BeautifulSoup(script, "html.parser")
            updated, success = _update_tag(
                tag.find("script"), "src", args.cross_origin, args.referrer_policy, blacklist
            )
            all_success = all_success and success

            if updated:
                replace[script] = tag.prettify().strip()

        styles = _LINK_RE.findall(content, re.MULTILINE)
        for style in styles:
            tag = BeautifulSoup(style, "html.parser")
            updated, success = _update_tag(
                tag.find("link"), "href", args.cross_origin, args.referrer_policy, blacklist
            )
            all_success = all_success and success

            if updated:
                replace[style] = tag.prettify().strip()

        if replace:
            for old, new in replace.items():
                content = content.replace(old, new)
            with open(file, "w", encoding="utf-8") as destination_file:
                destination_file.write(content)

            if args.pre_commit:
                env = {**os.environ}
                if "SKIP" in env:
                    env["SKIP"] += ",integrity-updater"
                else:
                    env["SKIP"] = "integrity-updater"
                subprocess.run(  # pylint: disable=subprocess-run-check
                    ["pre-commit", "run", "--color=never", "--file=" + file], env=env
                )  # nosec

    if not all_success:
        sys.exit(1)


if __name__ == "__main__":
    main()
