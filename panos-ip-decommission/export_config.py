"""Export Panorama address objects and policies to JSON with the REST API.

The files written here are the input of ``decom_offline.py``. Objects and
rules are read from ``shared`` and from each requested device group, and
every entry keeps the ``@location`` / ``@device-group`` attributes returned
by the API, so the offline analysis knows where each one is defined.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

import requests
import urllib3

DEFAULT_API_VERSION = "10.2"

# Output file name -> REST API resource
RESOURCES = {
    "addresses.json": "Objects/Addresses",
    "address_groups.json": "Objects/AddressGroups",
    "security_pre_rules.json": "Policies/SecurityPreRules",
    "security_post_rules.json": "Policies/SecurityPostRules",
    "nat_pre_rules.json": "Policies/NatPreRules",
    "nat_post_rules.json": "Policies/NatPostRules",
}


class PanoramaRestError(RuntimeError):
    pass


class PanoramaRestApi:
    def __init__(self, host: str, api_key: str, api_version: str = DEFAULT_API_VERSION,
                 verify: bool = True, timeout: float = 60):
        self.base_url = f"https://{host}/restapi/v{api_version}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Accept": "application/json", "X-PAN-KEY": api_key})

    def get_entries(self, resource: str, device_group: str | None = None) -> list[dict]:
        """Return all entries of ``resource`` in ``shared`` or in ``device_group``."""
        if device_group:
            params = {"location": "device-group", "device-group": device_group}
        else:
            params = {"location": "shared"}

        response = self.session.get(f"{self.base_url}/{resource}", params=params, timeout=self.timeout)
        try:
            data = response.json()
        except ValueError:
            data = {}

        if response.status_code != 200 or data.get("@status") != "success":
            message = data.get("message") or data.get("details") or response.text[:200]
            location = device_group or "shared"
            raise PanoramaRestError(f"{resource} ({location}): HTTP {response.status_code}: {message}")

        return data.get("result", {}).get("entry", [])


def export_config(api: PanoramaRestApi, device_groups: list[str]) -> dict[str, list[dict]]:
    export = {}
    for file_name, resource in RESOURCES.items():
        entries = api.get_entries(resource)
        for device_group in device_groups:
            entries.extend(api.get_entries(resource, device_group))
        export[file_name] = entries
    return export


def write_export(out_dir: Path, export: dict[str, list[dict]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for file_name, entries in export.items():
        (out_dir / file_name).write_text(json.dumps(entries, indent=4) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=os.environ.get("PANOS_HOST"), help="Panorama address (default: $PANOS_HOST)")
    parser.add_argument(
        "-g", "--device-group", action="append", dest="device_groups", default=[], metavar="NAME",
        help="device group to export in addition to shared (can be repeated)",
    )
    parser.add_argument("-o", "--out", type=Path, default=Path("export"), help="output directory (default: export)")
    parser.add_argument("--api-version", default=DEFAULT_API_VERSION, help=f"REST API version (default: {DEFAULT_API_VERSION})")
    parser.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    args = parser.parse_args(argv)
    if not args.host:
        parser.error("--host is required when PANOS_HOST is not set")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    api_key = os.environ.get("PANOS_API_KEY") or getpass.getpass("API key: ")

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    api = PanoramaRestApi(args.host, api_key, args.api_version, verify=not args.insecure)

    try:
        export = export_config(api, args.device_groups)
    except (requests.RequestException, PanoramaRestError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return 1

    write_export(args.out, export)
    for file_name, entries in export.items():
        print(f"{file_name}: {len(entries)} entries")
    print(f"Export written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
