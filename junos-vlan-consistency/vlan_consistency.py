"""Check that groups of Junos aggregated Ethernet bundles carry the same VLANs.

For every device in the inventory, the script reads the VLAN and interface
configuration (live over SSH with Netmiko, or from previously saved JSON
files) and compares the VLAN membership of each configured group of ``ae``
interfaces. Any VLAN that is not present on every bundle of a group is
reported, together with the bundles where it is missing.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException, SSHException

AE_PATTERN = re.compile(r"^ae\d+$")
VLANS_COMMAND = "show configuration vlans | display json"
INTERFACES_COMMAND = "show configuration interfaces | display json"
DEFAULT_DEVICE_TYPE = "juniper_junos"

EXIT_OK = 0
EXIT_INCONSISTENT = 1
EXIT_ERROR = 2


def load_inventory(path: Path) -> dict[str, dict]:
    """Load the YAML inventory and validate the minimum required fields."""
    with open(path) as file:
        data = yaml.safe_load(file) or {}

    devices = data.get("devices") or {}
    if not devices:
        raise ValueError(f"No devices defined in {path}")

    for name, device in devices.items():
        if not device or not device.get("host"):
            raise ValueError(f"Device '{name}' has no host defined")
        groups = device.get("compare_groups")
        if not groups or not all(isinstance(members, list) and members for members in groups.values()):
            raise ValueError(f"Device '{name}' needs at least one non-empty compare group")
    return devices


def get_credentials() -> tuple[str, str]:
    """Read credentials from the environment, prompting for anything missing."""
    username = os.environ.get("JUNOS_USERNAME") or input("Username: ")
    password = os.environ.get("JUNOS_PASSWORD") or getpass.getpass("Password: ")
    return username, password


def fetch_device_config(device: dict, username: str, password: str) -> tuple[dict, dict]:
    """Connect to a device and return its VLAN and interface configuration as dicts."""
    connection_params = {
        "device_type": device.get("device_type", DEFAULT_DEVICE_TYPE),
        "host": device["host"],
        "username": username,
        "password": password,
        "port": device.get("port", 22),
    }
    with ConnectHandler(**connection_params) as connection:
        vlans = json.loads(connection.send_command(VLANS_COMMAND))
        interfaces = json.loads(connection.send_command(INTERFACES_COMMAND))
    return vlans, interfaces


def raw_config_paths(directory: Path, device_name: str) -> tuple[Path, Path]:
    return directory / f"{device_name}_vlans.json", directory / f"{device_name}_interfaces.json"


def load_saved_config(directory: Path, device_name: str) -> tuple[dict, dict]:
    vlans_path, interfaces_path = raw_config_paths(directory, device_name)
    with open(vlans_path) as file:
        vlans = json.load(file)
    with open(interfaces_path) as file:
        interfaces = json.load(file)
    return vlans, interfaces


def save_raw_config(directory: Path, device_name: str, vlans: dict, interfaces: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    vlans_path, interfaces_path = raw_config_paths(directory, device_name)
    vlans_path.write_text(json.dumps(vlans, indent=4))
    interfaces_path.write_text(json.dumps(interfaces, indent=4))


def parse_vlans(vlans_config: dict) -> dict[str, int | None]:
    """Map each VLAN name to its VLAN ID (``None`` when no single ID is set)."""
    vlans = vlans_config.get("configuration", {}).get("vlans", {}).get("vlan", [])
    return {vlan["name"]: vlan.get("vlan-id") for vlan in vlans if "name" in vlan}


def parse_ae_members(
    interfaces_config: dict, vlan_ids: dict[str, int | None] | None = None
) -> tuple[dict[str, set[str]], dict[str, str]]:
    """Return the VLAN members of every ``ae`` interface in switching mode.

    Members configured by numeric ID are translated to the VLAN name when the
    ID is defined in ``vlan_ids``, so that bundles configured with names and
    bundles configured with IDs compare correctly.

    The second value maps the ``ae`` interfaces that could not be evaluated to
    the reason why.
    """
    id_to_name = {vlan_id: name for name, vlan_id in (vlan_ids or {}).items() if vlan_id is not None}
    interfaces = interfaces_config.get("configuration", {}).get("interfaces", {}).get("interface", [])

    members_by_interface: dict[str, set[str]] = {}
    skipped: dict[str, str] = {}

    for interface in interfaces:
        name = interface.get("name", "")
        if not AE_PATTERN.match(name):
            continue

        unit = next((u for u in interface.get("unit", []) if str(u.get("name")) == "0"), None)
        if unit is None:
            skipped[name] = "no unit 0 configured"
            continue

        switching = unit.get("family", {}).get("ethernet-switching")
        if switching is None:
            skipped[name] = "unit 0 has no ethernet-switching family"
            continue

        members = switching.get("vlan", {}).get("members")
        if not members:
            skipped[name] = "no VLAN members configured"
            continue
        if isinstance(members, str):
            members = [members]

        members_by_interface[name] = {
            id_to_name.get(int(member), member) if str(member).isdigit() else str(member)
            for member in members
        }

    return members_by_interface, skipped


def compare_group(
    group_interfaces: list[str],
    members_by_interface: dict[str, set[str]],
    skipped: dict[str, str],
) -> dict:
    """Compare the VLAN membership of a group of interfaces."""
    evaluated = [name for name in group_interfaces if name in members_by_interface]
    unavailable = {
        name: skipped.get(name, "interface not found in configuration")
        for name in group_interfaces
        if name not in members_by_interface
    }

    member_sets = [members_by_interface[name] for name in evaluated]
    all_vlans = set().union(*member_sets)
    common_vlans = set.intersection(*member_sets) if member_sets else set()

    missing = {}
    for name in evaluated:
        absent = all_vlans - members_by_interface[name]
        if absent:
            missing[name] = absent

    return {
        "interfaces": list(group_interfaces),
        "consistent": not missing and not unavailable,
        "all_vlans": all_vlans,
        "inconsistent_vlans": all_vlans - common_vlans,
        "missing": missing,
        "unavailable": unavailable,
    }


def _vlan_sort_key(vlan_ids: dict[str, int | None]):
    def key(name: str):
        vlan_id = vlan_ids.get(name)
        return (vlan_id is None, vlan_id or 0, name)

    return key


def _describe(names: set[str], vlan_ids: dict[str, int | None]) -> list[dict]:
    return [{"name": name, "vlan_id": vlan_ids.get(name)} for name in sorted(names, key=_vlan_sort_key(vlan_ids))]


def build_report(device_name: str, vlans_config: dict, interfaces_config: dict, compare_groups: dict) -> dict:
    """Build the JSON-serialisable report for one device."""
    vlan_ids = parse_vlans(vlans_config)
    members_by_interface, skipped = parse_ae_members(interfaces_config, vlan_ids)

    groups = {}
    for group_name, group_interfaces in compare_groups.items():
        result = compare_group(group_interfaces, members_by_interface, skipped)
        groups[group_name] = {
            "interfaces": result["interfaces"],
            "consistent": result["consistent"],
            "vlan_count": len(result["all_vlans"]),
            "all_vlans": _describe(result["all_vlans"], vlan_ids),
            "inconsistent_vlans": _describe(result["inconsistent_vlans"], vlan_ids),
            "missing": {name: _describe(absent, vlan_ids) for name, absent in result["missing"].items()},
            "unavailable": result["unavailable"],
        }

    return {"device": device_name, "consistent": all(g["consistent"] for g in groups.values()), "groups": groups}


def format_summary(report: dict) -> str:
    lines = [report["device"]]
    for group_name, group in report["groups"].items():
        state = "consistent" if group["consistent"] else "INCONSISTENT"
        interfaces = ", ".join(group["interfaces"])
        lines.append(f"  {group_name} ({interfaces}): {group['vlan_count']} VLANs, {state}")
        for interface, vlans in group["missing"].items():
            described = ", ".join(
                f"{vlan['name']} ({vlan['vlan_id']})" if vlan["vlan_id"] is not None else vlan["name"]
                for vlan in vlans
            )
            lines.append(f"    {interface} missing: {described}")
        for interface, reason in group["unavailable"].items():
            lines.append(f"    {interface} not evaluated: {reason}")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-i", "--inventory", type=Path, required=True, help="YAML inventory file")
    parser.add_argument(
        "-d", "--device", action="append", dest="devices", metavar="NAME",
        help="only check this device (can be repeated)",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--offline", type=Path, metavar="DIR",
        help="read <device>_vlans.json and <device>_interfaces.json from DIR instead of connecting",
    )
    source.add_argument("--save-raw", type=Path, metavar="DIR", help="save the configuration pulled from each device to DIR")
    parser.add_argument("-r", "--report", type=Path, metavar="FILE", help="write the full report as JSON to FILE")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        inventory = load_inventory(args.inventory)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Inventory error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    device_names = args.devices or list(inventory)
    unknown = [name for name in device_names if name not in inventory]
    if unknown:
        print(f"Devices not in inventory: {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR

    credentials = None if args.offline else get_credentials()
    reports, failures = [], []

    # A device that cannot be read is reported and the remaining devices are still checked.
    for name in device_names:
        device = inventory[name]
        try:
            if args.offline:
                vlans, interfaces = load_saved_config(args.offline, name)
            else:
                print(f"Connecting to {name} ({device['host']})...", file=sys.stderr)
                vlans, interfaces = fetch_device_config(device, *credentials)
                if args.save_raw:
                    save_raw_config(args.save_raw, name, vlans, interfaces)
        except (OSError, ValueError, SSHException, NetmikoBaseException) as exc:
            print(f"{name}: could not read configuration: {exc}", file=sys.stderr)
            failures.append(name)
            continue

        report = build_report(name, vlans, interfaces, device["compare_groups"])
        reports.append(report)
        print(format_summary(report))

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"devices": reports, "failed": failures}, indent=4))

    if failures:
        return EXIT_ERROR
    return EXIT_OK if all(report["consistent"] for report in reports) else EXIT_INCONSISTENT


if __name__ == "__main__":
    sys.exit(main())
