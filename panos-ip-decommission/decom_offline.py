"""Generate Panorama decommission commands from an exported configuration.

Reads the JSON files written by ``export_config.py``, finds the address
objects that match the IPs to decommission and follows every reference to
them through address groups (including nested groups), security rules and
NAT rules. The result is a list of ``delete`` CLI commands, written in an
order that removes references before the objects they point to.

The analysis is read-only: it never connects to Panorama.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from decom_plan import SHARED, DecomPlan, ObjectRef, RuleRef, members_at

ADDRESSES_FILE = "addresses.json"
ADDRESS_GROUPS_FILE = "address_groups.json"
RULE_FILES = {
    ("pre-rulebase", "security"): "security_pre_rules.json",
    ("post-rulebase", "security"): "security_post_rules.json",
    ("pre-rulebase", "nat"): "nat_pre_rules.json",
    ("post-rulebase", "nat"): "nat_post_rules.json",
}

# Rule fields that hold address objects or groups. If one of them would be
# left empty, the whole rule is deleted: an empty source or destination is not
# valid, and replacing it with "any" would widen the rule.
RULE_FIELDS = {
    "security": [("source",), ("destination",)],
    "nat": [
        ("source",),
        ("destination",),
        ("source-translation", "dynamic-ip-and-port", "translated-address"),
        ("source-translation", "dynamic-ip", "translated-address"),
        ("source-translation", "static-ip", "translated-address"),
        ("destination-translation", "translated-address"),
        ("dynamic-destination-translation", "translated-address"),
    ],
}


def read_ips(path: Path) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
    """Read one IP or prefix per line, ignoring blank lines and ``#`` comments."""
    ips = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            ips.append(ipaddress.ip_interface(value))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from None
    return ips


def format_ip(ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
    return str(ip.ip) if ip.network.num_addresses == 1 else ip.with_prefixlen


def entry_location(entry: dict) -> str:
    if entry.get("@location") == "device-group":
        return entry.get("@device-group") or entry.get("@loc") or SHARED
    return SHARED


def load_entries(path: Path) -> list[dict]:
    """Load an export file, accepting a plain list or a raw REST API response."""
    with open(path) as file:
        data = json.load(file)
    if isinstance(data, dict):
        data = data.get("result", {}).get("entry", [])
    return data


def load_export(export_dir: Path) -> tuple[list[dict], list[dict], list[tuple[str, str, dict]], list[str]]:
    addresses = load_entries(export_dir / ADDRESSES_FILE)

    groups_path = export_dir / ADDRESS_GROUPS_FILE
    groups = load_entries(groups_path) if groups_path.exists() else []

    rules, missing = [], []
    for (rulebase, rule_type), file_name in RULE_FILES.items():
        path = export_dir / file_name
        if not path.exists():
            missing.append(file_name)
            continue
        rules.extend((rulebase, rule_type, entry) for entry in load_entries(path))
    if not groups_path.exists():
        missing.append(ADDRESS_GROUPS_FILE)
    return addresses, groups, rules, missing


class OfflineAnalyzer:
    def __init__(self, addresses: list[dict], groups: list[dict], rules: list[tuple[str, str, dict]]):
        self.addresses = addresses
        self.static_groups = [group for group in groups if "static" in group]
        self.rules = rules
        self.defined = {(entry_location(entry), entry["@name"]) for entry in [*addresses, *groups]}
        self.removed: set[tuple[str, str]] = set()
        self.plan = DecomPlan()

    def is_removed(self, name: str, location: str) -> bool:
        """Resolve a reference by name the way Panorama does: local first, then shared."""
        if (location, name) in self.removed:
            return True
        if location != SHARED and (location, name) in self.defined:
            return False
        return (SHARED, name) in self.removed

    def match_addresses(self, ips) -> list:
        """Mark the address objects whose value matches one of ``ips``.

        Returns the IPs that did not match any object. FQDN, range and wildcard
        objects are not compared.
        """
        wanted = set(ips)
        matched = set()
        for entry in self.addresses:
            value = entry.get("ip-netmask")
            if value is None:
                continue
            try:
                ip = ipaddress.ip_interface(value)
            except ValueError:
                continue
            if ip in wanted:
                location = entry_location(entry)
                self.removed.add((location, entry["@name"]))
                self.plan.delete_object(ObjectRef(location, "address", entry["@name"]))
                matched.add(ip)
        return [ip for ip in ips if ip not in matched]

    def resolve_groups(self) -> None:
        """Delete groups left without members, repeating until nested groups settle."""
        changed = True
        while changed:
            changed = False
            for group in self.static_groups:
                location, name = entry_location(group), group["@name"]
                if (location, name) in self.removed:
                    continue
                members = members_at(group, ("static",))
                if members and all(self.is_removed(member, location) for member in members):
                    self.removed.add((location, name))
                    self.plan.delete_object(ObjectRef(location, "address-group", name))
                    changed = True

        for group in self.static_groups:
            location, name = entry_location(group), group["@name"]
            if (location, name) in self.removed:
                continue
            for member in members_at(group, ("static",)):
                if self.is_removed(member, location):
                    self.plan.remove_group_member(ObjectRef(location, "address-group", name), member)

    def resolve_rules(self) -> None:
        for rulebase, rule_type, entry in self.rules:
            location = entry_location(entry)
            rule = RuleRef(location, rulebase, rule_type, entry["@name"])
            for path in RULE_FIELDS.get(rule_type, []):
                members = members_at(entry, path)
                hits = [member for member in members if self.is_removed(member, location)]
                if not hits:
                    continue
                if len(hits) == len(members):
                    self.plan.delete_rule(rule)
                    break
                for member in hits:
                    self.plan.remove_rule_member(rule, path, member)

    def run(self, ips) -> tuple[DecomPlan, list]:
        unmatched = self.match_addresses(ips)
        self.resolve_groups()
        self.resolve_rules()
        return self.plan, unmatched


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-e", "--export-dir", type=Path, required=True, help="directory written by export_config.py")
    parser.add_argument("-i", "--ips", type=Path, required=True, help="file with one IP or prefix per line")
    parser.add_argument("-o", "--out", type=Path, help="write the commands to this file instead of stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        ips = read_ips(args.ips)
        addresses, groups, rules, missing = load_export(args.export_dir)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for file_name in missing:
        print(f"Warning: {file_name} not found in {args.export_dir}, skipped", file=sys.stderr)

    plan, unmatched = OfflineAnalyzer(addresses, groups, rules).run(ips)

    for line in plan.summary():
        print(line, file=sys.stderr)
    if unmatched:
        print(f"IPs without an address object: {', '.join(format_ip(ip) for ip in unmatched)}", file=sys.stderr)

    commands = "\n".join(plan.commands())
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(commands + "\n" if commands else "")
        print(f"Commands written to {args.out}", file=sys.stderr)
    elif commands:
        print(commands)
    return 0


if __name__ == "__main__":
    sys.exit(main())
