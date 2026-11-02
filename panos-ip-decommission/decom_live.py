"""Generate Panorama decommission commands using Panorama's own reference check.

For every IP and device group, the tool asks Panorama (XML API) to delete the
matching address object from the candidate configuration. When the object is
still in use, Panorama refuses and lists every reference to it. The tool
parses that list, looks up each referencing group or rule and decides whether
only the member has to be removed or the whole group or rule has to go. Groups
that would be left empty are followed the same way, so the references to them
are found too.

Deletes that succeed only touch the candidate configuration, which is
reverted before the tool exits. The output is a commands file to review and
apply manually.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
import urllib3
import xmltodict

from decom_plan import SHARED, DecomPlan, ObjectRef, RuleRef, as_list, members_at, text

LOG = logging.getLogger("decom_live")

FORCE_LIST = ("entry", "member", "line")
PANORAMA_DEVICE = "localhost.localdomain"
CODE_OBJECT_NOT_FOUND = "7"
REFERENCES_MARKER = "cannot be deleted because of references from"


class PanoramaApiError(RuntimeError):
    pass


class PanoramaXmlApi:
    """Minimal PAN-OS XML API client.

    Requests are sent as POST so that XPaths and commands do not end up in
    URLs, and the API key travels in the ``X-PAN-KEY`` header.
    """

    def __init__(self, host: str, api_key: str, verify: bool = True, timeout: float = 60):
        self.url = f"https://{host}/api/"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"X-PAN-KEY": api_key})

    def request(self, params: dict) -> dict:
        response = self.session.post(self.url, data=params, timeout=self.timeout)
        response.raise_for_status()
        return xmltodict.parse(response.text, force_list=FORCE_LIST)["response"]

    def op(self, cmd: str) -> dict:
        result = self.request({"type": "op", "cmd": cmd})
        if result.get("@status") != "success":
            raise PanoramaApiError(f"{cmd}: {message_text(result)}")
        return result

    def show(self, xpath: str) -> dict | None:
        """Return the running-config entry at ``xpath``, or ``None`` if it does not exist."""
        result = self.request({"type": "config", "action": "show", "xpath": xpath})
        if result.get("@status") != "success":
            raise PanoramaApiError(f"show {xpath}: {message_text(result)}")
        entries = as_list((result.get("result") or {}).get("entry"))
        return entries[0] if entries else None

    def delete(self, xpath: str) -> dict:
        return self.request({"type": "config", "action": "delete", "xpath": xpath})

    def device_groups(self) -> list[str]:
        result = self.op("<show><devicegroups></devicegroups></show>")
        devicegroups = (result.get("result") or {}).get("devicegroups") or {}
        return [entry["@name"] for entry in as_list(devicegroups.get("entry"))]

    def has_pending_changes(self) -> bool:
        result = self.op("<check><pending-changes></pending-changes></check>")
        return text(result.get("result", "")).strip().lower() == "yes"

    def revert(self) -> None:
        self.op("<revert><config></config></revert>")


def message_lines(result: dict) -> list[str]:
    msg = result.get("msg")
    if isinstance(msg, dict):
        lines = as_list(msg.get("line"))
    else:
        lines = as_list(msg)
    return [text(line).strip() for line in lines if text(line).strip()]


def message_text(result: dict) -> str:
    return " ".join(message_lines(result)) or "no message"


def xpath_literal(value: str) -> str:
    return f'"{value}"' if "'" in value else f"'{value}'"


def location_xpath(location: str) -> str:
    if location == SHARED:
        return "/config/shared"
    return (
        f"/config/devices/entry[@name='{PANORAMA_DEVICE}']"
        f"/device-group/entry[@name={xpath_literal(location)}]"
    )


def object_xpath(obj: ObjectRef) -> str:
    return f"{location_xpath(obj.location)}/{obj.kind}/entry[@name={xpath_literal(obj.name)}]"


def rule_xpath(rule: RuleRef) -> str:
    return (
        f"{location_xpath(rule.location)}/{rule.rulebase}/{rule.rule_type}"
        f"/rules/entry[@name={xpath_literal(rule.name)}]"
    )


@dataclass(frozen=True)
class GroupReference:
    group: ObjectRef


@dataclass(frozen=True)
class RuleReference:
    rule: RuleRef
    path: tuple[str, ...]


def parse_reference(line: str) -> GroupReference | RuleReference | None:
    """Parse one reference line from a failed delete.

    Examples of the format returned by Panorama::

        shared -> address-group -> GRP_APP_SERVERS -> static
        device-group -> DG-Prod -> post-rulebase -> security -> rules -> Allow web -> destination
    """
    parts = [part.strip() for part in line.split(" -> ")]
    if parts[0] == SHARED:
        location, rest = SHARED, parts[1:]
    elif parts[0] == "device-group" and len(parts) > 1:
        location, rest = parts[1], parts[2:]
    else:
        return None

    if len(rest) == 3 and rest[0] == "address-group" and rest[2] == "static":
        return GroupReference(ObjectRef(location, "address-group", rest[1]))
    if len(rest) >= 5 and rest[0].endswith("rulebase") and rest[2] == "rules":
        return RuleReference(RuleRef(location, rest[0], rest[1], rest[3]), tuple(rest[4:]))
    return None


class LivePlanner:
    def __init__(self, api: PanoramaXmlApi):
        self.api = api
        self.plan = DecomPlan()
        self.visited: set[ObjectRef] = set()
        self._entries: dict[ObjectRef | RuleRef, dict | None] = {}

    def entry(self, item: ObjectRef | RuleRef) -> dict | None:
        if item not in self._entries:
            xpath = object_xpath(item) if isinstance(item, ObjectRef) else rule_xpath(item)
            self._entries[item] = self.api.show(xpath)
        return self._entries[item]

    def process_object(self, obj: ObjectRef) -> bool:
        """Try to delete ``obj`` and follow its references. Returns ``False`` if it does not exist."""
        if obj in self.visited:
            return True
        self.visited.add(obj)

        result = self.api.delete(object_xpath(obj))
        status, code = result.get("@status"), result.get("@code")

        if status == "success" and code == CODE_OBJECT_NOT_FOUND:
            LOG.debug("%s %s not found in %s", obj.kind, obj.name, obj.location)
            return False

        if status == "success":
            LOG.info("%s %s (%s) has no references", obj.kind, obj.name, obj.location)
            self.plan.delete_object(obj)
            return True

        lines = message_lines(result)
        if not lines or REFERENCES_MARKER not in lines[0]:
            raise PanoramaApiError(f"delete {obj.kind} {obj.name} ({obj.location}): {message_text(result)}")

        LOG.info("%s %s (%s) is referenced from:", obj.kind, obj.name, obj.location)
        self.plan.delete_object(obj)
        for line in lines[1:]:
            LOG.info("  %s", line)
            self.process_reference(obj, line)
        return True

    def process_reference(self, obj: ObjectRef, line: str) -> None:
        reference = parse_reference(line)
        if reference is None:
            self.plan.manual_review.append(f"{obj.name}: {line}")
            return

        if isinstance(reference, GroupReference):
            group = reference.group
            if self.plan.is_deleted(group):
                return
            entry = self.entry(group)
            if entry is None:
                self.plan.manual_review.append(f"{obj.name}: {line} (group not found in running config)")
                return
            members = set(members_at(entry, ("static",)))
            remaining = members - self.plan.pending_group_removals(group) - {obj.name}
            if remaining:
                self.plan.remove_group_member(group, obj.name)
            else:
                LOG.info("  address-group %s would be left empty, following its references", group.name)
                self.process_object(group)
            return

        rule, path = reference.rule, reference.path
        if self.plan.is_deleted(rule):
            return
        entry = self.entry(rule)
        if entry is None:
            self.plan.manual_review.append(f"{obj.name}: {line} (rule not found in running config)")
            return
        members = set(members_at(entry, path))
        remaining = members - self.plan.pending_rule_removals(rule, path) - {obj.name}
        if remaining:
            self.plan.remove_rule_member(rule, path, obj.name)
        else:
            self.plan.delete_rule(rule)


def read_ips(path: Path) -> list[str]:
    """Read one IP address per line, ignoring blank lines and ``#`` comments."""
    ips = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from None
        ips.append(value)
    return ips


def run(api: PanoramaXmlApi, ips: list[str], name_format: str, skip_dg: re.Pattern | None) -> tuple[DecomPlan, list[str]]:
    """Build the plan for ``ips``. Returns the plan and the IPs with no object anywhere."""
    if api.has_pending_changes():
        raise PanoramaApiError(
            "the candidate configuration has uncommitted changes; commit or revert them first, "
            "since this tool reverts the candidate configuration when it finishes"
        )

    locations = [SHARED] + [dg for dg in api.device_groups() if not (skip_dg and skip_dg.search(dg))]
    planner = LivePlanner(api)
    found = set()

    try:
        for location in locations:
            LOG.info("Checking %s", location)
            for ip in ips:
                obj = ObjectRef(location, "address", name_format.format(ip=ip))
                if planner.process_object(obj):
                    found.add(ip)
    finally:
        LOG.info("Reverting the candidate configuration")
        try:
            api.revert()
            still_pending = api.has_pending_changes()
        except (requests.RequestException, PanoramaApiError) as exc:
            LOG.error("Could not revert the candidate configuration (%s); revert it manually", exc)
        else:
            if still_pending:
                LOG.error("The candidate configuration still has pending changes; revert it manually")

    return planner.plan, [ip for ip in ips if ip not in found]


def configure_logging(log_file: Path) -> None:
    close_logging()
    LOG.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    LOG.addHandler(file_handler)
    LOG.addHandler(console_handler)


def close_logging() -> None:
    for handler in list(LOG.handlers):
        handler.close()
        LOG.removeHandler(handler)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=os.environ.get("PANOS_HOST"), help="Panorama address (default: $PANOS_HOST)")
    parser.add_argument("-i", "--input", type=Path, required=True, help="file with one IP address per line")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("output"), help="directory for the commands and log files")
    parser.add_argument(
        "--name-format", default="H_{ip}",
        help="address object naming convention, with {ip} as placeholder (default: H_{ip})",
    )
    parser.add_argument("--skip-dg", type=re.compile, metavar="REGEX", help="skip device groups whose name matches REGEX")
    parser.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    args = parser.parse_args(argv)
    if not args.host:
        parser.error("--host is required when PANOS_HOST is not set")
    if "{ip}" not in args.name_format:
        parser.error("--name-format must contain {ip}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        ips = read_ips(args.input)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    commands_file = args.output_dir / f"{timestamp}_commands.txt"
    log_file = args.output_dir / f"{timestamp}_log.txt"
    configure_logging(log_file)

    api_key = os.environ.get("PANOS_API_KEY") or getpass.getpass("API key: ")
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    api = PanoramaXmlApi(args.host, api_key, verify=not args.insecure)

    try:
        plan, not_found = run(api, ips, args.name_format, args.skip_dg)
    except (requests.RequestException, PanoramaApiError) as exc:
        LOG.error("Aborted: %s", exc)
        return 1
    finally:
        close_logging()

    commands = plan.commands()
    commands_file.write_text("\n".join(commands) + "\n" if commands else "")

    for line in plan.summary():
        print(line)
    if not_found:
        print(f"IPs without an address object: {', '.join(not_found)}")
    print(f"Commands: {commands_file}")
    print(f"Log:      {log_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
