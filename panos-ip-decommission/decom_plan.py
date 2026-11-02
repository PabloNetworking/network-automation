"""Decommission plan shared by the live and offline tools.

A plan records which objects and rules have to be deleted and which members
have to be removed from groups and rules that remain. ``DecomPlan.commands``
renders it as Panorama configuration-mode CLI commands, ordered so that every
reference is removed before the object it points to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SHARED = "shared"
_NEEDS_QUOTES = re.compile(r"[\s\"']")


@dataclass(frozen=True)
class ObjectRef:
    """An address or address group in ``shared`` or in a device group."""

    location: str
    kind: str  # "address" or "address-group"
    name: str


@dataclass(frozen=True)
class RuleRef:
    """A policy rule, for example a security post-rule in a device group."""

    location: str
    rulebase: str  # "pre-rulebase" or "post-rulebase"
    rule_type: str  # "security", "nat", ...
    name: str


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def text(value) -> str:
    """Return the text of a value parsed from XML or JSON.

    xmltodict turns elements that carry attributes (for example the audit
    attributes PAN-OS adds to recently changed config) into dicts.
    """
    if isinstance(value, dict):
        return str(value.get("#text", ""))
    return str(value)


def members_at(entry: dict, path: tuple[str, ...]) -> list[str]:
    """Return the object names stored at ``path`` inside a config entry.

    Handles ``{"member": [...]}`` lists, single ``member`` values and plain
    string values such as a NAT rule ``translated-address``.
    """
    node = entry
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return []
        node = node[key]
    if isinstance(node, dict) and "member" in node:
        node = node["member"]
    if isinstance(node, dict):
        return [text(node)] if "#text" in node else []
    return [text(item) for item in as_list(node)]


def quote(name: str) -> str:
    if not name or _NEEDS_QUOTES.search(name):
        escaped = name.replace('"', '\\"')
        return f'"{escaped}"'
    return name


def scope(location: str) -> str:
    return SHARED if location == SHARED else f"device-group {quote(location)}"


@dataclass
class DecomPlan:
    deleted_objects: list[ObjectRef] = field(default_factory=list)
    deleted_rules: list[RuleRef] = field(default_factory=list)
    group_member_removals: dict[ObjectRef, list[str]] = field(default_factory=dict)
    rule_member_removals: dict[RuleRef, dict[tuple[str, ...], list[str]]] = field(default_factory=dict)
    manual_review: list[str] = field(default_factory=list)

    def delete_object(self, obj: ObjectRef) -> None:
        if obj not in self.deleted_objects:
            self.deleted_objects.append(obj)

    def delete_rule(self, rule: RuleRef) -> None:
        if rule not in self.deleted_rules:
            self.deleted_rules.append(rule)

    def remove_group_member(self, group: ObjectRef, member: str) -> None:
        members = self.group_member_removals.setdefault(group, [])
        if member not in members:
            members.append(member)

    def remove_rule_member(self, rule: RuleRef, path: tuple[str, ...], member: str) -> None:
        members = self.rule_member_removals.setdefault(rule, {}).setdefault(path, [])
        if member not in members:
            members.append(member)

    def pending_group_removals(self, group: ObjectRef) -> set[str]:
        return set(self.group_member_removals.get(group, []))

    def pending_rule_removals(self, rule: RuleRef, path: tuple[str, ...]) -> set[str]:
        return set(self.rule_member_removals.get(rule, {}).get(path, []))

    def is_deleted(self, item: ObjectRef | RuleRef) -> bool:
        return item in self.deleted_objects or item in self.deleted_rules

    def edited_groups(self) -> dict[ObjectRef, list[str]]:
        return {g: m for g, m in self.group_member_removals.items() if g not in self.deleted_objects}

    def edited_rules(self) -> dict[RuleRef, dict[tuple[str, ...], list[str]]]:
        return {r: f for r, f in self.rule_member_removals.items() if r not in self.deleted_rules}

    def commands(self) -> list[str]:
        """Render the plan as CLI commands in a safe order.

        1. Delete rules that would be left without a source, destination or
           translated address.
        2. Remove members from the rules that remain.
        3. Remove members from the address groups that remain.
        4. Delete emptied address groups, outermost group first.
        5. Delete the address objects.
        """
        commands = []

        for rule in self.deleted_rules:
            commands.append(f"delete {self._rule_path(rule)}")

        for rule, fields in self.edited_rules().items():
            for path, members in fields.items():
                for member in members:
                    commands.append(f"delete {self._rule_path(rule)} {' '.join(path)} {quote(member)}")

        for group, members in self.edited_groups().items():
            for member in members:
                commands.append(
                    f"delete {scope(group.location)} address-group {quote(group.name)} static {quote(member)}"
                )

        groups = [obj for obj in self.deleted_objects if obj.kind == "address-group"]
        addresses = [obj for obj in self.deleted_objects if obj.kind != "address-group"]
        for obj in [*reversed(groups), *addresses]:
            commands.append(f"delete {scope(obj.location)} {obj.kind} {quote(obj.name)}")

        return commands

    def summary(self) -> list[str]:
        groups = [obj for obj in self.deleted_objects if obj.kind == "address-group"]
        lines = [
            f"Address objects to delete: {len(self.deleted_objects) - len(groups)}",
            f"Address groups to delete:  {len(groups)}",
            f"Address groups to edit:    {len(self.edited_groups())}",
            f"Rules to delete:           {len(self.deleted_rules)}",
            f"Rules to edit:             {len(self.edited_rules())}",
        ]
        if self.manual_review:
            lines.append(f"References to review manually: {len(self.manual_review)}")
            lines.extend(f"  {item}" for item in self.manual_review)
        return lines

    @staticmethod
    def _rule_path(rule: RuleRef) -> str:
        return f"{scope(rule.location)} {rule.rulebase} {rule.rule_type} rules {quote(rule.name)}"
