import ipaddress
import json
from pathlib import Path

import pytest

import decom_offline as offline

PROJECT_DIR = Path(__file__).resolve().parent.parent
EXPORT_DIR = PROJECT_DIR / "sample_data" / "export"
IPS_FILE = PROJECT_DIR / "ips.example.txt"

EXPECTED_SAMPLE_COMMANDS = [
    'delete device-group DG-Prod post-rulebase security rules "Allow legacy DB"',
    'delete device-group DG-Prod post-rulebase security rules "Allow backup"',
    'delete device-group DG-Edge post-rulebase nat rules "Inbound DNAT db01"',
    'delete shared pre-rulebase security rules "Allow DNS from servers" source H_192.0.2.10',
    'delete device-group DG-Prod post-rulebase security rules "Allow mgmt to hosts" destination H_192.0.2.10',
    'delete device-group DG-Edge post-rulebase nat rules "Outbound SNAT hosts" source H_192.0.2.10',
    "delete shared address-group GRP_APP_SERVERS static H_192.0.2.10",
    "delete shared address-group GRP_MONITORED static GRP_LEGACY_ALL",
    "delete shared address-group GRP_LEGACY_ALL",
    "delete shared address-group GRP_LEGACY_DB",
    "delete shared address H_192.0.2.10",
    "delete shared address H_192.0.2.11",
    "delete shared address H_192.0.2.12",
    "delete device-group DG-Prod address H_198.51.100.20",
]


def ips(*values):
    return [ipaddress.ip_interface(value) for value in values]


def address(name, value, dg=None, kind="ip-netmask"):
    entry = {"@name": name, kind: value}
    entry.update({"@location": "device-group", "@device-group": dg} if dg else {"@location": "shared"})
    return entry


def rule(name, source, destination, dg="DG-Prod", **extra):
    return {
        "@name": name, "@location": "device-group", "@device-group": dg,
        "source": {"member": source}, "destination": {"member": destination}, **extra,
    }


def analyze(addresses, groups=(), rules=(), targets=("192.0.2.10",)):
    return offline.OfflineAnalyzer(list(addresses), list(groups), list(rules)).run(ips(*targets))


def test_sample_export_produces_expected_commands():
    addresses, groups, rules, missing = offline.load_export(EXPORT_DIR)
    plan, unmatched = offline.OfflineAnalyzer(addresses, groups, rules).run(offline.read_ips(IPS_FILE))

    assert missing == []
    assert plan.commands() == EXPECTED_SAMPLE_COMMANDS
    assert [offline.format_ip(ip) for ip in unmatched] == ["203.0.113.99"]


def test_bare_ip_and_host_prefix_match_the_same_object():
    plan, unmatched = analyze(
        [address("A", "192.0.2.10/32"), address("B", "192.0.2.11")], targets=("192.0.2.10", "192.0.2.11/32")
    )
    assert unmatched == []
    assert plan.commands() == ["delete shared address A", "delete shared address B"]


def test_every_matching_object_is_found():
    plan, _ = analyze([address("FIRST", "192.0.2.1"), address("H_192.0.2.10", "192.0.2.10")])
    assert plan.commands() == ["delete shared address H_192.0.2.10"]


def test_fqdn_range_and_invalid_objects_are_skipped():
    plan, unmatched = analyze([
        address("F", "www.example.com", kind="fqdn"),
        address("R", "192.0.2.1-192.0.2.20", kind="ip-range"),
        address("BAD", "not-an-ip"),
    ])
    assert plan.commands() == []
    assert len(unmatched) == 1


def test_rule_is_deleted_when_a_field_would_be_empty():
    plan, _ = analyze([address("H", "192.0.2.10")], rules=[("post-rulebase", "security", rule("R", ["H"], ["any"]))])
    assert plan.commands()[0] == "delete device-group DG-Prod post-rulebase security rules R"


def test_source_and_destination_are_both_edited():
    entry = rule("R", ["H", "OTHER"], ["H", "OTHER"])
    plan, _ = analyze([address("H", "192.0.2.10")], rules=[("post-rulebase", "security", entry)])
    assert plan.commands()[:2] == [
        "delete device-group DG-Prod post-rulebase security rules R source H",
        "delete device-group DG-Prod post-rulebase security rules R destination H",
    ]


def test_nat_translated_address_deletes_the_rule():
    static_nat = rule("NAT", ["any"], ["any"], **{
        "source-translation": {"static-ip": {"translated-address": "H", "bi-directional": "yes"}}
    })
    plan, _ = analyze([address("H", "192.0.2.10")], rules=[("post-rulebase", "nat", static_nat)])
    assert plan.commands()[0] == "delete device-group DG-Prod post-rulebase nat rules NAT"


def test_local_object_with_same_name_shadows_shared_one():
    addresses = [address("H", "192.0.2.10"), address("H", "198.51.100.10", dg="DG-Lab")]
    lab_rule = rule("Lab rule", ["H"], ["any"], dg="DG-Lab")
    prod_rule = rule("Prod rule", ["H"], ["any"], dg="DG-Prod")
    plan, _ = analyze(addresses, rules=[("post-rulebase", "security", lab_rule), ("post-rulebase", "security", prod_rule)])
    assert plan.commands() == [
        "delete device-group DG-Prod post-rulebase security rules \"Prod rule\"",
        "delete shared address H",
    ]


def test_dynamic_groups_are_ignored():
    groups = [{"@name": "DYN", "@location": "shared", "dynamic": {"filter": "'web'"}}]
    plan, _ = analyze([address("H", "192.0.2.10")], groups=groups)
    assert plan.commands() == ["delete shared address H"]


def test_group_emptied_by_several_ips_is_deleted():
    groups = [{"@name": "G", "@location": "shared", "static": {"member": ["A", "B"]}}]
    plan, _ = analyze(
        [address("A", "192.0.2.10"), address("B", "192.0.2.11")], groups=groups, targets=("192.0.2.10", "192.0.2.11")
    )
    assert plan.commands() == ["delete shared address-group G", "delete shared address A", "delete shared address B"]


def test_read_ips_ignores_comments_and_reports_bad_lines(tmp_path):
    good = tmp_path / "good.txt"
    good.write_text("# header\n192.0.2.10  # app01\n\n192.0.2.0/24\n")
    assert [offline.format_ip(ip) for ip in offline.read_ips(good)] == ["192.0.2.10", "192.0.2.0/24"]

    bad = tmp_path / "bad.txt"
    bad.write_text("192.0.2.10\n192.0.2.300\n")
    with pytest.raises(ValueError, match="bad.txt:2"):
        offline.read_ips(bad)


def test_load_entries_accepts_raw_rest_response(tmp_path):
    path = tmp_path / "addresses.json"
    path.write_text(json.dumps({"@status": "success", "result": {"entry": [address("H", "192.0.2.10")]}}))
    assert offline.load_entries(path)[0]["@name"] == "H"


def test_main_writes_commands_file(tmp_path, capsys):
    out = tmp_path / "commands.txt"
    exit_code = offline.main(["-e", str(EXPORT_DIR), "-i", str(IPS_FILE), "-o", str(out)])

    assert exit_code == 0
    assert out.read_text().splitlines() == EXPECTED_SAMPLE_COMMANDS
    err = capsys.readouterr().err
    assert "Rules to delete:           3" in err
    assert "IPs without an address object: 203.0.113.99" in err


def test_main_warns_about_missing_rule_files(tmp_path, capsys):
    (tmp_path / "addresses.json").write_text(json.dumps([address("H", "192.0.2.10")]))
    exit_code = offline.main(["-e", str(tmp_path), "-i", str(IPS_FILE)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "security_post_rules.json not found" in captured.err
    assert captured.out.strip() == "delete shared address H"
