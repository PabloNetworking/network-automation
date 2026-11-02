import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from netmiko.exceptions import NetmikoTimeoutException

import vlan_consistency as vc

PROJECT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = PROJECT_DIR / "sample_data"
INVENTORY = PROJECT_DIR / "inventory.example.yaml"
TEST_USER, TEST_CREDENTIAL = "netops", "placeholder"


def interfaces_config(*interfaces):
    return {"configuration": {"interfaces": {"interface": list(interfaces)}}}


def trunk(name, members):
    return {
        "name": name,
        "unit": [{"name": 0, "family": {"ethernet-switching": {"vlan": {"members": members}}}}],
    }


def test_parse_vlans_maps_names_to_ids():
    config = {"configuration": {"vlans": {"vlan": [
        {"name": "MGMT", "vlan-id": 10},
        {"name": "NO_ID"},
    ]}}}
    assert vc.parse_vlans(config) == {"MGMT": 10, "NO_ID": None}


def test_parse_ae_members_only_considers_ae_bundles():
    config = interfaces_config(
        trunk("ae1", ["A"]),
        trunk("xe-0/0/1", ["A"]),
        trunk("irb", ["A"]),
        trunk("aex", ["A"]),
    )
    members, skipped = vc.parse_ae_members(config)
    assert members == {"ae1": {"A"}}
    assert skipped == {}


def test_parse_ae_members_reports_bundles_that_cannot_be_evaluated():
    config = interfaces_config(
        {"name": "ae1"},
        {"name": "ae2", "unit": [{"name": 0, "family": {"inet": {}}}]},
        {"name": "ae3", "unit": [{"name": 0, "family": {"ethernet-switching": {"interface-mode": "trunk"}}}]},
    )
    members, skipped = vc.parse_ae_members(config)
    assert members == {}
    assert set(skipped) == {"ae1", "ae2", "ae3"}


def test_numeric_members_are_translated_to_vlan_names():
    config = interfaces_config(trunk("ae1", ["MGMT", "20", "4000"]))
    members, _ = vc.parse_ae_members(config, {"MGMT": 10, "VMOTION": 20})
    assert members["ae1"] == {"MGMT", "VMOTION", "4000"}


def test_single_member_as_string_is_accepted():
    members, _ = vc.parse_ae_members(interfaces_config(trunk("ae1", "MGMT")))
    assert members["ae1"] == {"MGMT"}


def test_compare_group_consistent():
    members = {"ae1": {"A", "B"}, "ae2": {"A", "B"}}
    result = vc.compare_group(["ae1", "ae2"], members, {})
    assert result["consistent"]
    assert result["missing"] == {}
    assert result["inconsistent_vlans"] == set()


def test_compare_group_reports_differences_in_both_directions():
    members = {"ae1": {"A", "B"}, "ae2": {"A", "C"}, "ae3": {"A", "B", "C"}}
    result = vc.compare_group(["ae1", "ae2", "ae3"], members, {})
    assert not result["consistent"]
    assert result["missing"] == {"ae1": {"C"}, "ae2": {"B"}}
    assert result["inconsistent_vlans"] == {"B", "C"}
    assert result["all_vlans"] == {"A", "B", "C"}


def test_compare_group_does_not_modify_its_input():
    members = {"ae1": {"A"}, "ae2": {"B"}}
    vc.compare_group(["ae1", "ae2"], members, {})
    assert members == {"ae1": {"A"}, "ae2": {"B"}}


def test_compare_group_flags_missing_and_skipped_interfaces():
    members = {"ae1": {"A"}}
    result = vc.compare_group(["ae1", "ae2", "ae9"], members, {"ae2": "no unit 0 configured"})
    assert not result["consistent"]
    assert result["unavailable"] == {
        "ae2": "no unit 0 configured",
        "ae9": "interface not found in configuration",
    }


def test_build_report_on_sample_data():
    vlans, interfaces = vc.load_saved_config(SAMPLE_DIR, "leaf01")
    groups = {"esxi-cluster-a": ["ae1", "ae2", "ae3", "ae4"], "backup-hosts": ["ae10", "ae11", "ae12"]}
    report = vc.build_report("leaf01", vlans, interfaces, groups)

    esxi = report["groups"]["esxi-cluster-a"]
    assert not esxi["consistent"]
    assert esxi["vlan_count"] == 7
    assert esxi["missing"]["ae3"] == [
        {"name": "APP_TEST", "vlan_id": 130},
        {"name": "BACKUP", "vlan_id": 200},
    ]
    assert [v["name"] for v in esxi["missing"]["ae1"]] == ["APP_TEST"]
    assert "ae4" not in esxi["missing"]
    assert [v["name"] for v in esxi["inconsistent_vlans"]] == ["APP_TEST", "BACKUP"]

    backup = report["groups"]["backup-hosts"]
    assert backup["missing"] == {}
    assert backup["unavailable"] == {"ae12": "no unit 0 configured"}


def test_load_inventory_rejects_device_without_groups(tmp_path):
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("devices:\n  leaf01:\n    host: 192.0.2.11\n")
    with pytest.raises(ValueError):
        vc.load_inventory(inventory)


def test_main_offline_writes_report_and_flags_inconsistency(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    exit_code = vc.main(["-i", str(INVENTORY), "--offline", str(SAMPLE_DIR), "-r", str(report_path)])

    assert exit_code == vc.EXIT_INCONSISTENT
    report = json.loads(report_path.read_text())
    assert [device["device"] for device in report["devices"]] == ["leaf01", "leaf02"]
    assert report["devices"][1]["consistent"]
    assert "ae3 missing: APP_TEST (130), BACKUP (200)" in capsys.readouterr().out


def test_main_offline_single_consistent_device():
    exit_code = vc.main(["-i", str(INVENTORY), "--offline", str(SAMPLE_DIR), "-d", "leaf02"])
    assert exit_code == vc.EXIT_OK


def test_main_reports_missing_offline_files(tmp_path):
    exit_code = vc.main(["-i", str(INVENTORY), "--offline", str(tmp_path)])
    assert exit_code == vc.EXIT_ERROR


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("JUNOS_USERNAME", TEST_USER)
    monkeypatch.setenv("JUNOS_PASSWORD", TEST_CREDENTIAL)


def test_live_run_collects_with_netmiko_and_saves_raw_config(tmp_path, monkeypatch, credentials):
    vlans, interfaces = vc.load_saved_config(SAMPLE_DIR, "leaf02")
    outputs = {vc.VLANS_COMMAND: json.dumps(vlans), vc.INTERFACES_COMMAND: json.dumps(interfaces)}
    connection = MagicMock()
    connection.__enter__.return_value.send_command.side_effect = outputs.__getitem__
    handler = MagicMock(return_value=connection)
    monkeypatch.setattr(vc, "ConnectHandler", handler)

    exit_code = vc.main(["-i", str(INVENTORY), "-d", "leaf02", "--save-raw", str(tmp_path)])

    assert exit_code == vc.EXIT_OK
    handler.assert_called_once_with(
        device_type="juniper_junos", host="192.0.2.12", username=TEST_USER, password=TEST_CREDENTIAL, port=22
    )
    assert json.loads((tmp_path / "leaf02_interfaces.json").read_text()) == interfaces


def test_live_run_continues_after_connection_failure(monkeypatch, credentials, capsys):
    vlans, interfaces = vc.load_saved_config(SAMPLE_DIR, "leaf02")
    outputs = {vc.VLANS_COMMAND: json.dumps(vlans), vc.INTERFACES_COMMAND: json.dumps(interfaces)}
    connection = MagicMock()
    connection.__enter__.return_value.send_command.side_effect = outputs.__getitem__
    handler = MagicMock(side_effect=[NetmikoTimeoutException("timed out"), connection])
    monkeypatch.setattr(vc, "ConnectHandler", handler)

    exit_code = vc.main(["-i", str(INVENTORY)])

    assert exit_code == vc.EXIT_ERROR
    assert handler.call_count == 2
    captured = capsys.readouterr()
    assert "leaf01: could not read configuration" in captured.err
    assert "leaf02" in captured.out
