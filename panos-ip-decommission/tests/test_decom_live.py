import json
import re
from pathlib import Path

import pytest
import requests
import xmltodict

import decom_live as live

PROJECT_DIR = Path(__file__).resolve().parent.parent
XML_DIR = PROJECT_DIR / "sample_data" / "xml_api"
IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "203.0.113.99"]

EXPECTED_COMMANDS = [
    'delete device-group DG-Edge post-rulebase nat rules "Inbound DNAT db01"',
    'delete device-group DG-Prod post-rulebase security rules "Allow legacy DB"',
    'delete device-group DG-Prod post-rulebase security rules "Allow mgmt to hosts" destination H_192.0.2.10',
    'delete device-group DG-Edge post-rulebase nat rules "Outbound SNAT hosts" source H_192.0.2.10',
    'delete shared pre-rulebase security rules "Allow DNS from servers" source H_192.0.2.10',
    'delete device-group DG-Prod post-rulebase security rules "Allow backup" source H_192.0.2.12',
    "delete shared address-group GRP_APP_SERVERS static H_192.0.2.10",
    "delete shared address-group GRP_MONITORED static GRP_LEGACY_ALL",
    "delete shared address-group GRP_LEGACY_ALL",
    "delete shared address-group GRP_LEGACY_DB",
    "delete shared address H_192.0.2.10",
    "delete shared address H_192.0.2.11",
    "delete shared address H_192.0.2.12",
    "delete device-group DG-Edge address H_192.0.2.10",
]


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakePanorama:
    """Stands in for ``requests.Session`` and answers from ``sample_data/xml_api``."""

    def __init__(self):
        self.index = json.loads((XML_DIR / "index.json").read_text())
        self.headers = {}
        self.verify = True
        self.calls = []
        self.overrides = {}

    def post(self, url, data, timeout):
        self.calls.append(data)
        key = data.get("cmd") or data.get("xpath")
        if (data.get("action"), key) in self.overrides:
            return FakeResponse(self.overrides[(data.get("action"), key)])
        if data["type"] == "op":
            name = self.index["op"][data["cmd"]]
        elif data["action"] == "delete":
            name = self.index["delete"].get(data["xpath"], self.index["default_delete"])
        else:
            name = self.index["show"].get(data["xpath"])
            if name is None:
                return FakeResponse('<response status="success" code="19"><result/></response>')
        return FakeResponse((XML_DIR / name).read_text())

    def calls_for(self, action):
        return [call for call in self.calls if call.get("action") == action]

    def op_calls(self):
        return [call["cmd"] for call in self.calls if call["type"] == "op"]


@pytest.fixture
def panorama(monkeypatch):
    fake = FakePanorama()
    monkeypatch.setattr(live.requests, "Session", lambda: fake)
    return fake


@pytest.fixture
def api(panorama):
    return live.PanoramaXmlApi("panorama.example.com", "example-key")


def test_parse_reference_variants():
    group = live.parse_reference("shared -> address-group -> GRP -> static")
    assert group == live.GroupReference(live.ObjectRef("shared", "address-group", "GRP"))

    rule = live.parse_reference(
        "device-group -> DG-Prod -> post-rulebase -> security -> rules -> Allow web to app -> destination"
    )
    assert rule == live.RuleReference(live.RuleRef("DG-Prod", "post-rulebase", "security", "Allow web to app"), ("destination",))

    nat = live.parse_reference(
        "device-group -> DG-Edge -> pre-rulebase -> nat -> rules -> DNAT -> destination-translation -> translated-address"
    )
    assert nat.path == ("destination-translation", "translated-address")

    shared_rule = live.parse_reference("shared -> pre-rulebase -> decryption -> rules -> Decrypt -> source")
    assert shared_rule.rule == live.RuleRef("shared", "pre-rulebase", "decryption", "Decrypt")

    assert live.parse_reference("template -> TPL -> config -> something") is None


def test_single_members_are_parsed_as_lists():
    xml = (XML_DIR / "show_GRP_LEGACY_ALL.xml").read_text()
    entry = xmltodict.parse(xml, force_list=live.FORCE_LIST)["response"]["result"]["entry"][0]
    assert entry["static"]["member"] == ["GRP_LEGACY_DB"]


def test_members_with_audit_attributes_are_read(api):
    entry = api.show(live.object_xpath(live.ObjectRef("shared", "address-group", "GRP_APP_SERVERS")))
    assert live.members_at(entry, ("static",)) == ["H_192.0.2.10", "H_192.0.2.13"]


def test_message_lines():
    assert live.message_lines({"msg": "Object doesn't exist"}) == ["Object doesn't exist"]
    assert live.message_lines({"msg": {"line": [" a ", {"#text": "b"}]}}) == ["a", "b"]


def test_xpaths():
    assert live.object_xpath(live.ObjectRef("shared", "address", "H_192.0.2.10")) == (
        "/config/shared/address/entry[@name='H_192.0.2.10']"
    )
    assert live.rule_xpath(live.RuleRef("DG-Prod", "post-rulebase", "security", "it's")) == (
        "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DG-Prod']"
        "/post-rulebase/security/rules/entry[@name=\"it's\"]"
    )


def test_run_builds_plan_and_reverts(api, panorama):
    plan, not_found = live.run(api, IPS, "H_{ip}", None)

    assert plan.commands() == EXPECTED_COMMANDS
    assert plan.manual_review == []
    assert not_found == ["203.0.113.99"]
    assert panorama.op_calls()[-2:] == ["<revert><config></config></revert>", "<check><pending-changes></pending-changes></check>"]
    assert panorama.op_calls().count("<revert><config></config></revert>") == 1


def test_run_skips_device_groups(api, panorama):
    live.run(api, IPS, "H_{ip}", re.compile("VPN"))
    deletes = [call["xpath"] for call in panorama.calls_for("delete")]
    assert any("DG-Prod" in xpath for xpath in deletes)
    assert not any("DG-VPN-Remote" in xpath for xpath in deletes)


def test_run_refuses_to_start_with_pending_changes(api, panorama):
    panorama.overrides[(None, "<check><pending-changes></pending-changes></check>")] = (
        '<response status="success"><result>yes</result></response>'
    )
    with pytest.raises(live.PanoramaApiError, match="uncommitted changes"):
        live.run(api, IPS, "H_{ip}", None)
    assert panorama.calls_for("delete") == []
    assert "<revert><config></config></revert>" not in panorama.op_calls()


def test_run_reverts_when_a_delete_fails(api, panorama):
    xpath = live.object_xpath(live.ObjectRef("shared", "address", "H_192.0.2.11"))
    panorama.overrides[("delete", xpath)] = (
        '<response status="error" code="13"><msg><line>Config is locked by another admin</line></msg></response>'
    )
    with pytest.raises(live.PanoramaApiError, match="locked"):
        live.run(api, IPS, "H_{ip}", None)
    assert "<revert><config></config></revert>" in panorama.op_calls()


def test_reference_to_missing_rule_goes_to_manual_review(api, panorama):
    xpath = live.rule_xpath(live.RuleRef("DG-Prod", "post-rulebase", "security", "Allow backup"))
    panorama.overrides[("show", xpath)] = '<response status="success" code="19"><result/></response>'
    plan, _ = live.run(api, IPS, "H_{ip}", None)
    assert len(plan.manual_review) == 1
    assert "Allow backup" in plan.manual_review[0]


def test_main_writes_commands_and_log(tmp_path, monkeypatch, panorama, capsys):
    ips_file = tmp_path / "ips.txt"
    ips_file.write_text("\n".join(IPS) + "\n")
    monkeypatch.setenv("PANOS_API_KEY", "example-key")

    exit_code = live.main(["--host", "panorama.example.com", "-i", str(ips_file), "-o", str(tmp_path / "out")])

    assert exit_code == 0
    assert panorama.headers == {"X-PAN-KEY": "example-key"}
    commands_file = next((tmp_path / "out").glob("*_commands.txt"))
    assert commands_file.read_text().splitlines() == EXPECTED_COMMANDS
    log_text = next((tmp_path / "out").glob("*_log.txt")).read_text()
    assert "is referenced from" in log_text
    assert "IPs without an address object: 203.0.113.99" in capsys.readouterr().out


def test_name_format_must_contain_placeholder(tmp_path):
    with pytest.raises(SystemExit):
        live.parse_args(["--host", "panorama.example.com", "-i", "ips.txt", "--name-format", "HOST"])
