import json

import pytest

import export_config as export


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self.payload


class FakeRestSession:
    def __init__(self, failing_resource=None):
        self.headers = {}
        self.verify = True
        self.calls = []
        self.failing_resource = failing_resource

    def get(self, url, params, timeout):
        self.calls.append((url, params))
        resource = url.split("/restapi/v10.2/", 1)[1]
        if resource == self.failing_resource:
            return FakeResponse({"code": 7, "message": "Object not present"}, status_code=400)
        location = params.get("device-group", "shared")
        if resource == "Policies/NatPreRules":
            return FakeResponse({"@status": "success", "result": {"@total-count": "0", "@count": "0"}})
        entry = {"@name": f"{resource.split('/')[1]}-{location}", "@location": params["location"]}
        if location != "shared":
            entry["@device-group"] = location
        return FakeResponse({"@status": "success", "result": {"@total-count": "1", "entry": [entry]}})


@pytest.fixture
def session(monkeypatch):
    fake = FakeRestSession()
    monkeypatch.setattr(export.requests, "Session", lambda: fake)
    return fake


def test_export_reads_shared_and_device_groups(session):
    api = export.PanoramaRestApi("panorama.example.com", "example-key")
    data = export.export_config(api, ["DG-Prod", "DG-Edge"])

    assert set(data) == set(export.RESOURCES)
    assert [e["@name"] for e in data["addresses.json"]] == [
        "Addresses-shared", "Addresses-DG-Prod", "Addresses-DG-Edge",
    ]
    assert data["nat_pre_rules.json"] == []
    assert session.headers["X-PAN-KEY"] == "example-key"
    assert ("https://panorama.example.com/restapi/v10.2/Objects/Addresses",
            {"location": "device-group", "device-group": "DG-Prod"}) in session.calls


def test_api_errors_are_raised(monkeypatch):
    monkeypatch.setattr(export.requests, "Session", lambda: FakeRestSession("Objects/AddressGroups"))
    api = export.PanoramaRestApi("panorama.example.com", "example-key")
    with pytest.raises(export.PanoramaRestError, match="Objects/AddressGroups"):
        export.export_config(api, [])


def test_main_writes_one_file_per_resource(tmp_path, monkeypatch, session):
    monkeypatch.setenv("PANOS_API_KEY", "example-key")
    out = tmp_path / "export"

    exit_code = export.main(["--host", "panorama.example.com", "-g", "DG-Prod", "-o", str(out)])

    assert exit_code == 0
    assert sorted(p.name for p in out.iterdir()) == sorted(export.RESOURCES)
    rules = json.loads((out / "security_post_rules.json").read_text())
    assert rules[1]["@device-group"] == "DG-Prod"
