# Network automation

Simple Python tools for day-to-day network operations.

The current collection incorporates:
1) Auditing switch configuration.
2) Preparing firewall changes.

| Project | What it does | Stack |
| --- | --- | --- |
| [junos-vlan-consistency](junos-vlan-consistency/) | Finds VLANs missing on some of the `ae` bundles that should carry the same trunk (for example, all the hosts of a hypervisor cluster) | Netmiko, Junos `display json` |
| [panos-ip-decommission](panos-ip-decommission/) | Finds every reference to the address objects of decommissioned hosts in Panorama and generates the `delete` commands in a safe order | PAN-OS XML API and REST API |

Each project is independent, with its own README, `requirements.txt`, made-up sample data and tests.

## Running the tests

```bash
cd <project>
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

The tests run offline against the sample data, so no network devices are needed.

## Conventions

- Credentials come from environment variables or an interactive prompt, not from files in the repository.
- Inventories and IP lists are local files ignored by git. Only `*.example.*` versions are committed.
- Sample data uses the documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.com`.
