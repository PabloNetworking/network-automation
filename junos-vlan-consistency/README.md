# Junos VLAN consistency check

Finds VLAN drift between aggregated Ethernet (`ae`) bundles on Junos switches that are meant to carry the same VLANs.

In a data center fabric, every hypervisor in a cluster usually connects to the leaf switches through a LAG with an identical trunk. When a new VLAN is added to some of those bundles but not to the others, workloads fail only after they move to the host where the VLAN is missing (vMotion, HA failover). This check finds those gaps before that happens.

## How it works

1. For each device in the inventory, the script collects the VLAN and interface configuration with Netmiko:
   - `show configuration vlans | display json`
   - `show configuration interfaces | display json`
2. From the interface configuration it takes the VLAN members of unit 0 (`family ethernet-switching`) on every `aeN` interface. Members configured by VLAN ID are translated to the VLAN name, so both styles compare correctly.
3. For each *compare group* in the inventory, it computes:
   - all VLANs present on at least one bundle of the group
   - the VLANs that are not present on every bundle (`inconsistent_vlans`)
   - for each bundle, the VLANs it is missing
   - bundles that could not be evaluated (not found, no unit 0, not in switching mode)
4. It prints a summary and, optionally, writes a JSON report.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (Netmiko, PyYAML)

## Inventory

Copy `inventory.example.yaml` to `inventory.yaml`:

```yaml
devices:
  leaf01:
    host: 192.0.2.11
    compare_groups:
      esxi-cluster-a: [ae1, ae2, ae3, ae4]
      backup-hosts: [ae10, ae11, ae12]
  leaf02:
    host: 192.0.2.12
    compare_groups:
      esxi-cluster-a: [ae1, ae2, ae3, ae4]
```

`device_type` (default `juniper_junos`) and `port` (default `22`) can be set per device.

## Usage

Credentials are read from `JUNOS_USERNAME` and `JUNOS_PASSWORD`. If either is not set, the script prompts for it.

```bash
# Check every device in the inventory
python vlan_consistency.py -i inventory.yaml

# Check one device, keep the raw configuration and write a JSON report
python vlan_consistency.py -i inventory.yaml -d leaf01 --save-raw raw/ -r report.json

# Re-run the analysis on saved configuration, without connecting to anything
python vlan_consistency.py -i inventory.yaml --offline raw/
```

| Option | Description |
| --- | --- |
| `-i, --inventory FILE` | YAML inventory (required) |
| `-d, --device NAME` | Only check this device; can be repeated |
| `--save-raw DIR` | Save `<device>_vlans.json` and `<device>_interfaces.json` to `DIR` |
| `--offline DIR` | Read those files from `DIR` instead of connecting |
| `-r, --report FILE` | Write the full report as JSON |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All groups are consistent |
| `1` | At least one group is inconsistent |
| `2` | Inventory error or a device could not be read |

## Example

`sample_data/` contains made-up configuration for two leaf switches:

```text
$ python vlan_consistency.py -i inventory.example.yaml --offline sample_data/
leaf01
  esxi-cluster-a (ae1, ae2, ae3, ae4): 7 VLANs, INCONSISTENT
    ae1 missing: APP_TEST (130)
    ae2 missing: APP_TEST (130)
    ae3 missing: APP_TEST (130), BACKUP (200)
  backup-hosts (ae10, ae11, ae12): 3 VLANs, INCONSISTENT
    ae12 not evaluated: no unit 0 configured
leaf02
  esxi-cluster-a (ae1, ae2, ae3, ae4): 6 VLANs, consistent
```

`ae4` on leaf01 lists `APP_DB` by its VLAN ID (`120`), and it is still matched against the bundles that use the name.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests use the sample data and a mocked Netmiko connection, so no devices are needed.
