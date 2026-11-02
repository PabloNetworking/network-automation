# PAN-OS IP decommission

Generates the Panorama CLI commands needed to remove the address objects of decommissioned hosts, together with every reference to them in address groups, security rules and NAT rules.

Removing an address object by hand means finding every group and rule that uses it and deciding, for each one, whether to remove only the object or the whole group or rule. Removing only the object is enough when other members remain. When the object is the last member, the group or rule has to go, and so does everything that references that group. These tools work this out and write the commands in an order Panorama accepts. Nothing is committed: the output is a commands file to review and apply.

## Two approaches

| | `decom_live.py` | `export_config.py` + `decom_offline.py` |
| --- | --- | --- |
| API | XML API | REST API (read-only) |
| How references are found | Panorama itself: the tool tries to delete each object in the candidate config, and Panorama refuses and lists what still uses it | Offline analysis of an exported config |
| Matches objects by | Name, using a naming convention (`H_{ip}` by default) | Value (`ip-netmask`), whatever the object is called |
| Coverage | Any reference Panorama reports (any rulebase) | Address groups, security rules and NAT rules (pre and post) |
| Access needed | Config write permission. The candidate config is reverted at the end | Read-only API access, once, for the export |
| Repeatable / testable | Needs a Panorama | Runs anywhere from the JSON files |

`decom_plan.py` holds the logic both tools share: the plan model and how it is rendered as CLI commands.

## How the dependencies are resolved

For each IP to decommission:

1. **IP → address objects.** Find the address objects for the IP, in `shared` and in every device group.
2. **Address groups.** For each static group that contains a removed object:
   - If other members remain, remove only that member.
   - If no members would remain, delete the group and treat it as removed too, so that groups nesting it and rules using it are handled the same way. This repeats until no more groups are affected.
3. **Security rules.** For each rule that uses a removed object or group:
   - If the source or destination would be left empty, delete the rule (replacing an empty field with `any` would widen the rule).
   - Otherwise, remove the member from the field.
4. **NAT rules.** The same applies to the original-packet source and destination. A NAT rule whose translated address (source or destination translation) is removed is deleted.
5. **Command order.** Commands are written in this order: delete rules, edit rules, edit groups, delete groups (outermost first), delete address objects. Every reference is removed before the object it points to.

The live tool tracks the members already scheduled for removal. That way, two IPs that are the only members of the same group or rule field correctly lead to deleting it.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (requests, xmltodict)
- A Panorama API key, read from `PANOS_API_KEY` (prompted for if not set). The Panorama address can be given with `--host` or `PANOS_HOST`.

## Offline workflow

```bash
export PANOS_HOST=panorama.example.com
export PANOS_API_KEY=...

# 1. Export shared objects and policies plus the device groups of interest
python export_config.py -g DG-Prod -g DG-Edge -o export/

# 2. Analyse the export (no connection to Panorama)
python decom_offline.py -e export/ -i ips.txt -o commands.txt
```

`ips.txt` has one IP or prefix per line, and `#` starts a comment (see `ips.example.txt`). The export directory contains `addresses.json`, `address_groups.json`, `security_pre_rules.json`, `security_post_rules.json`, `nat_pre_rules.json` and `nat_post_rules.json`. Raw REST API responses saved under those names are accepted as well.

### Example

`sample_data/export/` is a small made-up configuration:

```text
$ python decom_offline.py -e sample_data/export -i ips.example.txt
Address objects to delete: 4
Address groups to delete:  2
Address groups to edit:    2
Rules to delete:           3
Rules to edit:             3
IPs without an address object: 203.0.113.99
delete device-group DG-Prod post-rulebase security rules "Allow legacy DB"
delete device-group DG-Prod post-rulebase security rules "Allow backup"
delete device-group DG-Edge post-rulebase nat rules "Inbound DNAT db01"
delete shared pre-rulebase security rules "Allow DNS from servers" source H_192.0.2.10
delete device-group DG-Prod post-rulebase security rules "Allow mgmt to hosts" destination H_192.0.2.10
delete device-group DG-Edge post-rulebase nat rules "Outbound SNAT hosts" source H_192.0.2.10
delete shared address-group GRP_APP_SERVERS static H_192.0.2.10
delete shared address-group GRP_MONITORED static GRP_LEGACY_ALL
delete shared address-group GRP_LEGACY_ALL
delete shared address-group GRP_LEGACY_DB
delete shared address H_192.0.2.10
delete shared address H_192.0.2.11
delete shared address H_192.0.2.12
delete device-group DG-Prod address H_198.51.100.20
```

`GRP_LEGACY_DB` only contained two of the decommissioned hosts, so it is deleted. That empties `GRP_LEGACY_ALL`, which nests it, so that group is deleted too, along with the rule that used it as its only destination. `GRP_MONITORED` keeps its other member and only loses the reference.

## Live workflow

```bash
python decom_live.py --host panorama.example.com -i ips.txt -o output/
```

| Option | Description |
| --- | --- |
| `-i, --input FILE` | One IP address per line |
| `-o, --output-dir DIR` | Where `<timestamp>_commands.txt` and `<timestamp>_log.txt` are written (default `output/`) |
| `--name-format FORMAT` | Address object naming convention (default `H_{ip}`) |
| `--skip-dg REGEX` | Skip device groups whose name matches, for example ones that never define address objects |
| `--insecure` | Do not verify the Panorama TLS certificate |

Safeguards:

- The tool refuses to start if the candidate configuration has uncommitted changes. This guarantees that the final revert only discards its own test deletions.
- The revert runs even if the tool stops on an error, and the tool then checks that no pending changes are left.
- It never commits.
- References it cannot classify are listed under "References to review manually" instead of being guessed.

Use a dedicated API administrator, so that the test deletions are easy to tell apart in the config audit.

## Limitations

- Static address groups only. Dynamic groups match by tag and are not affected by removing an object.
- FQDN, range and wildcard objects are not matched by IP.
- The offline analysis resolves names in the rule's own device group first, then in `shared`. It does not follow intermediate parent device groups.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

HTTP is mocked: the live tool is tested against the made-up XML API responses in `sample_data/xml_api/`, and the export against JSON responses defined in the tests. No Panorama is needed.
