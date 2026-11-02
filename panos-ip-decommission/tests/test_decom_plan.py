from decom_plan import DecomPlan, ObjectRef, RuleRef, members_at, quote, scope


def test_quote_only_when_needed():
    assert quote("H_192.0.2.10") == "H_192.0.2.10"
    assert quote("Allow web") == '"Allow web"'
    assert quote('say "hi"') == '"say \\"hi\\""'


def test_scope():
    assert scope("shared") == "shared"
    assert scope("DG-Prod") == "device-group DG-Prod"
    assert scope("DG Prod") == 'device-group "DG Prod"'


def test_members_at_handles_every_shape():
    entry = {
        "source": {"member": ["A", "B"]},
        "destination": {"member": "C"},
        "static": {"member": [{"@admin": "netops", "#text": "D"}, "E"]},
        "destination-translation": {"translated-address": "F"},
    }
    assert members_at(entry, ("source",)) == ["A", "B"]
    assert members_at(entry, ("destination",)) == ["C"]
    assert members_at(entry, ("static",)) == ["D", "E"]
    assert members_at(entry, ("destination-translation", "translated-address")) == ["F"]
    assert members_at(entry, ("source-translation", "static-ip", "translated-address")) == []


def test_commands_are_ordered_and_skip_edits_on_deleted_items():
    plan = DecomPlan()
    address = ObjectRef("shared", "address", "H_192.0.2.10")
    inner = ObjectRef("shared", "address-group", "GRP_INNER")
    outer = ObjectRef("shared", "address-group", "GRP_OUTER")
    kept_group = ObjectRef("DG-Prod", "address-group", "GRP_KEPT")
    kept_rule = RuleRef("DG-Prod", "post-rulebase", "security", "Allow web")
    deleted_rule = RuleRef("shared", "pre-rulebase", "security", "Old rule")

    plan.delete_object(address)
    plan.remove_group_member(inner, "H_192.0.2.10")
    plan.delete_object(inner)
    plan.delete_object(outer)
    plan.remove_group_member(kept_group, "GRP_OUTER")
    plan.remove_rule_member(kept_rule, ("destination",), "H_192.0.2.10")
    plan.remove_rule_member(deleted_rule, ("source",), "H_192.0.2.10")
    plan.delete_rule(deleted_rule)

    assert plan.commands() == [
        "delete shared pre-rulebase security rules \"Old rule\"",
        "delete device-group DG-Prod post-rulebase security rules \"Allow web\" destination H_192.0.2.10",
        "delete device-group DG-Prod address-group GRP_KEPT static GRP_OUTER",
        "delete shared address-group GRP_OUTER",
        "delete shared address-group GRP_INNER",
        "delete shared address H_192.0.2.10",
    ]


def test_duplicates_are_ignored():
    plan = DecomPlan()
    rule = RuleRef("DG-Prod", "post-rulebase", "security", "R")
    plan.delete_rule(rule)
    plan.delete_rule(rule)
    plan.remove_group_member(ObjectRef("shared", "address-group", "G"), "A")
    plan.remove_group_member(ObjectRef("shared", "address-group", "G"), "A")
    assert len(plan.commands()) == 2
