"""Rule behaviour Bridge Bank relies on from actualpy 0.23.0, which replaced
three local workarounds (upstream issues bvanelli/actualpy#211, #212, #213):

- Rules written with Actual's own field names (payee, account, imported_payee)
  load instead of failing validation.
- One rule actualpy cannot parse is skipped and logged; the rest still run.
- A rule that sets notes keeps the casing and accents it was written with.
"""
import json
import unittest
from unittest.mock import patch

from actual.database import Transactions

import app.sync as sync_mod

PAYEE = "6a0b3a8e-0000-4000-8000-000000000001"


class _RuleRow:
    def __init__(self, conditions, actions, rule_id="r"):
        self.id = rule_id
        self.conditions = json.dumps(conditions)
        self.actions = json.dumps(actions)
        self.conditions_op = "and"
        self.stage = None


def _load(rows):
    with patch("actual.queries.get_rules", return_value=rows):
        return sync_mod._load_ruleset_tolerant(None)


def _txn(**kw):
    base = dict(id="t", notes=None, amount=-100, date=20261124, acct="a",
                description=PAYEE, is_parent=0, is_child=0, sort_order=0, tombstone=0)
    base.update(kw)
    return Transactions(**base)


class ActualpyRulesTest(unittest.TestCase):
    def test_frontend_field_names_load(self):
        rows = [_RuleRow(
            [{"field": "payee", "op": "is", "value": PAYEE, "type": "id"},
             {"field": "imported_payee", "op": "contains", "value": "amazon",
              "type": "imported_payee"}],
            [{"field": "notes", "op": "set", "value": "x", "type": "string"}])]
        ruleset = _load(rows)
        self.assertEqual(len(ruleset.rules), 1)
        fields = [c.field for c in ruleset.rules[0].conditions]
        self.assertEqual(fields, ["description", "imported_description"])

    def test_unsupported_rule_is_skipped_and_logged(self):
        good = _RuleRow([{"field": "description", "op": "is", "value": PAYEE, "type": "id"}],
                        [{"field": "notes", "op": "set", "value": "ok", "type": "string"}], "good")
        bad = _RuleRow([{"field": "description", "op": "is", "value": PAYEE, "type": "id"}],
                       [{"field": "no_such_field", "op": "set", "value": "X", "type": "string"}], "bad")
        with self.assertLogs(sync_mod.log, level="INFO") as logs:
            ruleset = _load([good, bad])
        self.assertEqual(len(ruleset.rules), 1)
        text = "\n".join(logs.output)
        self.assertIn("Skipping rule the import engine cannot process", text)
        self.assertIn("'bad'", text)
        self.assertIn("Rules loaded: 1, skipped: 1", text)

    def test_set_notes_keeps_casing(self):
        ruleset = _load([_RuleRow(
            [{"field": "description", "op": "is", "value": PAYEE, "type": "id"}],
            [{"field": "notes", "op": "set", "value": "#Transferência", "type": "string"}])])
        txn = _txn()
        ruleset.rules[0].actions[0].run(txn)
        self.assertEqual(txn.notes, "#Transferência")


if __name__ == "__main__":
    unittest.main()
