import contextlib, os, json, sys, time, logging, datetime, decimal, requests

from . import config, db, email_notify, licence

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

STATE_FILE = "/data/state.json"
EB_API     = "https://api.enablebanking.com"
TRANSFER_MATCH_WINDOW_DAYS = 3
ACTUAL_RETRY_DELAYS_SECONDS = (15, 60)

def _config_flag(name, default=True):
    raw = getattr(config, name, None)
    if raw in (None, ""):
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}

def _actual_kwargs():
    return {
        "base_url": config.ACTUAL_URL,
        "password": config.ACTUAL_PASSWORD,
        "encryption_password": config.ACTUAL_ENCRYPTION_PASSWORD or None,
        "file": config.ACTUAL_SYNC_ID,
        "data_dir": "/data/actual-cache",
    }

def _actual_http_target(request):
    if not request:
        return ""
    method = getattr(request, "method", "")
    url = getattr(request, "url", None)
    if not url:
        return str(request)
    scheme = getattr(url, "scheme", "")
    host = getattr(url, "host", "")
    port = getattr(url, "port", None)
    path = getattr(url, "path", "") or "/"
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    host_part = f"{host}:{port}" if port and not default_port else host
    return f"{method} {scheme}://{host_part}{path}".strip()

def _actual_http_target_from_exception(exc):
    current = exc
    seen = set()
    while current and id(current) not in seen:
        seen.add(id(current))
        target = _actual_http_target(getattr(current, "request", None))
        if target:
            return target
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
    return ""

def _attach_actual_diagnostics(actual, label):
    session = getattr(actual, "_requests_session", None)
    if not session or getattr(session, "_bridge_bank_diagnostics", False):
        return

    def on_request(request):
        request.extensions["bridge_bank_started_at"] = time.monotonic()
        log.info("%s: Actual HTTP request started: %s", label, _actual_http_target(request))

    def on_response(response):
        started = response.request.extensions.get("bridge_bank_started_at")
        elapsed = f" in {time.monotonic() - started:.1f}s" if started else ""
        log.info(
            "%s: Actual HTTP response: %s %s%s",
            label,
            response.status_code,
            _actual_http_target(response.request),
            elapsed,
        )

    session.event_hooks.setdefault("request", []).append(on_request)
    session.event_hooks.setdefault("response", []).append(on_response)
    session._bridge_bank_diagnostics = True

@contextlib.contextmanager
def _actual_phase(label, phase):
    started = time.monotonic()
    log.info("%s: Actual phase started: %s", label, phase)
    try:
        yield
    except Exception as e:
        target = _actual_http_target_from_exception(e)
        target_msg = f" Last HTTP request: {target}." if target else ""
        log.error(
            "%s: Actual phase failed: %s after %.1fs.%s Error: %s",
            label,
            phase,
            time.monotonic() - started,
            target_msg,
            e,
            exc_info=True,
        )
        raise
    else:
        log.info("%s: Actual phase completed: %s in %.1fs", label, phase, time.monotonic() - started)

@contextlib.contextmanager
def _actual_client(label):
    from actual import Actual
    _patch_idempotent_migrations()
    actual = Actual(**_actual_kwargs())
    _attach_actual_diagnostics(actual, label)
    try:
        with _actual_phase(label, "open/load Actual budget"):
            actual.__enter__()
    except BaseException:
        actual.__exit__(*sys.exc_info())
        raise
    try:
        yield actual
    except BaseException:
        actual.__exit__(*sys.exc_info())
        raise
    else:
        actual.__exit__(None, None, None)

def _is_transient_actual_error(exc):
    parts = []
    current = exc
    seen = set()
    while current and id(current) not in seen:
        seen.add(id(current))
        parts.append(f"{type(current).__name__} {current}")
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
    text = " ".join(parts).lower()
    return any(
        marker in text
        for marker in (
            "timeout",
            "timed out",
            "connection reset",
            "temporarily unavailable",
            "remote protocol error",
            # A hosted Actual instance (PikaPods etc.) answering 502/503/504
            # is briefly unreachable behind its proxy, not gone; retry.
            "bad gateway",
            "service unavailable",
            "gateway timeout",
        )
    )

def _run_actual_with_retries(label, operation):
    attempts = len(ACTUAL_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as e:
            if attempt >= len(ACTUAL_RETRY_DELAYS_SECONDS) or not _is_transient_actual_error(e):
                raise
            wait = ACTUAL_RETRY_DELAYS_SECONDS[attempt]
            log.warning(
                "%s: Actual Budget connection failed transiently (%s). Retrying in %ds (%d/%d).",
                label,
                e,
                wait,
                attempt + 2,
                attempts,
            )
            time.sleep(wait)

def _own_names():
    val = config.ACCOUNT_HOLDER_NAME or ""
    return {n.strip().lower() for n in val.split(",") if n.strip()}

def _make_headers():
    import jwt, uuid, glob
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    pem_content = db.get_setting("eb_pem_content")
    if pem_content:
        key_data = pem_content.encode()
    else:
        key_path = "/data/private.pem"
        if not os.path.exists(key_path):
            pem_files = glob.glob("/data/*.pem")
            if not pem_files:
                raise RuntimeError(
                    "No .pem file found. Go to the Bank setup page in Bridge Bank and upload your .pem file from Enable Banking."
                )
            key_path = pem_files[0]
        key_data = open(key_path, "rb").read()
    app_id = db.get_setting("eb_app_id") or config.EB_APPLICATION_ID
    key = load_pem_private_key(key_data, password=None)
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com", "aud": "api.enablebanking.com",
        "iat": now, "exp": now + 3600,
        "jti": str(uuid.uuid4()), "sub": app_id
    }
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": app_id})
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def _load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def _save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def _get_session(account):
    """Takes a bank_accounts row dict, returns (session_id, account_uid). Warns on expiry."""
    sid = account.get("session_id")
    uid = account.get("account_uid")
    exp = account.get("session_expiry")
    if not sid or not uid:
        raise RuntimeError(
            "No active bank session for %s. Open Bridge Bank and click 'Re-authorise bank' on the Bank page."
            % account.get("bank_name", "unknown")
        )
    if exp:
        expiry = datetime.datetime.fromisoformat(exp)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
        if days_left < 7:
            log.warning("Session for %s expires in %d days.", account.get("bank_name", "unknown"), days_left)
            email_notify.send_session_expiry_warning(days_left)
    return sid, uid

def _fetch_transactions(account_uid, date_from):
    headers = _make_headers()
    base_params = {"date_from": date_from.isoformat(), "date_to": datetime.date.today().isoformat()}
    params  = dict(base_params)
    txns    = []
    url     = f"{EB_API}/accounts/{account_uid}/transactions"
    page    = 0
    while url:
        if page > 0:
            time.sleep(1)
        for attempt in range(4):
            r = requests.get(url, headers=headers, params=params, timeout=30)
            if r.status_code == 429:
                wait = min(2 ** attempt * 5, 60)
                log.warning("Rate limited (429), retrying in %ds (attempt %d/4)", wait, attempt + 1)
                time.sleep(wait)
                continue
            break
        if not r.ok:
            log.error("Enable Banking error %s: %s", r.status_code, r.text)
            r.raise_for_status()
        data = r.json()
        txns.extend(data.get("transactions", []))
        ck  = data.get("continuation_key")
        url = f"{EB_API}/accounts/{account_uid}/transactions" if ck else None
        params = {**base_params, "continuation_key": ck} if ck else {}
        page += 1
    log.info("Fetched %d transactions from Enable Banking", len(txns))
    return txns

def _parse_date(t):
    raw = t.get("booking_date") or t.get("value_date") or t.get("transaction_date")
    if not raw: raise ValueError("No date")
    return datetime.date.fromisoformat(raw[:10])

def _parse_amount(t):
    amt   = decimal.Decimal(str((t.get("transaction_amount") or {}).get("amount", "0")))
    indic = t.get("credit_debit_indicator") or t.get("credit_debit_indic", "")
    return -abs(amt) if indic.upper() == "DBIT" else abs(amt)

def _parse_payee(t):
    own   = _own_names()
    indic = (t.get("credit_debit_indicator") or t.get("credit_debit_indic", "")).upper()
    if indic == "DBIT":
        name = (t.get("creditor") or {}).get("name") or t.get("creditor_name")
        if not name:
            ri = t.get("remittance_information")
            name = ri[0] if isinstance(ri, list) else ri
    else:
        name = (t.get("debtor") or {}).get("name") or t.get("debtor_name")
        if not name or (own and name.lower() in own):
            ri = t.get("remittance_information")
            name = ri[0] if isinstance(ri, list) else ri
    return name or "Unknown"

def _parse_notes(t):
    ref = t.get("remittance_information_unstructured")
    if ref: return ref
    ri = t.get("remittance_information")
    if ri and isinstance(ri, list): return " ".join(ri)
    return ""

def _get_entry_ref(t):
    return t.get("entry_reference") or t.get("transaction_id") or ""

def _record_reconciled_transaction(transaction, existing_ids: set[str], new_txn: list) -> str:
    txn_id = str(transaction.id)
    is_new_txn = txn_id not in existing_ids
    if is_new_txn or transaction.changed():
        if is_new_txn:
            existing_ids.add(txn_id)
            result = "added"
        else:
            result = "updated"
        new_txn.append(transaction)
        return result
    return "skipped"

def _patch_payee_name_rules(session):
    """Remap Actual's UI-level rule field names to the ones actualpy accepts.

    Actual Budget stores rule conditions/actions with fields like 'payee',
    'account', 'payee_name' and 'imported_payee'; actualpy only accepts the
    internal column names ('description', 'acct', 'imported_description').
    Without this patch a single rule using one of those fields makes the
    ruleset fail Pydantic validation and no rules apply on import."""
    import json
    from actual.queries import get_rules
    field_map = {
        "payee_name": "description",
        "imported_payee": "imported_description",
        "payee": "description",
        "account": "acct",
    }
    for rule in get_rules(session):
        for attr in ("conditions", "actions"):
            raw = getattr(rule, attr, None)
            if not raw:
                continue
            try:
                items = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            patched = False
            for item in items:
                old = item.get("field")
                if old in field_map:
                    item["field"] = field_map[old]
                    patched = True
            if patched:
                setattr(rule, attr, json.dumps(items))

def _load_ruleset_tolerant(session):
    """Build the ruleset one rule at a time, skipping rules actualpy cannot parse.

    actualpy's get_ruleset() validates every rule in one go, so a single rule
    using an unsupported field or operator would disable EVERY rule for the
    whole import (while manual 'Run Rules' in Actual still works, since that
    uses Actual's own engine). Skipped rules are logged with their contents."""
    from pydantic import TypeAdapter
    from actual.queries import get_rules
    from actual.rules import Rule, Condition, Action, RuleSet
    rules = []
    for rule in get_rules(session):
        if not rule.conditions or not rule.actions:
            continue
        try:
            conditions = TypeAdapter(list[Condition]).validate_json(rule.conditions)
            actions = TypeAdapter(list[Action]).validate_json(rule.actions)
            rules.append(Rule(conditions=conditions, operation=rule.conditions_op,
                              actions=actions, stage=rule.stage))
        except Exception as e:
            log.warning(
                "Skipping rule the import engine cannot process (it still "
                "works via 'Run Rules' in Actual). conditions=%s actions=%s | %s",
                rule.conditions, rule.actions, e)
    return RuleSet(rules=rules)

_action_run_patched = False
_migrations_patched = False

def _patch_idempotent_migrations():
    """Tolerate already-applied schema changes when actualpy replays migrations.

    A budget migrated by the Actual web client can carry a schema change whose
    migration id is not recorded in the budget's __migrations__ table, because
    an earlier Actual version applied that change under a different id. When
    actualpy loads the budget it re-runs the server's migration file, and
    SQLite raises e.g. 'duplicate column name: show_trend_lines'. The whole
    sync then aborts as 'Could not connect to Actual Budget'. This bites budgets
    on newer Actual servers (26.x added custom_reports.show_trend_lines) and is
    not fixed upstream (run_migrations is unchanged across actualpy 0.21-0.22.x).

    Replace Actual.run_migrations with a version that records and skips any
    migration whose only failure is that the change already exists, and still
    raises on any other error. Upstream: bvanelli/actualpy run_migrations."""
    global _migrations_patched
    if _migrations_patched:
        return
    import sqlite3
    from actual import Actual
    from actual.database import reflect_model
    from actual.migrations import js_migration_statements

    def _run_migrations(self, migration_files):
        data_dir = getattr(self, "data_dir", None) or self._data_dir
        with sqlite3.connect(data_dir / "db.sqlite") as conn:
            for file in migration_files:
                if not file.startswith("migrations"):
                    continue  # in case db.sqlite is passed as one of the files
                file_id = file.split("_")[0].split("/")[1]
                if conn.execute(
                    "SELECT id FROM __migrations__ WHERE id = ?;", (file_id,)
                ).fetchall():
                    continue  # already applied
                sql_statements = self.data_file(file).decode()
                if file.endswith(".js"):
                    sql_statements = "\n".join(js_migration_statements(sql_statements))
                try:
                    conn.executescript(sql_statements)
                except sqlite3.OperationalError as e:
                    text = str(e).lower()
                    if "duplicate column name" in text or "already exists" in text:
                        # the schema change is already present; drop the failed
                        # migration's open transaction and just record it as done
                        log.warning(
                            "Actual migration %s already applied to the budget schema "
                            "(%s); recording it as done and continuing.", file_id, e
                        )
                        conn.rollback()
                    else:
                        raise
                conn.execute("INSERT INTO __migrations__ (id) VALUES (?);", (file_id,))
            conn.commit()
        conn.close()
        # refresh the reflected model, as upstream run_migrations does
        metadata = reflect_model(self.engine)
        if hasattr(self, "_database_metadata"):
            self._database_metadata = metadata
        else:
            self._meta = metadata

    Actual.run_migrations = _run_migrations
    _migrations_patched = True

def _patch_action_note_casing():
    """Stop actualpy from lowercasing note values written by rules.

    actualpy's Action.run passes SET values through get_normalized_string()
    (lowercase + NFD), which is meant for condition comparisons only. The
    result: a rule that sets notes to '#Transferência' writes
    '#transferência', on the main transaction and on every split. The real
    Actual rule engine keeps the original casing. Patch SET actions on
    string fields to write the raw value; everything else falls through to
    the original implementation. Upstream: bvanelli/actualpy."""
    global _action_run_patched
    if _action_run_patched:
        return
    from actual import rules as _rules
    _orig_run = _rules.Action.run

    def _patched_run(self, transaction):
        if (self.op == _rules.ActionType.SET
                and self.type == _rules.ValueType.STRING
                and isinstance(self.value, str)):
            split_index = self.get_split_index()
            if split_index and len(transaction.splits) >= split_index:
                transaction = transaction.splits[split_index - 1]
            attr = _rules.get_attribute_by_table_name(
                str(_rules.Transactions.__tablename__), str(self.field))
            setattr(transaction, attr, self.value)
            return
        return _orig_run(self, transaction)

    _rules.Action.run = _patched_run
    _action_run_patched = True

def _run_rules_on_transfer_counterparts(actual, new_txn, ruleset):
    """Run rules on the mirrored side of transfers created by this import.

    Only imported transactions go through the rule pass, so rules that target
    the counterpart row (e.g. account is 'Savings' -> set notes) never fire
    automatically; the user has to select the transaction and click
    'Run Rules' by hand. Collect the counterparts of any new transfers and
    give them the same rule pass."""
    from actual.database import Transactions
    new_ids = {getattr(t, "id", None) for t in new_txn}
    counterparts = []
    for txn in new_txn:
        transfer_id = _txn_transfer_id(txn)
        if not transfer_id or transfer_id in new_ids:
            continue
        counterpart = actual.session.get(Transactions, transfer_id)
        if counterpart is None:
            continue
        # A counterpart created mid-rule-pass copied the origin's notes as
        # they were at that moment (usually the raw bank narration). The
        # Actual server mirrors the final notes onto the counterpart after
        # sync anyway; do it now so rule conditions on the counterpart see
        # the note the user's rules just wrote (e.g. notes is 'x').
        if txn.notes and counterpart.notes != txn.notes:
            counterpart.notes = txn.notes
        counterparts.append(counterpart)
    if not counterparts:
        return
    log.info("Applying rules to %d transfer counterpart(s)", len(counterparts))
    ruleset.run(counterparts)
    _fix_rule_note_casing(actual.session, counterparts)

def _fix_rule_note_casing(session, transactions):
    """Restore original case for notes set by rules.

    actualpy lowercases all string values via get_normalized_string(), including
    SET action values for notes. This compares each transaction's notes against
    the lowercased rule value and restores the original case if they match.

    Both sides are normalised to NFC before comparison so the check works
    regardless of whether actualpy applies NFD normalisation internally."""
    import json, unicodedata
    from actual.queries import get_rules
    note_rules = []
    for rule in get_rules(session):
        try:
            actions = json.loads(rule.actions)
        except (json.JSONDecodeError, TypeError):
            continue
        for action in actions:
            if action.get("field") == "notes" and action.get("op") == "set" and action.get("value"):
                original = action["value"]
                lowered = unicodedata.normalize("NFC", original).lower()
                note_rules.append((lowered, original))
    if not note_rules:
        return
    for txn in transactions:
        if not txn.notes:
            continue
        txn_notes_nfc = unicodedata.normalize("NFC", txn.notes).lower()
        for lowered, original in note_rules:
            if txn_notes_nfc == lowered:
                txn.notes = original
                break

def _txn_account_id(txn):
    return getattr(txn, "acct", None) or getattr(txn, "account", None)

def _txn_transfer_id(txn):
    return getattr(txn, "transferred_id", None) or getattr(txn, "transfer_id", None)

def _txn_date(txn):
    if hasattr(txn, "get_date"):
        return txn.get_date()
    raw = getattr(txn, "date", None)
    if isinstance(raw, datetime.date):
        return raw
    if isinstance(raw, str):
        return datetime.date.fromisoformat(raw[:10])
    return None

def _is_transfer_candidate(txn, account_ids, allow_existing_transfer=False):
    account_id = _txn_account_id(txn)
    amount = getattr(txn, "amount", None)
    if account_id not in account_ids:
        return False
    if not amount:
        return False
    if _txn_transfer_id(txn) and not allow_existing_transfer:
        return False
    if not getattr(txn, "financial_id", None):
        return False
    if not bool(getattr(txn, "cleared", 0)):
        return False
    if getattr(txn, "is_parent", 0) or getattr(txn, "is_child", 0):
        return False
    if getattr(txn, "starting_balance_flag", 0):
        return False
    if getattr(txn, "reconciled", 0):
        return False
    return _txn_date(txn) is not None

def _transfer_candidates_for(txn, candidates):
    txn_date = _txn_date(txn)
    txn_account = _txn_account_id(txn)
    txn_amount = getattr(txn, "amount", 0)
    matches = []
    for other in candidates:
        if other.id == txn.id:
            continue
        if _txn_account_id(other) == txn_account:
            continue
        if getattr(other, "amount", 0) != -txn_amount:
            continue
        other_date = _txn_date(other)
        if other_date is None:
            continue
        distance = abs((other_date - txn_date).days)
        if distance <= TRANSFER_MATCH_WINDOW_DAYS:
            matches.append((distance, other))
    matches.sort(key=lambda item: (item[0], _txn_date(item[1]), str(item[1].id)))
    return [other for _, other in matches]

def _find_transfer_pairs(transactions, account_ids, allow_existing_transfers=False):
    candidates = [
        t for t in transactions
        if _is_transfer_candidate(t, account_ids, allow_existing_transfers)
    ]
    outgoing = [t for t in candidates if getattr(t, "amount", 0) < 0]
    incoming = [t for t in candidates if getattr(t, "amount", 0) > 0]

    incoming_matches = {t.id: _transfer_candidates_for(t, outgoing) for t in incoming}
    pairs = []
    matched = set()
    for source in sorted(outgoing, key=lambda t: (_txn_date(t), abs(getattr(t, "amount", 0)), str(t.id))):
        if source.id in matched:
            continue
        matches = _transfer_candidates_for(source, incoming)
        if len(matches) != 1:
            continue
        dest = matches[0]
        if dest.id in matched:
            continue
        if len(incoming_matches.get(dest.id, [])) != 1:
            continue
        pairs.append((source, dest))
        matched.add(source.id)
        matched.add(dest.id)
    return pairs

def _can_relink_imported_pair(source, dest, txn_by_id, account_ids):
    for txn, other in ((source, dest), (dest, source)):
        transfer_id = _txn_transfer_id(txn)
        if not transfer_id or transfer_id == other.id:
            continue
        existing = txn_by_id.get(transfer_id)
        if not existing:
            return False
        if getattr(existing, "financial_id", None):
            return False
        if _txn_account_id(existing) not in account_ids:
            return False
        if getattr(existing, "amount", 0) != -getattr(txn, "amount", 0):
            return False
    return True

def _remove_generated_counterparts(session, source, dest, txn_by_id):
    removed = 0
    for txn, other in ((source, dest), (dest, source)):
        transfer_id = _txn_transfer_id(txn)
        if not transfer_id or transfer_id == other.id:
            continue
        existing = txn_by_id.get(transfer_id)
        if existing and not getattr(existing, "financial_id", None):
            existing.transferred_id = None
            existing.tombstone = 1
            session.add(existing)
            removed += 1
    return removed

def _link_transfer_pair(session, source, dest, account_by_id, transfer_payee_by_account_id):
    source_account_id = _txn_account_id(source)
    dest_account_id = _txn_account_id(dest)
    dest_payee = transfer_payee_by_account_id.get(dest_account_id)
    source_payee = transfer_payee_by_account_id.get(source_account_id)
    if not dest_payee or not source_payee:
        return False

    changed = (
        source.payee_id != dest_payee.id
        or dest.payee_id != source_payee.id
        or source.transferred_id != dest.id
        or dest.transferred_id != source.id
    )
    source.payee_id = dest_payee.id
    dest.payee_id = source_payee.id
    source.transferred_id = dest.id
    dest.transferred_id = source.id

    source_account = account_by_id.get(source_account_id)
    dest_account = account_by_id.get(dest_account_id)
    source_offbudget = bool(getattr(source_account, "offbudget", 0))
    dest_offbudget = bool(getattr(dest_account, "offbudget", 0))
    if source_offbudget == dest_offbudget:
        changed = changed or source.category_id is not None or dest.category_id is not None
        source.category_id = None
        dest.category_id = None

    if changed:
        session.add(source)
        session.add(dest)
    return changed

def _get_transfer_match_start(accounts):
    dates = []
    for account in accounts:
        if account.get("sync_mode") == "balance":
            continue
        raw = account.get("start_sync_date") or config.START_SYNC_DATE
        if raw:
            try:
                dates.append(datetime.date.fromisoformat(raw[:10]))
            except ValueError:
                pass
    if dates:
        return min(dates)
    return datetime.date.today() - datetime.timedelta(days=90)

def _auto_link_internal_transfers(actual, accounts):
    if not _config_flag("AUTO_LINK_TRANSFERS", True):
        return 0

    transfer_accounts = [
        a for a in accounts
        if a.get("sync_mode") != "balance" and a.get("actual_account")
    ]
    actual_account_names = sorted({a["actual_account"] for a in transfer_accounts})
    if len(actual_account_names) < 2:
        return 0

    from actual.queries import get_account, get_payees, get_transactions

    account_by_id = {}
    transactions = []
    start_date = _get_transfer_match_start(transfer_accounts)
    end_date = datetime.date.today() + datetime.timedelta(days=1)

    for name in actual_account_names:
        account_obj = get_account(actual.session, name)
        if not account_obj:
            continue
        account_by_id[account_obj.id] = account_obj
        transactions.extend(
            get_transactions(
                actual.session,
                start_date=start_date,
                end_date=end_date,
                account=account_obj,
            )
        )

    if len(account_by_id) < 2:
        return 0

    account_ids = set(account_by_id)
    transfer_payee_by_account_id = {
        p.transfer_acct: p
        for p in get_payees(actual.session)
        if getattr(p, "transfer_acct", None) in account_ids
    }
    if len(transfer_payee_by_account_id) < len(account_ids):
        log.warning("Could not auto-link transfers: missing Actual transfer payees for one or more accounts")
        return 0

    linked = removed = 0
    txn_by_id = {t.id: t for t in transactions}
    for source, dest in _find_transfer_pairs(transactions, account_ids, allow_existing_transfers=True):
        if not _can_relink_imported_pair(source, dest, txn_by_id, account_ids):
            continue
        removed += _remove_generated_counterparts(actual.session, source, dest, txn_by_id)
        if _link_transfer_pair(actual.session, source, dest, account_by_id, transfer_payee_by_account_id):
            linked += 1

    if linked:
        log.info(
            "Auto-linked %d internal transfer%s%s",
            linked,
            "" if linked == 1 else "s",
            f" and removed {removed} generated counterpart{'s' if removed != 1 else ''}" if removed else "",
        )
    return linked

def _sync_balance_account(account):
    """Sync a balance-only provider account. Returns (success, tx_count, label)."""
    from .providers import get_provider
    from . import crypto

    provider_name = account["provider"]
    actual_name = account.get("actual_account", config.ACTUAL_ACCOUNT)
    bank_label = f"{account.get('bank_name', provider_name)} \u2192 {actual_name}"

    try:
        provider = get_provider(provider_name)
    except ValueError as e:
        return False, 0, str(e)

    try:
        credentials = crypto.decrypt_credentials(account.get("provider_credentials", ""))
    except Exception as e:
        msg = f"{bank_label}: Could not decrypt credentials: {e}"
        log.error(msg)
        return False, 0, msg

    try:
        target_balance = provider.get_balance(credentials)
    except Exception as e:
        msg = f"{bank_label}: Could not fetch balance from {provider.display_name}: {e}"
        log.error(msg)
        return False, 0, msg

    def write_balance_to_actual():
        from actual.queries import get_or_create_account, get_transactions, create_transaction

        with _actual_client(bank_label) as actual:
            with _actual_phase(bank_label, "load Actual balance account"):
                account_obj = get_or_create_account(actual.session, actual_name)
                existing = list(get_transactions(actual.session, account=account_obj))

            with _actual_phase(bank_label, "replace balance transaction"):
                # actualpy amounts are in whole currency units (e.g. 69.15 = €69.15)
                target_amount = float(target_balance)
                balance_note = f"{provider.display_name} portfolio value"

                # Delete ALL existing transactions in this account, then create
                # a single transaction with the exact portfolio value. This ensures
                # the account balance matches the provider exactly.
                for txn in existing:
                    txn.delete()

                tx_count = 0
                if target_amount != 0:
                    create_transaction(
                        actual.session,
                        datetime.date.today(),
                        account_obj,
                        f"{provider.display_name}",
                        balance_note,
                        amount=target_amount,
                        cleared=True,
                    )
                    tx_count = 1

            with _actual_phase(bank_label, "commit Actual balance changes"):
                actual.commit()
            log.info("Balance sync %s: set to %s EUR", bank_label, target_amount)
            return tx_count

    try:
        tx_count = _run_actual_with_retries(bank_label, write_balance_to_actual)
    except Exception as e:
        msg = f"{bank_label}: Could not connect to Actual Budget: {e}"
        log.error(msg)
        return False, 0, msg

    return True, tx_count, "OK"


def _sync_account(account, state):
    """Sync a single bank account. Returns (success, tx_count, message)."""
    if account.get("sync_mode") == "balance":
        return _sync_balance_account(account)

    account_id = str(account["id"])
    actual_name = account.get("actual_account", config.ACTUAL_ACCOUNT)
    bank_label = f"{account.get('bank_name', 'Unknown')} ({account.get('bank_country', '')}) \u2192 {actual_name}"
    actual_account_name = account.get("actual_account", config.ACTUAL_ACCOUNT)

    try:
        _, account_uid = _get_session(account)
    except RuntimeError as e:
        msg = str(e)
        log.error(msg)
        return False, 0, msg

    # Per-account state
    if "accounts" not in state:
        state["accounts"] = {}
    acct_state = state["accounts"].get(account_id, {})

    last = acct_state.get("last_sync_date") or account.get("start_sync_date") or config.START_SYNC_DATE or None
    if last:
        date_from = datetime.date.fromisoformat(last)
    else:
        date_from = datetime.date.today() - datetime.timedelta(days=30)
        log.warning("No start date configured for %s — defaulting to last 30 days. To change this, set a start date in the Bank page.", bank_label)

    pending_map = acct_state.get("pending_map", {})
    if pending_map:
        earliest = min(datetime.date.fromisoformat(k.split("|")[0]) for k in pending_map)
        if earliest < date_from:
            date_from = earliest

    try:
        raw = _fetch_transactions(account_uid, date_from)
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            msg = f"{bank_label}: Your bank is rate-limiting requests. Bridge Bank will retry on the next scheduled sync."
        elif e.response is not None and e.response.status_code in (401, 403):
            msg = f"{bank_label}: Your bank session has expired. Open Bridge Bank and click 'Re-authorise bank' on the Bank page."
        else:
            msg = f"{bank_label}: Could not fetch transactions from your bank. Open Bridge Bank and click 'Re-authorise bank' on the Bank page."
        log.error(msg)
        return False, 0, msg

    if not raw:
        log.info("No new transactions for %s", bank_label)
        acct_state["last_sync_date"] = datetime.date.today().isoformat()
        state["accounts"][account_id] = acct_state
        return True, 0, "OK"

    pending_map_start = dict(pending_map)
    imported_refs_start = set(acct_state.get("imported_refs", []))

    def write_transactions_to_actual():
        pending_map = dict(pending_map_start)
        imported_refs = set(imported_refs_start)
        added = updated = skipped = 0
        from actual.queries import get_or_create_account, reconcile_transaction, get_transactions, create_transaction

        with _actual_client(bank_label) as actual:
            with _actual_phase(bank_label, "load Actual account and existing transactions"):
                account_obj    = get_or_create_account(actual.session, actual_account_name)
                existing       = list(get_transactions(actual.session, account=account_obj))
                existing_ids   = {str(t.id) for t in existing}
                already_matched = existing[:]
                new_txn        = []

            skip_pending = bool(account.get("skip_pending"))

            with _actual_phase(bank_label, "reconcile fetched transactions"):
                for txn in raw:
                    try:
                        status = txn.get("status", "BOOK")
                        if status == "PDNG" and skip_pending:
                            skipped += 1
                            continue
                        date   = _parse_date(txn)
                        amount = _parse_amount(txn)
                        payee  = _parse_payee(txn)
                        notes  = _parse_notes(txn)
                        if notes and notes.strip().lower() == payee.strip().lower():
                            notes = ""
                        ref    = _get_entry_ref(txn)
                        key    = f"{date}|{amount}"

                        if status == "PDNG":
                            if key not in pending_map:
                                try:
                                    t = reconcile_transaction(
                                        actual.session, date, account_obj, payee, notes,
                                        None, amount, imported_id=ref or None, cleared=False,
                                        imported_payee=payee, already_matched=already_matched
                                    )
                                except Exception:
                                    t = create_transaction(
                                        actual.session, date, account_obj, payee, notes,
                                        amount=amount, imported_id=ref or None,
                                        cleared=False, imported_payee=payee
                                    )
                                already_matched.append(t)
                                result = _record_reconciled_transaction(t, existing_ids, new_txn)
                                if result != "skipped":
                                    pending_map[key] = str(t.id)
                                    if result == "added":
                                        added += 1
                                    else:
                                        updated += 1
                                else:
                                    skipped += 1
                            else:
                                skipped += 1
                        else:
                            if ref and ref in imported_refs:
                                skipped += 1
                                continue
                            if key in pending_map:
                                txn_id       = pending_map[key]
                                existing_txn = next((t for t in existing if str(t.id) == txn_id), None)
                                if existing_txn:
                                    existing_txn.cleared = True
                                    if ref:
                                        existing_txn.financial_id = ref
                                    del pending_map[key]
                                    if ref: imported_refs.add(ref)
                                    updated += 1
                                else:
                                    del pending_map[key]
                                    if ref: imported_refs.add(ref)
                                    skipped += 1
                            else:
                                try:
                                    t = reconcile_transaction(
                                        actual.session, date, account_obj, payee, notes,
                                        None, amount, imported_id=ref or None, cleared=True,
                                        imported_payee=payee, already_matched=already_matched
                                    )
                                except Exception:
                                    t = create_transaction(
                                        actual.session, date, account_obj, payee, notes,
                                        amount=amount, imported_id=ref or None,
                                        cleared=True, imported_payee=payee
                                    )
                                already_matched.append(t)
                                if ref:
                                    imported_refs.add(ref)
                                result = _record_reconciled_transaction(t, existing_ids, new_txn)
                                if result == "added":
                                    added += 1
                                elif result == "updated":
                                    updated += 1
                                else:
                                    skipped += 1
                    except Exception as e:
                        log.warning("Skipping transaction: %s | %s", e, txn)

            try:
                with _actual_phase(bank_label, "apply Actual rules"):
                    _patch_payee_name_rules(actual.session)
                    _patch_action_note_casing()
                    ruleset = _load_ruleset_tolerant(actual.session)
                    ruleset.run(new_txn)
                    _fix_rule_note_casing(actual.session, new_txn)
                    _run_rules_on_transfer_counterparts(actual, new_txn, ruleset)
            except Exception as e:
                log.error("Error applying rules: %s", e)

            with _actual_phase(bank_label, "commit Actual transaction changes"):
                actual.commit()
            log.info("Done %s: %d added, %d confirmed, %d skipped", bank_label, added, updated, skipped)
            return pending_map, imported_refs, added, updated

    try:
        pending_map, imported_refs, added, updated = _run_actual_with_retries(
            bank_label,
            write_transactions_to_actual,
        )
    except Exception as e:
        msg = f"{bank_label}: Could not connect to Actual Budget at {config.ACTUAL_URL}. Error: {e}"
        log.error(msg)
        return False, 0, msg

    acct_state["last_sync_date"]  = datetime.date.today().isoformat()
    acct_state["pending_map"]     = pending_map
    acct_state["imported_refs"]   = list(imported_refs)
    state["accounts"][account_id] = acct_state
    return True, added + updated, "OK"

def bank_label(account):
    """Human label for an account, used in sync-log messages and the UI.

    Kept in one place so log messages and per-account status matching cannot
    drift apart.
    """
    actual_name = account.get("actual_account", config.ACTUAL_ACCOUNT)
    if account.get("sync_mode") == "balance":
        return f"{account.get('bank_name', account.get('provider', 'Unknown'))} → {actual_name}"
    return f"{account.get('bank_name', 'Unknown')} ({account.get('bank_country', '')}) → {actual_name}"

def run():
    log.info("Starting sync...")

    # License check
    result = licence.validate()
    if not result["valid"]:
        msg = f"License invalid: {result['error']}"
        log.error(msg)
        # Send specific trial expired email if applicable
        try:
            act_info = licence.get_activation_info()
            if act_info.get("is_trial"):
                email_notify.send_trial_expired()
            else:
                email_notify.send_failure(msg)
        except Exception:
            email_notify.send_failure(msg)
        db.log_sync("failure", message=msg)
        return False, 0, msg

    # Trial expiry warning
    try:
        act_info = licence.get_activation_info()
        if act_info.get("is_trial") and act_info.get("expires_at"):
            expires = datetime.date.fromisoformat(act_info["expires_at"][:10])
            days_left = (expires - datetime.date.today()).days
            if 0 < days_left <= 7:
                log.warning("Trial expires in %d days", days_left)
                email_notify.send_trial_expiry_warning(days_left)
    except Exception:
        pass

    all_accounts = db.get_all_bank_accounts()
    if not all_accounts:
        # Still report the (empty) seat list so the license server releases
        # this machine's seats; otherwise removing every bank leaves stale
        # seats registered until a new connection attempt.
        try:
            licence.sync_bank_seats([])
        except Exception:
            pass
        msg = "No bank connection found. Please connect your bank."
        log.error(msg)
        db.log_sync("failure", message=msg)
        return False, 0, msg

    seat_result = licence.sync_bank_seats(all_accounts)
    if not seat_result.get("ok"):
        if seat_result.get("network"):
            log.warning("Bank seat verification skipped: %s", seat_result.get("error"))
        else:
            msg = seat_result.get("error") or "Bank account limit reached for this licence."
            log.error(msg)
            db.set_setting("license_bank_limit_error", msg)
            db.log_sync("failure", message=msg)
            email_notify.send_failure(msg)
            return False, 0, msg
    else:
        db.set_setting("license_bank_limit_error", "")

    state = _load_state()
    total_added = 0
    errors = []
    successes = []

    for i, account in enumerate(all_accounts):
        if i > 0:
            time.sleep(2)
        label = bank_label(account)
        try:
            success, added, msg = _sync_account(account, state)
            if success:
                total_added += added
                successes.append(f"{label}: {added} transactions")
                db.log_sync("success", tx_count=added, message=label)
            else:
                errors.append(msg)
                db.log_sync("failure", tx_count=0, message=msg)
        except Exception as e:
            log.error("Unexpected error syncing %s: %s", label, e)
            errors.append(f"{label}: {e}")
            db.log_sync("failure", tx_count=0, message=f"{label}: {e}")

    linked_transfers = 0
    # Run transfer-linking whenever at least one account synced successfully
    # (i.e. Actual is reachable). A single failing or timed-out account must
    # never disable internal-transfer linking for all the healthy accounts.
    if successes:
        def link_internal_transfers():
            with _actual_client("Internal transfers") as actual:
                with _actual_phase("Internal transfers", "scan and link transfers"):
                    linked = _auto_link_internal_transfers(actual, all_accounts)
                if linked:
                    with _actual_phase("Internal transfers", "commit transfer links"):
                        actual.commit()
                return linked

        try:
            linked_transfers = _run_actual_with_retries(
                "Internal transfers",
                link_internal_transfers,
            )
            if linked_transfers:
                successes.append(
                    f"Internal transfers: {linked_transfers} linked"
                )
        except Exception as e:
            log.error("Error auto-linking internal transfers: %s", e)

    _save_state(state)

    if errors and not successes:
        email_notify.send_failure("\n".join(f"  ✗ {e}" for e in errors))
    elif errors:
        email_notify.send_partial(successes, errors)
    else:
        email_notify.send_success(total_added, successes)

    # Check for updates silently
    try:
        _check_for_update()
    except Exception:
        pass

    return len(errors) == 0, total_added, "OK" if not errors else msg


def _check_for_update():
    """Check Docker Hub for a newer image and store result in DB."""
    import json, platform, subprocess, os, requests as _req
    repo = "daalves/bridge-bank"
    tag = "latest"
    if not os.path.exists("/var/run/docker.sock"):
        # No docker socket: can't compare image digests, but a version-tag
        # comparison via Docker Hub still detects new releases.
        from . import version_check
        available, _ = version_check.update_available_by_version(
            os.environ.get("APP_VERSION", "dev"), repo)
        db.set_setting("update_available", "1" if available else "0")
        if available:
            log.info("Update available for %s (version tag check)", repo)
        return
    token_resp = _req.get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=5)
    token = token_resp.json().get("token", "")

    accept = (
        "application/vnd.oci.image.index.v1+json, "
        "application/vnd.docker.distribution.manifest.list.v2+json, "
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    manifest_resp = _req.get(
        f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
        },
        timeout=5
    )
    manifest_resp.raise_for_status()
    remote_digests = {manifest_resp.headers.get("Docker-Content-Digest", "")}
    content_type = manifest_resp.headers.get("Content-Type", "")
    if "manifest.list" in content_type or "image.index" in content_type:
        machine = platform.machine().lower()
        arch = "amd64" if machine in ("x86_64", "amd64") else "arm64" if machine in ("aarch64", "arm64") else "arm" if machine.startswith("armv") else machine
        variant = "v7" if machine.startswith("armv7") else "v6" if machine.startswith("armv6") else ""
        for manifest in manifest_resp.json().get("manifests", []):
            platform_info = manifest.get("platform") or {}
            if platform_info.get("architecture") != arch:
                continue
            if variant and platform_info.get("variant") != variant:
                continue
            remote_digests.add(manifest.get("digest", ""))
    remote_digests = {digest for digest in remote_digests if digest}

    local_result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .RepoDigests}}", f"{repo}:{tag}"],
        capture_output=True, text=True, timeout=10
    )
    local_digests = set()
    if local_result.returncode == 0:
        for digest in json.loads(local_result.stdout.strip() or "[]"):
            if "@" in digest:
                local_digests.add(digest.split("@")[-1])

    update_available = bool(remote_digests and local_digests and remote_digests.isdisjoint(local_digests))
    db.set_setting("update_available", "1" if update_available else "0")
    if update_available:
        log.info("Update available for %s", repo)
