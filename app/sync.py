import contextlib, os, json, sys, time, logging, datetime, decimal, requests

from . import config, db, email_notify, licence

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

STATE_FILE = "/data/state.json"
EB_API     = "https://api.enablebanking.com"
TRANSFER_MATCH_WINDOW_DAYS = 3
# Booked transactions keep their booking date, so a reference-less booking only
# ever matches its own earlier import on the same day. Anything wider would let
# a genuine repeat purchase later in the week be swallowed as a duplicate.
DUPLICATE_MATCH_WINDOW_DAYS = 0
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
    ensure_actual_compat_patches()
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
    """Fetch transactions, tolerating banks' unattended-history limits.

    Outside the short window right after SCA, many banks (ING NL among them)
    only serve ~90 days of history to unattended fetches; requesting more
    returns 422 WRONG_TRANSACTIONS_PERIOD, and a stale pending transaction in
    pending_map can drag date_from past that boundary months after connecting.
    strategy=longest asks Enable Banking to clamp to whatever the bank allows
    instead of erroring. Two fallbacks: banks that reject the strategy hint
    get a plain request, and a WRONG_TRANSACTIONS_PERIOD anyway is retried
    with the window clamped to 89 days."""
    try:
        return _fetch_transactions_once(account_uid, date_from, use_strategy=True)
    except requests.HTTPError as e:
        body = (getattr(e.response, "text", "") or "").upper() if e.response is not None else ""
        status = e.response.status_code if e.response is not None else 0
        if status in (400, 422) and ("STRATEGY" in body or "WRONG_REQUEST_PARAMETERS" in body):
            log.warning("Bank rejected the transactions strategy hint; retrying without it")
            return _fetch_transactions_once(account_uid, date_from, use_strategy=False)
        if "WRONG_TRANSACTIONS_PERIOD" in body:
            clamped = max(date_from, datetime.date.today() - datetime.timedelta(days=89))
            if clamped != date_from:
                log.warning("Bank refused history from %s (unattended limit); retrying from %s",
                            date_from.isoformat(), clamped.isoformat())
                return _fetch_transactions_once(account_uid, clamped, use_strategy=True)
        raise

def _fetch_transactions_once(account_uid, date_from, use_strategy=True):
    headers = _make_headers()
    base_params = {"date_from": date_from.isoformat(), "date_to": datetime.date.today().isoformat()}
    if use_strategy:
        base_params["strategy"] = "longest"
    params  = dict(base_params)
    txns    = []
    url     = f"{EB_API}/accounts/{account_uid}/transactions"
    page    = 0
    while url:
        if page > 0:
            time.sleep(1)
        for attempt in range(4):
            r = requests.get(url, headers=headers, params=params, timeout=30)
            # 5xx from Enable Banking is a brief upstream problem, same as 429.
            if r.status_code == 429 or r.status_code >= 500:
                wait = min(2 ** attempt * 5, 60)
                log.warning("Enable Banking %s, retrying in %ds (attempt %d/4)", r.status_code, wait, attempt + 1)
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

def _eb_error_snippet(response):
    """Short, safe extract of an Enable Banking error body for user-facing
    sync-log messages, so failures are diagnosable from the Status page
    without a full log download.

    The bank's own complaint arrives nested under "detail", while the top
    level only names Enable Banking's category for it. Openbank NL sends
    {"error": "ASPSP_ERROR", "detail": {"message": "Invalid status value"}},
    and reporting just "ASPSP_ERROR" names the messenger rather than the
    fault, so the nested message is appended when there is one."""
    if response is None:
        return ""
    try:
        data = response.json()
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    parts = []
    for key in ("code", "error", "detail", "message"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val.strip())
            break
    detail = data.get("detail")
    if isinstance(detail, dict):
        nested = detail.get("message")
        if isinstance(nested, str) and nested.strip() and nested.strip() not in parts:
            parts.append(nested.strip())
    if not parts:
        return ""
    return ": " + ": ".join(parts)[:160]

# Enable Banking wraps a consent the bank has revoked as a plain ASPSP_ERROR,
# so the bank's own wording is the only thing separating it from a genuine
# bank-side fault. Kept deliberately narrow: "Session status is not authorized"
# is Enable Banking talking about its own session, a different failure.
AUTH_FAILURE_MARKERS = ("unauthorized", "authentication failure")

def _eb_nested_detail(response):
    """The bank's own message from an Enable Banking error body, if it sent one."""
    if response is None:
        return ""
    try:
        data = response.json()
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    detail = data.get("detail")
    if isinstance(detail, dict):
        nested = detail.get("message")
        return nested.strip() if isinstance(nested, str) and nested.strip() else ""
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    return ""

def _eb_probe_detail_snippet(account_uid):
    """Ask /details for the reason /transactions would not give.

    Openbank NL answers a revoked consent with detail:null on the transactions
    endpoint but names the fault ("Unauthorized, authentication failure") on
    the account details endpoint, so without this probe the one field that
    identifies the failure never reaches the user. Runs on the error path
    only, and stays silent when the probe itself fails."""
    if not account_uid:
        return ""
    try:
        r = requests.get(f"{EB_API}/accounts/{account_uid}/details",
                         headers=_make_headers(), timeout=15)
        if r.ok:
            return ""
        nested = _eb_nested_detail(r)
        return (": " + nested[:160]) if nested else ""
    except Exception as e:
        log.debug("Detail probe for %s failed: %s", account_uid, e)
        return ""

def _looks_like_auth_failure(text):
    low = (text or "").lower()
    return any(marker in low for marker in AUTH_FAILURE_MARKERS)

# Every sync-log message for an authorisation the bank refused carries one of
# these. That refusal is what shows an account left on an older session has
# actually stopped working, rather than just being older.
AUTH_REFUSAL_PHRASES = ("rejected this account's authorisation", "bank session has expired")

def is_auth_refusal(message):
    low = (message or "").lower()
    return any(phrase in low for phrase in AUTH_REFUSAL_PHRASES)

def session_rank(account):
    """Order the sessions at one bank from oldest to newest.

    valid_until is stamped when an authorisation starts, so two of them minutes
    apart differ there; the row id breaks the tie if a bank pins both to the
    same timestamp.
    """
    return (account.get("session_expiry") or "", account.get("id") or 0)

def _session_account_uid(acct):
    return acct.get("uid") or acct.get("account_uid") or acct.get("resource_id")

def rebind_targets(row, newest_accounts, session_accounts, held_uids):
    """Accounts on its bank's newest session that `row` could be re-bound onto.

    Several sessions at one bank are not a fault in themselves: Revolut
    authorises a personal and a business profile separately, each session
    listing only its own account, and both keep working. Account uids are new
    in every session, so they cannot say whether the newest session covers the
    account this row syncs, but Enable Banking's identification_hash is the
    same for one bank account in every session and can.

    Returns (targets, matched). matched means the targets carry this row's own
    identification_hash. Otherwise they are the accounts it cannot be told
    apart from, and empty when the newest session covers nothing it could be.
    targets is None when the newest session's accounts were never recorded.
    Accounts some stored row already uses are never targets.
    """
    if newest_accounts is None:
        return None, False
    free = [a for a in newest_accounts
            if _session_account_uid(a) and _session_account_uid(a) not in held_uids]
    own_hash = ""
    for acct in session_accounts.get(row.get("session_id")) or []:
        if _session_account_uid(acct) == row.get("account_uid"):
            own_hash = acct.get("identification_hash") or ""
            break
    if not own_hash:
        return free, False
    same = [a for a in free if a.get("identification_hash") == own_hash]
    if same:
        return same, True
    return [a for a in free if not a.get("identification_hash")], False

def _bank_has_newer_session(account):
    """True when a later authorisation at this bank could take this account over.

    A bank that allows only one active consent revokes the previous one when a
    second is created, leaving the older row bound to a session the bank no
    longer honours. Enable Banking still reports both sessions AUTHORIZED, so
    comparing the stored rows is the only signal that the row can be repaired
    by re-binding instead of by a fresh SCA. A newer session that covers none
    of the accounts this row could be is a separate connection, which only a
    re-authorisation repairs."""
    if not account:
        return False
    try:
        rows = db.get_all_bank_accounts()
        session_accounts = db.get_session_accounts()
    except Exception:
        return False
    at_bank = [r for r in rows
               if r.get("sync_mode") != "balance" and r.get("session_id")
               and r.get("bank_name") == account.get("bank_name")
               and r.get("bank_country") == account.get("bank_country")]
    if not at_bank or not account.get("session_id"):
        return False
    newest = max(at_bank, key=session_rank)
    if newest.get("session_id") == account.get("session_id") or session_rank(newest) < session_rank(account):
        return False
    held = {r.get("account_uid") for r in rows if r.get("account_uid")}
    targets, _ = rebind_targets(account, session_accounts.get(newest.get("session_id")),
                                session_accounts, held)
    return targets is None or bool(targets)

def _fetch_failure_message(bank_label, exc, account=None):
    """User-facing sync-log message for a failed Enable Banking fetch.

    Only 401/403, and a bank that names an authentication failure, mean the
    connection needs attention; sending users to re-auth for rate limits or
    bank-side errors wastes their SCA and hides the real problem."""
    response = getattr(exc, "response", None)
    status = response.status_code if response is not None else 0
    if status == 429:
        return f"{bank_label}: Your bank is rate-limiting requests. Bridge Bank will retry on the next scheduled sync."
    if status in (401, 403):
        return f"{bank_label}: Your bank session has expired. Open Bridge Bank and click 'Re-authorise bank' on the Bank page."
    if isinstance(exc, requests.HTTPError):
        detail = _eb_error_snippet(response)
        if not _eb_nested_detail(response):
            detail += _eb_probe_detail_snippet((account or {}).get("account_uid"))
        if _looks_like_auth_failure(detail):
            # The bank is refusing this account's authorisation, which a fresh
            # one does clear. Re-binding clears it without spending an SCA.
            if _bank_has_newer_session(account):
                return (f"{bank_label}: Your bank rejected this account's authorisation (error {status}{detail}). "
                        "Another account at this bank is on a newer authorisation and this one was left "
                        "behind, which is what happens at banks that allow only one active consent. Open "
                        "the Bank page and use 'Re-bind to the newest connection' to repair it without a "
                        "new login.")
            return (f"{bank_label}: Your bank rejected this account's authorisation (error {status}{detail}). "
                    "Open Bridge Bank and click 'Re-authorise bank' on the Bank page to reconnect it.")
        # Deliberately does not offer re-authorisation. A refusal that is not
        # 401/403 and does not name an authentication failure is the bank
        # rejecting the request itself, so a fresh SCA cannot clear it, and
        # sending users to re-authorise burns their SCA and makes them think
        # they broke something.
        return (f"{bank_label}: Your bank refused the request (error {status}{detail}). "
                "This is a fault at the bank rather than an expired login, so reconnecting "
                "will not clear it. Bridge Bank will retry on the next scheduled sync. If it "
                "keeps repeating, send your logs from the Status page to support@bridgebank.app.")
    return (f"{bank_label}: Could not reach your bank's API ({type(exc).__name__}). "
            "Bridge Bank will retry on the next scheduled sync.")

def _parse_date(t, prefer_transaction_date=False):
    """Pick the date a transaction gets in Actual.

    The booking date is the default because it is the one date a booked
    transaction never changes, and both the pending_map keys and the
    reference-less duplicate match are built out of it.

    Banks that book late show the account holder a different date than the one
    that reaches Actual: at KBC (BE) a Friday evening payment carries a
    transaction and value date of Friday and books on the Monday, so every
    weekend and late-evening payment lands one to three days forward. Turning
    the preference on for such a bank swaps the order so Actual matches what
    the banking app shows. It also keeps a pending transaction on the date it
    was imported with once it books: a pending transaction has no booking date
    at all, so with the default order its date jumps forward the moment the
    booking arrives.
    """
    if prefer_transaction_date:
        raw = t.get("transaction_date") or t.get("value_date") or t.get("booking_date")
    else:
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

def _find_imported_duplicate(existing, claimed_ids, date, amount, imported_payee, live_refs=None):
    """Find the copy we already imported of a booking we cannot match by reference.

    entry_reference is optional in the underlying spec and some banks leave it
    empty, so imported_refs can never remember those bookings and every sync
    re-adds them. Fall back to same account, same amount, same original payee,
    same booking date. Match on imported_description rather than the payee
    because rules rewrite the payee after import, which would make the second
    sync miss its own first import.

    Two identical purchases on one day are told apart by count rather than by
    time: neither Actual nor Enable Banking records one, Actual stores a date as
    20260804. claimed_ids lets each incoming booking claim at most one existing
    copy, and every sync re-fetches the whole current day, so both bookings are
    always weighed against the copies together and the surplus gets added.

    live_refs is passed for a booking whose reference we have never seen. Banks
    sometimes renumber their transactions (Bankinter PT on every fetch, a bank
    moving to a new Enable Banking connector on reconnect), and the old copy
    then carries a reference the bank no longer sends. Only such copies are
    candidates: imported by us (financial_id set) and with a reference absent
    from the current fetch. A copy whose reference is still live belongs to a
    different booking, so for a bank that works nothing can ever qualify.
    """
    target_amount = round(decimal.Decimal(amount) * 100)
    wanted        = (imported_payee or "").strip()
    candidates    = []
    for t in existing:
        if str(t.id) in claimed_ids or t.is_child:
            continue
        if live_refs is not None:
            old_ref = getattr(t, "financial_id", None)
            if not old_ref or old_ref in live_refs:
                continue
        if t.amount != target_amount:
            continue
        if (t.imported_description or "").strip() != wanted:
            continue
        distance = abs((t.get_date() - date).days)
        if distance <= DUPLICATE_MATCH_WINDOW_DAYS:
            candidates.append((distance, t))
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]

def _find_pending_for_booking(existing, pending_map, ref):
    """Find the pending copy of a booking whose amount or date changed on settling.

    pending_map is keyed on date|amount, so a booking that settles for a
    different amount (a tip added to a ride, a hotel or fuel pre-authorisation,
    a card payment in another currency) never finds its pending copy there.
    reconcile_transaction then matches that copy on financial_id, because banks
    like Revolut keep one entry_reference from pending to booked, and updates
    everything except the amount: the pending amount stays in Actual for good
    and the pending_map entry is never cleared.

    Returns (pending_map key, transaction) or None. Only a reference match
    counts; without one, two card payments at one merchant cannot be told apart.
    """
    if not ref:
        return None
    key_by_txn_id = {txn_id: key for key, txn_id in pending_map.items()}
    for t in existing:
        key = key_by_txn_id.get(str(t.id))
        if key is not None and t.financial_id == ref:
            return key, t
    return None

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
    skipped = 0
    for rule in get_rules(session):
        if not rule.conditions or not rule.actions:
            continue
        try:
            conditions = TypeAdapter(list[Condition]).validate_json(rule.conditions)
            actions = TypeAdapter(list[Action]).validate_json(rule.actions)
            rules.append(Rule(conditions=conditions, operation=rule.conditions_op,
                              actions=actions, stage=rule.stage))
        except Exception as e:
            skipped += 1
            log.warning(
                "Skipping rule the import engine cannot process (it still "
                "works via 'Run Rules' in Actual). conditions=%s actions=%s | %s",
                rule.conditions, rule.actions, e)
    log.info("Rules loaded: %d, skipped: %d", len(rules), skipped)
    return RuleSet(rules=rules)

def _run_ruleset_tolerant(ruleset, transactions):
    """Run rules one at a time so a single failing rule cannot abort the rest.

    actualpy's RuleSet.run lets any exception propagate, so one rule that
    crashes at run time (e.g. an invalid regex in a 'matches' condition, or
    an edge-case value) silently cancels the whole rule pass for the import,
    while the same rules keep working via 'Run Rules' in Actual. Keeps the
    pre -> default -> post stage order."""
    failed_rules = 0
    for stage in ("pre", None, "post"):
        for rule in [r for r in ruleset.rules if r.stage == stage]:
            try:
                for txn in transactions:
                    rule.run(txn)
            except Exception as e:
                failed_rules += 1
                log.warning("Rule failed at run time and was skipped: %s | %s", rule, e)
    if failed_rules:
        log.warning("%d rule(s) failed at run time this pass", failed_rules)

_action_run_patched = False
_migrations_patched = False
_apply_changes_patched = False

def ensure_actual_compat_patches():
    """Install the actualpy compatibility patches (idempotent).

    Any code path that opens an Actual client outside _actual_client (e.g.
    the web UI's connection tests and account validation) must call this
    first, so budget downloads survive budgets from newer Actual servers."""
    _patch_idempotent_migrations()
    _patch_unknown_table_sync()

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

def _patch_unknown_table_sync():
    """Skip sync messages for tables this actualpy version does not model.

    Actual servers grow new tables ahead of actualpy releases: 26.4.0 added
    payee_locations for the experimental Payee Locations feature, and actualpy
    (through 0.22.3) has no model for it. apply_changes raises on the first
    sync message touching an unknown table, so every budget download fails
    with "Could not find table '...' on the database model" until the library
    catches up. Bridge Bank only reads and writes accounts, transactions,
    payees and rules, so changes to other tables can safely be left out of its
    local budget copy; the server's data is untouched either way. Drop those
    messages with a warning and apply the rest. Remove once actualpy models
    the new tables. Upstream: bvanelli/actualpy apply_changes."""
    global _apply_changes_patched
    if _apply_changes_patched:
        return
    from actual import Actual
    from actual.database import __TABLE_COLUMNS_MAP__ as _table_map

    _orig_apply_changes = Actual.apply_changes

    def _apply_changes(self, messages):
        supported, skipped = [], {}
        for message in messages:
            # 'prefs' is not a table; apply_changes routes it to metadata.json
            if message.dataset == "prefs" or message.dataset in _table_map:
                supported.append(message)
            else:
                skipped[message.dataset] = skipped.get(message.dataset, 0) + 1
        for dataset, count in sorted(skipped.items()):
            log.warning(
                "Skipping %d sync change(s) for table '%s', which this actualpy "
                "version does not support; the rest of the sync continues.",
                count,
                dataset,
            )
        return _orig_apply_changes(self, supported)

    Actual.apply_changes = _apply_changes
    _apply_changes_patched = True

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
            # Derive the split index from options directly instead of the
            # get_split_index() helper, which only exists in actualpy
            # >= 0.22.3. A production image with an older version turned
            # this patch into an AttributeError on every set-notes rule.
            split_index = 0
            if self.options:
                try:
                    split_index = int(self.options.get("splitIndex", 0) or 0)
                except (TypeError, ValueError):
                    split_index = 0
            splits = getattr(transaction, "splits", None) or []
            if split_index and len(splits) >= split_index:
                transaction = splits[split_index - 1]
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
    _run_ruleset_tolerant(ruleset, counterparts)
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
    # Pairs that are already linked to each other across accounts need no
    # repair, and leaving them in makes a second transfer of the same amount a
    # few days later look ambiguous, so that one is never repaired. Regular
    # top-ups of a round sum (110 on Monday, 110 again on Tuesday) hit this.
    by_id = {t.id: t for t in candidates}
    linked = {
        t.id for t in candidates
        if (other := by_id.get(_txn_transfer_id(t))) is not None
        and _txn_transfer_id(other) == t.id
        and _txn_account_id(other) != _txn_account_id(t)
    }
    candidates = [t for t in candidates if t.id not in linked]
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

class ActualAccountError(Exception):
    """The Actual account a bank syncs into cannot be used as it stands.

    The message is shown to the customer, so it says what happened and what to
    do. Nothing is imported or created when this is raised.
    """

def _has_sync_history(account, state):
    return bool(state.get("accounts", {}).get(str(account.get("id")), {}).get("last_sync_date"))

def _remember_actual_account(account, obj):
    """Store the Actual account's id and current name on the bank account row."""
    if account.get("actual_account_id") == obj.id and account.get("actual_account") == obj.name:
        return
    account["actual_account_id"] = obj.id
    account["actual_account"] = obj.name
    if account.get("id") is None:
        return
    try:
        db.update_bank_account_field(account["id"], "actual_account_id", obj.id)
        db.update_bank_account_field(account["id"], "actual_account", obj.name)
    except Exception as e:
        log.warning("Could not remember the Actual account for %s: %s", bank_label(account), e)

def resolve_actual_account(session, account, create=False, has_history=False):
    """The Actual account this bank account syncs into, found by id first.

    Actual lets people rename accounts freely, so the id is what identifies
    one; the stored name is only the last name seen. Looking up by name alone
    meant a rename made the next sync create a fresh account under the old name
    and import into that, and for a balance-only account (which replaces every
    transaction in its Actual account) an unrelated account later given the old
    name would have been wiped.

    In order:
    - the stored id, if that account still exists: renames are followed;
    - otherwise the stored name, but only an open account no other bank account
      already syncs into, and only when exactly one matches (the id is gone
      when the budget file was replaced or the account deleted and re-created);
    - otherwise a new account, but only for a bank account that has never
      synced: one that has lost its account is reported instead, because
      creating a replacement would import into an account nobody asked for.

    Returns None only when create is False and a new account would be needed.
    A created account is not remembered until a later sync finds it committed,
    so a failed commit cannot leave a dangling id behind.
    """
    from actual.database import Accounts
    from sqlmodel import select

    name = account.get("actual_account") or config.ACTUAL_ACCOUNT
    bound_id = account.get("actual_account_id") or ""
    live = session.exec(select(Accounts).where(Accounts.tombstone == 0)).all()

    if bound_id:
        obj = next((a for a in live if a.id == bound_id), None)
        if obj is not None:
            if obj.closed:
                raise ActualAccountError(
                    f'"{obj.name}" is closed in Actual Budget, so nothing was imported. Reopen it in '
                    'Actual Budget, or choose another account for this bank on the Bank page.')
            if obj.name != name:
                log.info('"%s" was renamed to "%s" in Actual Budget. %s keeps syncing into it.',
                         name, obj.name, account.get("bank_name") or "This bank")
            _remember_actual_account(account, obj)
            return obj

    taken = {
        a.get("actual_account_id") for a in db.get_all_bank_accounts()
        if a.get("id") != account.get("id") and a.get("actual_account_id")
    }
    named = [a for a in live if a.name == name]
    free = [a for a in named if a.id not in taken]
    usable = [a for a in free if not a.closed]
    if len(usable) == 1:
        if bound_id:
            log.warning('The Actual Budget account %s synced into is gone. Syncing into the account '
                        'named "%s" instead.', bank_label(account), name)
        _remember_actual_account(account, usable[0])
        return usable[0]
    if len(usable) > 1:
        raise ActualAccountError(
            f'Actual Budget has {len(usable)} open accounts named "{name}", so nothing was imported. '
            'Rename all but one in Actual Budget, or choose the account on the Bank page.')
    if free:
        raise ActualAccountError(
            f'"{name}" is closed in Actual Budget, so nothing was imported. Reopen it in '
            'Actual Budget, or choose another account for this bank on the Bank page.')
    if named:
        raise ActualAccountError(
            f'"{name}" in Actual Budget already receives another bank\'s transactions, so nothing '
            'was imported. Choose a different account for this bank on the Bank page.')
    if bound_id or has_history:
        raise ActualAccountError(
            f'The Actual Budget account "{name}" this bank synced into no longer exists (it was '
            'renamed or deleted before Bridge Bank could follow it), so nothing was imported. '
            'Choose the account to sync into on the Bank page.')
    if not create:
        return None
    from actual.queries import create_account
    log.info('Creating the account "%s" in Actual Budget.', name)
    return create_account(session, name)

def check_actual_accounts(accounts, state):
    """Bind every bank account to its Actual account and pick up renames.

    Runs once before a sync so names shown in labels, logs and emails are
    current, and so an account that cannot be synced is reported before its
    bank is asked for transactions (some banks allow only a few fetches a day).
    Returns {bank account id: message} for the accounts that cannot sync. If
    Actual cannot be reached nothing is reported here: each account's own
    sync then fails with the connection error (and its retries, so none are
    added here).
    """
    problems = {}
    try:
        with _actual_client("Actual accounts") as actual:
            with _actual_phase("Actual accounts", "match bank accounts to Actual accounts"):
                for a in accounts:
                    try:
                        resolve_actual_account(actual.session, a, has_history=_has_sync_history(a, state))
                    except ActualAccountError as e:
                        problems[a.get("id")] = str(e)
    except Exception as e:
        log.warning("Could not check the Actual Budget accounts before syncing: %s", e)
        return {}
    return problems

def _auto_link_internal_transfers(actual, accounts):
    if not _config_flag("AUTO_LINK_TRANSFERS", True):
        return 0

    transfer_accounts = [
        a for a in accounts
        if a.get("sync_mode") != "balance" and a.get("actual_account")
    ]
    if len(transfer_accounts) < 2:
        return 0

    from actual.queries import get_payees, get_transactions

    account_by_id = {}
    transactions = []
    start_date = _get_transfer_match_start(transfer_accounts)
    end_date = datetime.date.today() + datetime.timedelta(days=1)

    for a in transfer_accounts:
        try:
            account_obj = resolve_actual_account(actual.session, a)
        except ActualAccountError:
            continue
        if not account_obj or account_obj.id in account_by_id:
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
        from actual.queries import get_transactions, create_transaction

        with _actual_client(bank_label) as actual:
            with _actual_phase(bank_label, "load Actual balance account"):
                account_obj = resolve_actual_account(actual.session, account, create=True)
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
    except ActualAccountError as e:
        msg = f"{bank_label}: {e}"
        log.error(msg)
        return False, 0, msg
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
    except requests.RequestException as e:
        msg = _fetch_failure_message(bank_label, e, account)
        log.error(msg)
        return False, 0, msg

    if not raw:
        log.info("No new transactions for %s", bank_label)
        acct_state["last_sync_date"] = datetime.date.today().isoformat()
        state["accounts"][account_id] = acct_state
        return True, 0, "OK"

    has_history = bool(acct_state.get("last_sync_date"))
    pending_map_start = dict(pending_map)
    imported_refs_start = set(acct_state.get("imported_refs", []))
    live_refs = {r for r in (_get_entry_ref(t) for t in raw) if r}

    def write_transactions_to_actual():
        pending_map = dict(pending_map_start)
        imported_refs = set(imported_refs_start)
        added = updated = skipped = 0
        from actual.queries import reconcile_transaction, get_transactions, create_transaction

        with _actual_client(bank_label) as actual:
            with _actual_phase(bank_label, "load Actual account and existing transactions"):
                account_obj    = resolve_actual_account(actual.session, account, create=True,
                                                        has_history=has_history)
                existing       = list(get_transactions(actual.session, account=account_obj))
                existing_ids   = {str(t.id) for t in existing}
                already_matched = existing[:]
                claimed_ids    = set()
                new_txn        = []

            skip_pending = bool(account.get("skip_pending"))
            prefer_transaction_date = bool(account.get("prefer_transaction_date"))

            with _actual_phase(bank_label, "reconcile fetched transactions"):
                for txn in raw:
                    try:
                        status = txn.get("status", "BOOK")
                        if status == "PDNG" and skip_pending:
                            skipped += 1
                            continue
                        date   = _parse_date(txn, prefer_transaction_date)
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
                                claimed_ids.add(str(t.id))
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
                            elif (settled := _find_pending_for_booking(existing, pending_map, ref)):
                                pending_key, existing_txn = settled
                                existing_txn.set_amount(amount)
                                existing_txn.cleared = True
                                del pending_map[pending_key]
                                claimed_ids.add(str(existing_txn.id))
                                imported_refs.add(ref)
                                updated += 1
                            else:
                                duplicate = _find_imported_duplicate(
                                    existing, claimed_ids, date, amount, payee,
                                    live_refs=live_refs if ref else None,
                                )
                                if duplicate is not None:
                                    claimed_ids.add(str(duplicate.id))
                                    if ref:
                                        log.info("%s: bank changed a transaction's reference "
                                                 "(%s -> %s); kept the existing copy",
                                                 bank_label, duplicate.financial_id, ref)
                                        duplicate.financial_id = ref
                                        imported_refs.add(ref)
                                        for k, v in list(pending_map.items()):
                                            if v == str(duplicate.id):
                                                del pending_map[k]
                                    if not duplicate.cleared:
                                        duplicate.cleared = True
                                    result = _record_reconciled_transaction(duplicate, existing_ids, new_txn)
                                    if result == "updated":
                                        updated += 1
                                    else:
                                        skipped += 1
                                    continue
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
                                claimed_ids.add(str(t.id))
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
                    _run_ruleset_tolerant(ruleset, new_txn)
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
    except ActualAccountError as e:
        msg = f"{bank_label}: {e}"
        log.error(msg)
        return False, 0, msg
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

def run(only_account_id=None):
    """Sync all bank accounts, or just one when only_account_id is given.

    A per-account sync still runs the licence and seat checks and the
    internal-transfer linking (which spans every account, so a freshly synced
    account can still pair with transactions already imported from the others).
    Only the fetch-and-import loop is narrowed, which is the part that hits the
    banks and can trip their rate limits.
    """
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
    # Before any bank is asked for transactions: binds each account to its
    # Actual account id, so a rename in Actual shows up in every label below.
    account_problems = check_actual_accounts(all_accounts, state)

    if only_account_id is not None:
        accounts_to_sync = [a for a in all_accounts if a.get("id") == only_account_id]
        if not accounts_to_sync:
            msg = "The selected bank account no longer exists."
            log.error(msg)
            return False, 0, msg
        log.info("Syncing only %s", bank_label(accounts_to_sync[0]))
    else:
        accounts_to_sync = all_accounts

    total_added = 0
    errors = []
    successes = []

    for i, account in enumerate(accounts_to_sync):
        label = bank_label(account)
        problem = account_problems.get(account.get("id"))
        if problem:
            msg = f"{label}: {problem}"
            log.error(msg)
            errors.append(msg)
            db.log_sync("failure", tx_count=0, message=msg)
            continue
        if i > 0:
            time.sleep(2)
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
