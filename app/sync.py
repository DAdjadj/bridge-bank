import os, json, time, logging, datetime, decimal, requests

from . import config, db, email_notify, licence

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

STATE_FILE = "/data/state.json"
EB_API     = "https://api.enablebanking.com"

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
    params  = {"date_from": date_from.isoformat(), "date_to": datetime.date.today().isoformat()}
    txns    = []
    url     = f"{EB_API}/accounts/{account_uid}/transactions"
    while url:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if not r.ok:
            log.error("Enable Banking error %s: %s", r.status_code, r.text)
            r.raise_for_status()
        data = r.json()
        txns.extend(data.get("transactions", []))
        ck  = data.get("continuation_key")
        url = f"{EB_API}/accounts/{account_uid}/transactions" if ck else None
        params = {"continuation_key": ck} if ck else {}
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

def _sync_account(account, state):
    """Sync a single bank account. Returns (success, tx_count, message)."""
    account_id = str(account["id"])
    bank_label = f"{account.get('bank_name', 'Unknown')} ({account.get('bank_country', '')})"
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

    imported_refs = set(acct_state.get("imported_refs", []))
    added = updated = skipped = 0

    try:
        from actual import Actual
        from actual.queries import get_or_create_account, reconcile_transaction, get_transactions, create_transaction

        with Actual(base_url=config.ACTUAL_URL, password=config.ACTUAL_PASSWORD,
                    file=config.ACTUAL_SYNC_ID, data_dir="/data/actual-cache") as actual:
            account_obj    = get_or_create_account(actual.session, actual_account_name)
            existing       = list(get_transactions(actual.session, account=account_obj))
            already_matched = existing[:]
            new_txn        = []

            for txn in raw:
                try:
                    status = txn.get("status", "BOOK")
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
                                    already_matched=already_matched
                                )
                            except Exception:
                                t = create_transaction(
                                    actual.session, date, account_obj, payee, notes,
                                    amount, cleared=False, imported_payee=payee
                                )
                            already_matched.append(t)
                            if t.changed():
                                pending_map[key] = str(t.id)
                                added += 1
                                new_txn.append(t)
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
                                del pending_map[key]
                                if ref: imported_refs.add(ref)
                                updated += 1
                            else:
                                del pending_map[key]
                                if ref: imported_refs.add(ref)
                                skipped += 1
                        else:
                            t = reconcile_transaction(
                                actual.session, date, account_obj, payee, notes,
                                None, amount, imported_id=ref or None, cleared=True,
                                already_matched=already_matched
                            )
                            already_matched.append(t)
                            if t.changed():
                                if ref: imported_refs.add(ref)
                                new_txn.append(t)
                                added += 1
                            else:
                                skipped += 1
                except Exception as e:
                    log.warning("Skipping transaction: %s | %s", e, txn)

            try:
                actual.run_rules(new_txn)
            except Exception as e:
                log.error("Error applying rules: %s", e)

            actual.commit()
            log.info("Done %s: %d added, %d confirmed, %d skipped", bank_label, added, updated, skipped)

    except Exception as e:
        msg = f"{bank_label}: Could not connect to Actual Budget. Make sure Actual Budget is running and reachable at {config.ACTUAL_URL}."
        log.error(msg)
        return False, 0, msg

    acct_state["last_sync_date"]  = datetime.date.today().isoformat()
    acct_state["pending_map"]     = pending_map
    acct_state["imported_refs"]   = list(imported_refs)
    state["accounts"][account_id] = acct_state
    return True, added, "OK"

def run():
    log.info("Starting sync...")

    # License check
    result = licence.validate()
    if not result["valid"]:
        msg = f"License invalid: {result['error']}"
        log.error(msg)
        email_notify.send_failure(msg)
        db.log_sync("failure", message=msg)
        return False, 0, msg

    all_accounts = db.get_all_bank_accounts()
    if not all_accounts:
        msg = "No bank connection found. Please connect your bank."
        log.error(msg)
        db.log_sync("failure", message=msg)
        return False, 0, msg

    state = _load_state()
    total_added = 0
    errors = []
    successes = []

    for account in all_accounts:
        bank_label = f"{account.get('bank_name', 'Unknown')} ({account.get('bank_country', '')})"
        try:
            success, added, msg = _sync_account(account, state)
            if success:
                total_added += added
                successes.append(f"{bank_label}: {added} transactions")
                db.log_sync("success", tx_count=added, message=bank_label)
            else:
                errors.append(msg)
                db.log_sync("failure", tx_count=0, message=msg)
        except Exception as e:
            log.error("Unexpected error syncing %s: %s", bank_label, e)
            errors.append(f"{bank_label}: {e}")
            db.log_sync("failure", tx_count=0, message=f"{bank_label}: {e}")

    _save_state(state)

    if errors and not successes:
        email_notify.send_failure("\n".join(f"  ✗ {e}" for e in errors))
    elif errors:
        email_notify.send_partial(successes, errors)
    else:
        email_notify.send_success(total_added)

    # Check for updates silently
    try:
        _check_for_update()
    except Exception:
        pass

    return len(errors) == 0, total_added, "OK" if not errors else msg


def _check_for_update():
    """Check Docker Hub for a newer image and store result in DB."""
    import subprocess, os, requests as _req
    if not os.path.exists("/var/run/docker.sock"):
        return
    repo = "daalves/bridge-bank"
    tag = "latest"
    token_resp = _req.get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=5)
    token = token_resp.json().get("token", "")
    manifest_resp = _req.head(
        f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        timeout=5
    )
    remote_digest = manifest_resp.headers.get("Docker-Content-Digest", "")
    local_digest = subprocess.run(
        ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", f"{repo}:{tag}"],
        capture_output=True, text=True, timeout=10
    ).stdout.strip()
    local_sha = local_digest.split("@")[-1] if "@" in local_digest else ""
    update_available = remote_digest != local_sha and remote_digest != ""
    db.set_setting("update_available", "1" if update_available else "0")
    if update_available:
        log.info("Update available for %s", repo)
