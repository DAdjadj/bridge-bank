# Bridge Bank

> **Not comfortable with the terminal?** Use the [setup wizard at bridgebank.app](https://bridgebank.app) — fill in your details, download two files, and run one command. No manual configuration needed.

Automatically sync your bank transactions to [Actual Budget](https://actualbudget.org/) using [Enable Banking](https://enablebanking.com/).

- Imports confirmed transactions as **cleared**
- Imports pending transactions as **uncleared** -- categorise them immediately
- When a pending transaction confirms, it is automatically matched and cleared in place (no duplicates, your category is preserved)
- Email notification when your session is about to expire

> **Why Enable Banking?** GoCardless (formerly Nordigen) stopped accepting new account registrations in July 2025. Enable Banking offers a free restricted tier that works for personal use.

---

## Requirements

- Docker and Docker Compose
- A free [Enable Banking](https://enablebanking.com/) account
- A self-hosted [Actual Budget](https://actualbudget.org/) instance

---

## Setup

### 1. Create an Enable Banking application

1. Sign up at [enablebanking.com](https://enablebanking.com/)
2. Go to **Applications** and create a new application
3. Download your **private key** (`private.pem`)
4. Note your **Application ID** (a UUID shown on the dashboard)

### 2. Clone this repo

```bash
git clone https://github.com/DAdjadj/bridge-bank.git
cd bridge-bank
```

### 3. Add your private key

```bash
mkdir -p data
cp /path/to/your/private.pem data/private.pem
```

### 4. Authorise your bank account

Install the dependencies and run the setup script:

```bash
pip install requests PyJWT cryptography
EB_APPLICATION_ID=your-app-id python3 dosetup.py
```

The script will:
1. Open an authorisation URL -- open it in your browser
2. Log in to your bank and approve access
3. Paste the redirect URL back into the terminal
4. Save your session to `data/state.json`

> **Note:** when setting up your Enable Banking application, the redirect URL must be set to `https://enablebanking.com/`

**For banks other than Revolut:**

```bash
EB_APPLICATION_ID=your-app-id \
EB_BANK_NAME="Monzo" \
EB_BANK_COUNTRY="GB" \
python3 dosetup.py
```

See [Enable Banking's connector list](https://enablebanking.com/connectors/) for supported banks and country codes.

### 5. Configure docker-compose.yml

Edit `docker-compose.yml` and fill in your values:

```yaml
ACTUAL_URL: "http://actual-budget:5006"
ACTUAL_PASSWORD: "your-actual-password"
ACTUAL_SYNC_ID: "your-sync-id"        # Settings > Show advanced settings > Sync ID
ACTUAL_ACCOUNT: "Revolut"             # Name of the account in Actual Budget
EB_APPLICATION_ID: "your-app-id"
```

**Recommended:** set `ACCOUNT_HOLDER_NAME` to your name as it appears on bank transfers (e.g. `"John Doe,JOHN DOE"`). This ensures incoming transfers and card refunds show the correct payee instead of your own name.

**If Actual Budget is on a Docker network**, uncomment the `networks` section and adjust to match your setup.

### 6. Start the container

```bash
docker compose up -d
docker compose logs -f
```

You should see:

```
[INFO] Starting scheduler (every 6h)
[INFO] Starting sync...
[INFO] Fetched 12 transactions from Enable Banking
[INFO] Done: 12 added, 0 confirmed, 0 skipped
```

---

## How pending transactions work

| Stage | What happens |
|---|---|
| Transaction appears as pending | Imported into Actual as **uncleared** |
| You categorise and rename it in Actual | Your changes are saved |
| Transaction confirms (usually 1-3 days) | Automatically flipped to **cleared** |

You can safely edit the category, payee, and notes on a pending transaction. Matching uses **date and amount** -- avoid changing either of those.

---

## Session renewal (every 180 days)

Enable Banking sessions expire after 180 days (a PSD2 requirement). You will receive an email notification 7 days before expiry if you configured SMTP.

To renew:

```bash
EB_APPLICATION_ID=your-app-id python3 dosetup.py
docker compose restart
```

---

## Configuration reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `ACTUAL_URL` | Yes | | URL of your Actual Budget instance |
| `ACTUAL_PASSWORD` | Yes | | Actual Budget password |
| `ACTUAL_SYNC_ID` | Yes | | Sync ID from Actual Budget settings |
| `ACTUAL_ACCOUNT` | No | `Revolut` | Account name in Actual Budget |
| `EB_APPLICATION_ID` | Yes | | Enable Banking application ID |
| `SYNC_INTERVAL_HOURS` | No | `6` | How often to sync |
| `ACCOUNT_HOLDER_NAME` | No | | Your name as it appears on transfers, comma-separated. Used to correctly identify payees on incoming transfers and refunds. |
| `NOTIFY_EMAIL` | No | | Email address for session expiry alerts |
| `SMTP_HOST` | No | | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USER` | No | | SMTP username |
| `SMTP_PASS` | No | | SMTP password (use app-specific password) |

---

## Troubleshooting

**Transactions not importing**
- Check `docker compose logs` for errors
- Verify your session is valid: `cat data/state.json` -- check `eb_session_expiry`
- If expired, re-run `dosetup.py`

**Incoming transfers showing your own name as payee**
- Set `ACCOUNT_HOLDER_NAME` in `docker-compose.yml` to your name as it appears on bank transfers

**Duplicate transactions**
- Should not happen with the current setup
- If you see duplicates, open an issue

**Session expired**
- Re-run `dosetup.py` and restart the container

**Container keeps restarting**
- Usually means Actual Budget is unreachable -- verify `ACTUAL_URL` and that the container is running

**Transaction skipped with "Multiple rows were found when one or none was required"**
- This means Actual Budget has duplicate payee entries with the same name
- Go to **Settings > Payees** in Actual Budget, search for the payee name shown in the log, and merge the duplicates
- Restart the container after merging -- the skipped transaction will be retried automatically on the next sync

**Transaction skipped with "Multiple rows were found when one or none was required"**
- This means Actual Budget has duplicate payee entries with the same name
- Go to **Settings > Payees** in Actual Budget, search for the payee name shown in the log, and merge the duplicates
- Restart the container after merging -- the skipped transaction will be retried automatically on the next sync

---

## How it works

```
Enable Banking API
       |
       | (every 6 hours)
       v
   sync.py
       |
       |-- PDNG transactions --> Actual Budget (uncleared)
       |                              |
       |                         You categorise
       |
       |-- BOOK transactions --> match pending by date+amount
                                      |
                                 flip to cleared
                                 update payee name
```

Enable Banking acts as a PSD2-compliant bridge between your bank and this script. Your bank credentials never leave Enable Banking -- this script only receives a session token.

---

## Supported banks

Any bank supported by Enable Banking should work. Full list here: https://enablebanking.com/open-banking-apis

Tested with:
- Revolut (PT, GB)

If you test with another bank, please open a PR to add it to this list.

---

## License

MIT
