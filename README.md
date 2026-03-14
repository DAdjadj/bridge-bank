# Bridge Bank

> **Not comfortable with the terminal?** Use the [setup wizard at bridgebank.app](https://bridgebank.app) — fill in your details, download two files, and run one command. No manual configuration needed.

Automatically sync your bank transactions to [Actual Budget](https://actualbudget.org/) using [Enable Banking](https://enablebanking.com/).

- Imports confirmed transactions as **cleared**
- Imports pending transactions as **uncleared** -- categorise them immediately
- When a pending transaction confirms, it is automatically matched and cleared in place (no duplicates, your category is preserved)
- Looks back to the earliest pending transaction on every sync, so confirmations are never missed
- Email notification when your Enable Banking session is about to expire

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
3. Set the redirect URL to `https://enablebanking.com/`
4. Download your **private key** (`private.pem`)
5. Note your **Application ID** (a UUID shown on the dashboard)

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

**For banks other than Revolut**, pass the bank name and country:

```bash
EB_APPLICATION_ID=your-app-id \
EB_BANK_NAME="Monzo" \
EB_BANK_COUNTRY="GB" \
python3 dosetup.py
```

See [Enable Banking's supported banks](https://enablebanking.com/open-banking-apis) for the full list of supported banks and country codes.

### 5. Create a `.env` file

Create a `.env` file in the project directory with your personal configuration:

```env
ACTUAL_URL=http://actual-budget:5006
ACTUAL_PASSWORD=your-actual-password
ACTUAL_SYNC_ID=your-sync-id
ACTUAL_ACCOUNT=Revolut
EB_APPLICATION_ID=your-app-id
```

Find your Sync ID in Actual Budget under **Settings > Show advanced settings > Sync ID**.

**Recommended:** add `ACCOUNT_HOLDER_NAME` set to your name as it appears on bank transfers (e.g. `"John Doe,JOHN DOE"`). This ensures incoming transfers and refunds show the correct payee name instead of your own name.

**For email notifications** when your session is about to expire, add your SMTP details:

```env
NOTIFY_EMAIL=you@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASS=your-app-password
```

> **iCloud users:** use an app-specific password from [appleid.apple.com](https://appleid.apple.com) and set `SMTP_HOST=smtp.mail.me.com`.

**If Actual Budget is on a Docker network**, uncomment the `networks` section in `docker-compose.yml` and adjust to match your setup.

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
| Transaction confirms (usually 1-3 days) | Automatically flipped to **cleared**, no duplicate created |

You can safely edit the category, payee, and notes on a pending transaction. Matching uses **date and amount** -- avoid changing either of those.

On every sync, Bridge Bank looks back to the date of your earliest pending transaction to ensure no confirmations are missed, even if the sync interval skipped over them.

---

## Session renewal (every 180 days)

Enable Banking sessions expire after 180 days (a PSD2 requirement). If you configured SMTP, you will receive an email notification **7 days before expiry** so you have time to renew without any interruption to your syncs.

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
| `EB_BANK_NAME` | No | `Revolut` | Bank name |
| `EB_BANK_COUNTRY` | No | `GB` | Bank country code |
| `SYNC_INTERVAL_HOURS` | No | `6` | How often to sync |
| `ACCOUNT_HOLDER_NAME` | No | | Your name as it appears on transfers, comma-separated. Used to correctly identify payees on incoming transfers and refunds. |
| `NOTIFY_EMAIL` | No | | Email address for session expiry alerts |
| `SMTP_HOST` | No | | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USER` | No | | SMTP username |
| `SMTP_PASS` | No | | SMTP password (use an app-specific password) |

---

## Troubleshooting

**Transactions not importing**
- Check `docker compose logs` for errors
- Verify your session is valid: `cat data/state.json` -- check `eb_session_expiry`
- If expired, re-run `dosetup.py` and restart the container

**Pending transactions not confirming**
- Confirmed transactions are matched by date and amount -- make sure you have not edited these fields in Actual Budget
- If you manually reconciled (locked) a pending transaction before it confirmed, it will be skipped automatically on the next sync without creating a duplicate

**Incoming transfers showing your own name as payee**
- Set `ACCOUNT_HOLDER_NAME` in your `.env` to your name as it appears on bank transfers (e.g. `"John Doe,JOHN DOE"`)

**Duplicate transactions**
- Should not happen with the current setup
- If you see a duplicate, delete the extra entry in Actual Budget and open an issue

**Session expired**
- Re-run `dosetup.py` and restart the container

**Container keeps restarting**
- Usually means Actual Budget is unreachable -- verify `ACTUAL_URL` and that the Actual Budget container is running

**Transaction skipped with "Multiple rows were found when one or none was required"**
- Actual Budget has duplicate payee entries with the same name
- Go to **Settings > Payees** in Actual Budget, search for the payee shown in the log, and merge the duplicates
- Restart the container -- the skipped transaction will be retried on the next sync

---

## How it works

```
Enable Banking API
       |
       | (every N hours)
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
                                 preserve category + payee edits
```

Enable Banking acts as a PSD2-compliant bridge between your bank and this tool. Your bank credentials never leave Enable Banking -- Bridge Bank only receives a session token.

---

## Supported banks

Any bank supported by Enable Banking should work. Full list: https://enablebanking.com/open-banking-apis

Tested with:
- Revolut (PT, GB)

If you test with another bank, please open a PR to add it to this list.

---

## License

This project is licensed under MIT + Commons Clause. You are free to use, modify, and self-host this software for personal use. You may not offer it as a paid or hosted service without permission.

See the [LICENSE](LICENSE) file for the full terms.

