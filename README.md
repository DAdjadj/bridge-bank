# Bridge Bank

**Your EU bank transactions, inside Actual Budget. Automatically.**

Bridge Bank connects to your EU bank via open banking and imports your transactions into a self-hosted [Actual Budget](https://actualbudget.org/) instance once a day. It runs on your own machine — your financial data never touches any third-party server.

---

## What you get

- **Flexible sync frequency** — sync every 6, 12, or 24 hours, at a time you choose
- **2,500+ European banks** — Revolut, N26, Monzo, Wise, Millennium BCP, Santander, ING, BNP Paribas, and more across 29 countries
- **Multiple bank accounts** — connect up to 2 bank accounts by default, each syncing to a different Actual Budget account. Need more? Purchase additional slots from the status page.
- **Read-only, always** — Bridge Bank can never move money or modify your account
- **Pending transaction tracking** — pending transactions are imported as uncleared and automatically confirmed when they settle
- **Duplicate detection** — Bridge Bank tracks every transaction ID so nothing gets imported twice
- **Email notifications** — an alert if something goes wrong, and a warning before your bank session expires
- **Your data, your machine** — bank data goes directly from Enable Banking to your machine, never our servers
- **Lightweight** — runs as a single Docker container
- **Runs anywhere** — supports x86, Raspberry Pi, and other ARM devices out of the box

---

## Requirements

- Docker and Docker Compose (runs on x86, Raspberry Pi, and other ARM devices)
- A free [Enable Banking](https://enablebanking.com/) account
- A self-hosted [Actual Budget](https://actualbudget.org/) instance
- A Bridge Bank licence key — [buy one at bridgebank.app](https://bridgebank.app)

---

## Quick start

> **New to self-hosting?** Follow the step-by-step guide at [bridgebank.app/getting-started](https://bridgebank.app/getting-started.html) — it walks you through everything from Enable Banking setup to running your first sync.


### 1. Get your licence key

Purchase at [bridgebank.app](https://bridgebank.app). Your key is delivered to your email instantly.

### 2. Set up Enable Banking

Enable Banking is the regulated open banking provider that connects Bridge Bank to your bank.

1. Sign up at [enablebanking.com](https://enablebanking.com)
2. Go to **API applications** and click **Register new application**
3. Fill in the form:
   - **Application name:** Bridge Bank
   - **Allowed redirect URLs:** `https://bridgebank.app/callback`
   - **Application description:** Connect Actual Budget with my bank
   - **Email for data protection matters:** your email address
   - **Privacy URL:** `https://bridgebank.app/privacy`
   - **Terms URL:** `https://bridgebank.app/terms`
4. Click **Register** — a `.pem` file will be saved to your Downloads folder. The filename matches your Application ID (e.g. `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.pem`). Keep it safe — you'll need it in the setup wizard.
5. Click **Activate by linking accounts** on your application page
6. Select your country and bank from the dropdowns and click **Link**
7. Follow the steps to log in to your bank and approve read-only access — this activates your Enable Banking app

### 3. Install Bridge Bank

**On your server**, create the folder and download the compose file:
```bash
mkdir -p ~/bridge-bank/data && cd ~/bridge-bank
curl -O https://raw.githubusercontent.com/DAdjadj/bridge-bank/main/docker-compose.yml
```

Start the container:
```bash
docker compose up -d
```

Open **http://your-server-address:3002** in your browser. The setup wizard will guide you through the rest.

### Local SMTP relays

Bridge Bank defaults to STARTTLS on port 587 for common hosted providers. For a trusted local relay on port 25, set these environment variables on the `bridge-bank` service:

```yaml
environment:
  - NOTIFY_EMAIL=you@example.com
  - SMTP_HOST=mail-relay
  - SMTP_PORT=25
  - SMTP_SECURITY=none
  - SMTP_AUTH=false
  - SMTP_FROM=bridge-bank@home.lan
```

`SMTP_SECURITY` accepts `starttls`, `ssl`, or `none`. For a relay that uses STARTTLS with a self-signed certificate, keep `SMTP_SECURITY=starttls` and set `SMTP_TLS_VERIFY=false`.

---

## Setup wizard

The browser-based wizard walks you through five steps:

1. **License** — enter your key to activate Bridge Bank on this machine
2. **Actual Budget** — enter your Actual Budget URL, password, and Sync ID
3. **Notifications** — set your email and SMTP credentials
4. **Sync** — choose your sync frequency (every 6, 12, or 24 hours) and start date
5. **Bank** — upload your Enable Banking `.pem` file (App ID is filled automatically from the filename), then connect your bank via OAuth. You choose which Actual Budget account each bank syncs to.
6. **Status** — view sync history, manage bank connections, check for updates

You can connect up to 2 bank accounts by default. Each bank syncs to a different Actual Budget account (e.g. Revolut → "Revolut", N26 → "N26"). To add a second bank, go to the **Bank** tab and search for another bank.

Once complete, Bridge Bank runs silently in the background and syncs your transactions every day at the time you chose.

---

## First sync and duplicates

On the first sync, Bridge Bank will import all transactions from the start date you set in the wizard. If you set a past date and already have those transactions in Actual Budget from another source, you may see duplicates — just delete the extras manually. This will only happen once. From the second sync onwards, Bridge Bank tracks every transaction ID and will never import the same transaction twice.

To avoid duplicates entirely, set the start date to today when going through the wizard.

---

## How it works
```
Your bank
   ↓  (read-only OAuth, Enable Banking)
Bridge Bank (running on your machine)
   ↓  (Actual Budget API)
Your Actual Budget instance
   ↓  (SMTP)
Your inbox  ← alert emails
```

On each sync run, Bridge Bank:

1. Validates your licence key
2. Fetches transactions since the last sync from Enable Banking
3. Filters out any transaction IDs already imported
4. Writes new transactions to Actual Budget
5. Updates any previously pending transactions that have since settled
6. Logs the result and sends an alert email if something went wrong

---

## Session renewal (every ~180 days)

Enable Banking requires you to re-authorise access roughly every 6 months. If you configured email notifications, you will receive a warning before expiry.

To re-authorise, go to the **Bank** tab in the Bridge Bank web UI and click **Re-authorise bank**.

---

## Updating

Click **Check for updates** on the Status page. Bridge Bank will pull the latest version and restart automatically.

Or run manually:
```bash
docker compose pull && docker compose up -d
```

---

## License deactivation

Each licence key supports up to 2 machine activations. To move Bridge Bank to a new machine, go to the **Status** page in the web UI and click **Deactivate license** before reinstalling.

---

## License

MIT + Commons Clause. Free to self-host for personal use. You may not sell, sublicense, or offer Bridge Bank as a competing service.

Built by [David Alves](https://david-alves.com).
