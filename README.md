# Bridge Bank

**Your EU bank transactions, inside Actual Budget. Automatically.**

Bridge Bank connects to your EU bank via open banking and imports your transactions into a self-hosted [Actual Budget](https://actualbudget.org/) instance once a day. It runs on your own machine — your financial data never touches any third-party server.

---

## What you get

- **Daily automatic sync** — transactions land in Actual Budget once a day, at a time you choose
- **2,500+ European banks** — Revolut, N26, Monzo, Wise, Millennium BCP, Santander, ING, BNP Paribas, and more across 29 countries
- **Read-only, always** — Bridge Bank can never move money or modify your account
- **Pending transaction tracking** — pending transactions are imported as uncleared and automatically confirmed when they settle
- **Duplicate detection** — Bridge Bank tracks every transaction ID so nothing gets imported twice
- **Email notifications** — an alert if something goes wrong, and a warning before your bank session expires
- **Your data, your machine** — bank data goes directly from Enable Banking to your machine, never our servers
- **Lightweight** — runs as a single Docker container

---

## Requirements

- Docker and Docker Compose
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
2. Go to **API applications** and create a new application — name it `Bridge Bank`
3. Set the redirect URL to `https://bridgebank.app/callback`
4. Under **Keys**, select **Generate in the browser** and click **Register** — your application will be created and a `.pem` file will be automatically saved to your Downloads folder. The filename will match your Application ID (e.g. `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.pem`)

### 3. Install Bridge Bank

**On your server**, create the folder and download the compose file:
```bash
mkdir -p ~/bridge-bank/data && cd ~/bridge-bank
curl -O https://raw.githubusercontent.com/DAdjadj/bridge-bank/main/docker-compose.yml
```

**On your local machine**, upload the private key to your server. The filename matches your Enable Banking Application ID (e.g. `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.pem`):
```bash
scp ~/Downloads/your-app-id.pem user@your-server:~/bridge-bank/data/your-app-id.pem
```

**Back on your server**, start the container:
```bash
docker compose up -d
```

Open **http://your-server-address:3002** in your browser. The setup wizard will guide you through the rest.

---

## Setup wizard

The browser-based wizard walks you through four steps:

1. **License** — enter your key to activate Bridge Bank on this machine
2. **Actual Budget** — enter your Actual Budget URL, password, Sync ID, account name, and the date to start syncing from
3. **Notifications** — set your email, SMTP credentials, and daily sync time
4. **Bank** — connect your bank via Enable Banking OAuth (one-time, browser-based)

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
