import hashlib
import hmac
import logging
import time
from decimal import Decimal, ROUND_HALF_UP
import requests
from .base import BalanceProvider
from .etoro import _usd_to_eur

log = logging.getLogger(__name__)

BINANCE_API = "https://api.binance.com"


def _sign(query_string: str, secret: str) -> str:
    return hmac.new(secret.encode(), query_string.encode(), hashlib.sha256).hexdigest()


class BinanceProvider(BalanceProvider):
    name = "binance"
    display_name = "Binance"
    credential_fields = [
        {"key": "api_key", "label": "API Key", "type": "password",
         "help": "Go to Binance \u2192 Account \u2192 API Management \u2192 Create API. Enable 'Read' only (no trading/withdrawal).",
         "help_url": "https://www.binance.com/en/my/settings/api-management"},
        {"key": "api_secret", "label": "API Secret", "type": "password",
         "help": "Shown once when you create the API key. Copy it before closing the dialog."},
    ]

    def _headers(self, credentials: dict) -> dict:
        return {"X-MBX-APIKEY": credentials["api_key"]}

    def _signed_request(self, endpoint: str, credentials: dict) -> dict:
        timestamp = int(time.time() * 1000)
        query = f"timestamp={timestamp}"
        signature = _sign(query, credentials["api_secret"])
        url = f"{BINANCE_API}{endpoint}?{query}&signature={signature}"
        resp = requests.get(url, headers=self._headers(credentials), timeout=15)
        resp.raise_for_status()
        return resp.json()

    def validate_credentials(self, credentials: dict) -> bool:
        if not credentials.get("api_key") or not credentials.get("api_secret"):
            return False
        try:
            self._signed_request("/api/v3/account", credentials)
            return True
        except Exception as e:
            log.warning("Binance credential validation failed: %s", e)
            return False

    def get_balance(self, credentials: dict) -> Decimal:
        account = self._signed_request("/api/v3/account", credentials)
        # Get all non-zero balances
        assets = [
            b for b in account.get("balances", [])
            if Decimal(b["free"]) + Decimal(b["locked"]) > 0
        ]
        if not assets:
            return Decimal("0")

        # Fetch prices to convert to USDT
        prices_resp = requests.get(f"{BINANCE_API}/api/v3/ticker/price", timeout=15)
        prices_resp.raise_for_status()
        price_map = {p["symbol"]: Decimal(p["price"]) for p in prices_resp.json()}

        total = Decimal("0")
        for b in assets:
            asset = b["asset"]
            amount = Decimal(b["free"]) + Decimal(b["locked"])
            if asset in ("USDT", "BUSD", "USD"):
                total += amount
            elif f"{asset}USDT" in price_map:
                total += amount * price_map[f"{asset}USDT"]
            elif f"{asset}BUSD" in price_map:
                total += amount * price_map[f"{asset}BUSD"]

        # Convert USDT total to EUR
        rate = _usd_to_eur()
        total_eur = (total * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        log.info("Binance: %s USDT * %s = %s EUR", total, rate, total_eur)
        return total_eur

    def get_currency(self, credentials: dict) -> str:
        return "EUR"
