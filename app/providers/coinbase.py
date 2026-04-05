import json
import logging
import time
from decimal import Decimal
import requests
from .base import BalanceProvider

log = logging.getLogger(__name__)

COINBASE_API = "https://api.coinbase.com"


class CoinbaseProvider(BalanceProvider):
    name = "coinbase"
    display_name = "Coinbase"
    credential_fields = [
        {"key": "api_key_name", "label": "API Key Name", "type": "text"},
        {"key": "private_key", "label": "Private Key (PEM)", "type": "password"},
    ]

    def _make_jwt(self, credentials: dict) -> str:
        import jwt as pyjwt
        import uuid
        key_name = credentials["api_key_name"]
        private_key = credentials["private_key"]
        now = int(time.time())
        payload = {
            "sub": key_name,
            "iss": "cdp",
            "aud": ["cdp_service"],
            "nbf": now,
            "exp": now + 120,
            "uris": [],
        }
        headers = {
            "kid": key_name,
            "nonce": str(uuid.uuid4()),
            "typ": "JWT",
        }
        return pyjwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    def _get(self, path: str, credentials: dict) -> dict:
        token = self._make_jwt(credentials)
        resp = requests.get(
            f"{COINBASE_API}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def validate_credentials(self, credentials: dict) -> bool:
        if not credentials.get("api_key_name") or not credentials.get("private_key"):
            return False
        try:
            self._get("/v2/accounts?limit=1", credentials)
            return True
        except Exception as e:
            log.warning("Coinbase credential validation failed: %s", e)
            return False

    def get_balance(self, credentials: dict) -> Decimal:
        total = Decimal("0")
        path = "/v2/accounts?limit=100"
        while path:
            data = self._get(path, credentials)
            for account in data.get("data", []):
                native = account.get("native_balance", {})
                amount = native.get("amount", "0")
                total += Decimal(amount)
            pagination = data.get("pagination", {})
            path = pagination.get("next_uri")
        return total

    def get_currency(self, credentials: dict) -> str:
        data = self._get("/v2/accounts?limit=1", credentials)
        accounts = data.get("data", [])
        if accounts:
            return accounts[0].get("native_balance", {}).get("currency", "USD")
        return "USD"
