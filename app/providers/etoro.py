import logging
from decimal import Decimal
import requests
from .base import BalanceProvider

log = logging.getLogger(__name__)


class EtoroProvider(BalanceProvider):
    name = "etoro"
    display_name = "eToro"
    credential_fields = [
        {"key": "api_key", "label": "API Key", "type": "password"},
    ]

    def validate_credentials(self, credentials: dict) -> bool:
        api_key = credentials.get("api_key", "")
        if not api_key:
            return False
        try:
            resp = requests.get(
                "https://api.etoro.com/api/v1/portfolio",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=15,
            )
            return resp.status_code == 200
        except Exception as e:
            log.warning("eToro credential validation failed: %s", e)
            return False

    def get_balance(self, credentials: dict) -> Decimal:
        api_key = credentials["api_key"]
        resp = requests.get(
            "https://api.etoro.com/api/v1/portfolio",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        # Sum all position CurrentValue fields
        total = Decimal("0")
        for position in data.get("positions", []):
            total += Decimal(str(position.get("CurrentValue", 0)))
        return total

    def get_currency(self, credentials: dict) -> str:
        return "USD"
