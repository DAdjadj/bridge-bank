from decimal import Decimal


class BalanceProvider:
    name: str = ""
    display_name: str = ""
    credential_fields: list[dict] = []

    def validate_credentials(self, credentials: dict) -> bool:
        """Test that the provided credentials work. Called during setup."""
        raise NotImplementedError

    def get_balance(self, credentials: dict) -> Decimal:
        """Fetch current total portfolio/account value in minor units (cents)."""
        raise NotImplementedError

    def get_currency(self, credentials: dict) -> str:
        """Return the account currency code (e.g. 'USD', 'EUR')."""
        return "EUR"
