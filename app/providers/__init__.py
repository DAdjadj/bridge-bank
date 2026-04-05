from .base import BalanceProvider
from .etoro import EtoroProvider
from .binance import BinanceProvider
from .coinbase import CoinbaseProvider

PROVIDERS = {
    "etoro": EtoroProvider,
    "binance": BinanceProvider,
    "coinbase": CoinbaseProvider,
}


def get_provider(name: str) -> BalanceProvider:
    cls = PROVIDERS.get(name)
    if not cls:
        raise ValueError(f"Unknown provider: {name}")
    return cls()


def get_all_providers() -> list[dict]:
    """Return provider metadata for the UI."""
    result = []
    for key, cls in PROVIDERS.items():
        p = cls()
        result.append({
            "key": key,
            "display_name": p.display_name,
            "credential_fields": p.credential_fields,
        })
    return result
