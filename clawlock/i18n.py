"""ClawLock i18n - lightweight bilingual support (zh/en)."""

from __future__ import annotations

import os


def current_lang() -> str:
    """Return the normalized CLI language code."""
    return os.environ.get("CLAWLOCK_LANG", "").strip().lower()


def t(zh: str, en: str) -> str:
    """Return *zh* only when CLAWLOCK_LANG=zh, otherwise return *en*."""
    return zh if current_lang() == "zh" else en
