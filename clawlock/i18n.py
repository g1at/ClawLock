"""ClawLock i18n — lightweight bilingual support (zh/en)."""

from __future__ import annotations

import os

_LANG = os.environ.get("CLAWLOCK_LANG", "").lower()
if not _LANG:
    import locale

    _LANG = "en" if (locale.getdefaultlocale()[0] or "").startswith("en") else "zh"


def t(zh: str, en: str) -> str:
    """Return *en* when the active language is English, otherwise *zh*."""
    return en if _LANG.startswith("en") else zh
