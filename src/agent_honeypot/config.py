from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_path: Path
    secret_key: str
    soc_api_key: str = "aisoc"
    cookie_name: str = "ah_session"
    cookie_secure: bool = False
    max_body_bytes: int = 65536  # 64 KB
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"

    @classmethod
    def from_env(cls) -> "Settings":
        database_path = Path(os.getenv("AGENT_HONEYPOT_DB", "agent_honeypot.db"))
        secret_key = os.getenv("AGENT_HONEYPOT_SECRET") or secrets.token_hex(32)
        soc_api_key = os.getenv("AGENT_HONEYPOT_SOC_KEY") or "aisoc"
        cookie_secure = os.getenv("AGENT_HONEYPOT_COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
        max_body_bytes = int(os.getenv("AGENT_HONEYPOT_MAX_BODY_BYTES", "65536"))
        deepseek_api_key = os.getenv("DEEPSEEK_API_KEY", "")
        deepseek_base_url = os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
        deepseek_model = os.getenv("DEEPSEEK_MODEL") or "deepseek-chat"
        return cls(
            database_path=database_path,
            secret_key=secret_key,
            soc_api_key=soc_api_key,
            cookie_name=os.getenv("AGENT_HONEYPOT_COOKIE_NAME", "ah_session"),
            cookie_secure=cookie_secure,
            max_body_bytes=max_body_bytes,
            deepseek_api_key=deepseek_api_key,
            deepseek_base_url=deepseek_base_url,
            deepseek_model=deepseek_model,
        )
