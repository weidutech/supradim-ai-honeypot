from __future__ import annotations

import hashlib
import hmac
import secrets


class CanaryTokens:
    def __init__(self, secret_key: str):
        self.secret = secret_key.encode()

    def issue(self, session_id: str, purpose: str) -> str:
        nonce = secrets.token_hex(4)
        message = f"v2:{purpose}:{nonce}:{session_id}"
        signature = hmac.new(self.secret, message.encode(), hashlib.sha256).hexdigest()[:24]
        return f"{message}:{signature}"

    def verify(self, token: str, purpose: str) -> str | None:
        parts = token.split(":")
        if len(parts) == 5 and parts[0] == "v2":
            version, token_purpose, nonce, session_id, signature = parts
            if token_purpose != purpose:
                return None
            expected_msg = f"v2:{purpose}:{nonce}:{session_id}"
            expected_sig = hmac.new(self.secret, expected_msg.encode(), hashlib.sha256).hexdigest()[:24]
            if not hmac.compare_digest(signature, expected_sig):
                return None
            return session_id
        elif len(parts) == 4 and parts[0] == "v1":
            # Backward compatibility with v1 tokens
            version, token_purpose, session_id, signature = parts
            if token_purpose != purpose:
                return None
            expected_msg = f"v1:{purpose}:{session_id}"
            expected_sig = hmac.new(self.secret, expected_msg.encode(), hashlib.sha256).hexdigest()[:24]
            if not hmac.compare_digest(signature, expected_sig):
                return None
            return session_id
        return None

    def issue_session_token(self, session_id: str) -> str:
        """Sign a session_id into a tamper-proof session token."""
        sig = hmac.new(self.secret, f"sess:{session_id}".encode(), hashlib.sha256).hexdigest()[:24]
        return f"{session_id}.{sig}"

    def verify_session_token(self, token: str) -> str | None:
        """Verify and extract session_id from a session token."""
        try:
            session_id, sig = token.split(".", 1)
        except ValueError:
            return None
        expected = hmac.new(self.secret, f"sess:{session_id}".encode(), hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(sig, expected):
            return None
        return session_id

