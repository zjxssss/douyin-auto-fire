import json

import pytest
from cryptography.fernet import Fernet

from app.cloud_auth import (CloudAuthError, decrypt_bytes, encrypt_bytes,
                            save_cloud_state, validate_state)


@pytest.fixture(autouse=True)
def state_key(monkeypatch):
    monkeypatch.setenv("DOUYIN_STATE_KEY", Fernet.generate_key().decode("ascii"))


def test_encryption_hides_credentials_and_preserves_content():
    data = b'{"secret-cookie":"private-value"}'
    encrypted = encrypt_bytes(data, "browser-state")
    assert b"private-value" not in encrypted
    assert decrypt_bytes(encrypted, "browser-state") == data


def test_rejects_tampering_wrong_key_and_wrong_purpose(monkeypatch):
    encrypted = encrypt_bytes(b"private", "browser-state")
    for blob, purpose in [(encrypted[:-8] + b"changed!", "browser-state"),
                          (encrypted, "login-screen")]:
        with pytest.raises(CloudAuthError):
            decrypt_bytes(blob, purpose)
    monkeypatch.setenv("DOUYIN_STATE_KEY", Fernet.generate_key().decode())
    with pytest.raises(CloudAuthError):
        decrypt_bytes(encrypted, "browser-state")


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("DOUYIN_STATE_KEY")
    with pytest.raises(CloudAuthError, match="DOUYIN_STATE_KEY"):
        encrypt_bytes(b"private", "browser-state")


@pytest.mark.parametrize("state", [None, [], {}, {"cookies": [], "origins": "invalid"}])
def test_invalid_storage_state_rejected(state):
    with pytest.raises(CloudAuthError):
        validate_state(state)


@pytest.mark.asyncio
async def test_storage_state_saved_encrypted_with_indexed_db(tmp_path):
    state = {"cookies": [{"name": "sessionid", "value": "private"}], "origins": []}

    class Context:
        async def storage_state(self, *, indexed_db):
            assert indexed_db is True
            return state

    path = tmp_path / "state.enc"
    await save_cloud_state(Context(), path)
    assert json.loads(decrypt_bytes(path.read_bytes(), "browser-state")) == state
    assert list(tmp_path.iterdir()) == [path]
