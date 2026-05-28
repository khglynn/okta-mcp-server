# The Okta software accompanied by this notice is provided pursuant to the
# following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import jwt
import keyring
import pytest

from okta_mcp_server.utils.auth.auth_manager import SERVICE_NAME, OktaAuthManager


@pytest.fixture()
def okta_env(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("OKTA_SCOPES", "okta.users.read")
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)


def _mock_keyring(monkeypatch, store):
    def get_password(service_name, key):
        assert service_name == SERVICE_NAME
        return store.get(key)

    def set_password(service_name, key, value):
        assert service_name == SERVICE_NAME
        store[key] = value

    monkeypatch.setattr(keyring, "get_password", get_password)
    monkeypatch.setattr(keyring, "set_password", set_password)


def _access_token(expires_in_seconds: int, scopes: list[str] | None = None) -> str:
    return jwt.encode(
        {
            "exp": int(time.time()) + expires_in_seconds,
            "scp": scopes if scopes is not None else ["okta.users.read"],
        },
        "test-secret",
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_ensure_authenticated_reuses_valid_cached_access_token(monkeypatch, okta_env):
    store = {"api_token": _access_token(900)}
    _mock_keyring(monkeypatch, store)

    manager = OktaAuthManager()
    manager.refresh_access_token = MagicMock(return_value=True)
    manager.authenticate = AsyncMock()

    assert await manager.ensure_authenticated()
    manager.refresh_access_token.assert_not_called()
    manager.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_authenticated_refreshes_expired_cached_access_token(monkeypatch, okta_env):
    store = {
        "api_token": _access_token(-60),
        "refresh_token": "refresh-token",
    }
    _mock_keyring(monkeypatch, store)

    manager = OktaAuthManager()
    manager.refresh_access_token = MagicMock(return_value=True)
    manager.authenticate = AsyncMock()

    assert await manager.ensure_authenticated()
    manager.refresh_access_token.assert_called_once_with()
    manager.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_authenticated_refreshes_cached_token_with_missing_scope(monkeypatch, okta_env):
    store = {"api_token": _access_token(900, scopes=["okta.apps.read"])}
    _mock_keyring(monkeypatch, store)

    manager = OktaAuthManager()
    manager.refresh_access_token = MagicMock(return_value=True)
    manager.authenticate = AsyncMock()

    assert await manager.ensure_authenticated()
    manager.refresh_access_token.assert_called_once_with()
    manager.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_authenticated_opens_device_flow_only_when_refresh_fails(monkeypatch, okta_env):
    store = {}
    _mock_keyring(monkeypatch, store)

    manager = OktaAuthManager()
    manager.refresh_access_token = MagicMock(return_value=False)

    def authenticate():
        store["api_token"] = _access_token(900)

    manager.authenticate = AsyncMock(side_effect=authenticate)

    assert await manager.ensure_authenticated()
    manager.refresh_access_token.assert_called_once_with()
    manager.authenticate.assert_awaited_once_with()
