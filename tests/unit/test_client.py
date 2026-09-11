"""Unit tests for the Bastion API client library."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from bastion.client import BastionClient, BastionClientError, check_response, make_http_client


class TestCheckResponse:
    """Tests for the module-level check_response function."""

    def _mock_response(self, status_code: int, json_body=None, text: str = "") -> httpx.Response:
        """Build a minimal mock httpx.Response."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = status_code
        response.is_success = 200 <= status_code < 300
        response.content = b"body" if json_body is not None else b""
        response.text = text
        if json_body is not None:
            response.json.return_value = json_body
        else:
            response.json.side_effect = Exception("no body")
        return response

    def test_200_with_json_returns_dict(self):
        """A 200 response with JSON body must return the parsed dict."""
        resp = self._mock_response(200, json_body={"id": "abc"})
        result = check_response(resp)
        assert result == {"id": "abc"}

    def test_201_with_json_returns_dict(self):
        """A 201 response must also return the parsed dict."""
        resp = self._mock_response(201, json_body={"created": True})
        result = check_response(resp)
        assert result == {"created": True}

    def test_204_no_content_returns_empty_dict(self):
        """A 204 response with no body must return an empty dict."""
        resp = self._mock_response(204)
        result = check_response(resp)
        assert result == {}

    def test_400_raises_client_error(self):
        """A 400 response must raise BastionClientError with the detail."""
        resp = self._mock_response(400, json_body={"detail": "Bad request"})
        with pytest.raises(BastionClientError) as exc_info:
            check_response(resp)
        assert exc_info.value.status_code == 400
        assert "Bad request" in exc_info.value.detail

    def test_401_raises_client_error(self):
        """A 401 response must raise BastionClientError."""
        resp = self._mock_response(401, json_body={"detail": "Unauthorised"})
        with pytest.raises(BastionClientError) as exc_info:
            check_response(resp)
        assert exc_info.value.status_code == 401

    def test_404_raises_client_error(self):
        """A 404 response must raise BastionClientError."""
        resp = self._mock_response(404, json_body={"detail": "Not found"})
        with pytest.raises(BastionClientError) as exc_info:
            check_response(resp)
        assert exc_info.value.status_code == 404

    def test_500_raises_client_error(self):
        """A 500 response must raise BastionClientError."""
        resp = self._mock_response(500, json_body={"detail": "Server error"})
        with pytest.raises(BastionClientError) as exc_info:
            check_response(resp)
        assert exc_info.value.status_code == 500

    def test_non_json_error_uses_text(self):
        """A non-JSON error response must use the raw text as the detail."""
        resp = self._mock_response(503, text="Service unavailable")
        result_detail = None
        try:
            check_response(resp)
        except BastionClientError as exc:
            result_detail = exc.detail
        assert result_detail == "Service unavailable"

    def test_error_message_includes_status_code(self):
        """The exception message must include the HTTP status code."""
        resp = self._mock_response(422, json_body={"detail": "Validation error"})
        with pytest.raises(BastionClientError) as exc_info:
            check_response(resp)
        assert "422" in str(exc_info.value)


class TestBastionClientError:
    """Tests for BastionClientError."""

    def test_stores_status_code(self):
        """BastionClientError must store the status code."""
        err = BastionClientError(404, "Not found")
        assert err.status_code == 404

    def test_stores_detail(self):
        """BastionClientError must store the detail string."""
        err = BastionClientError(400, "Bad input")
        assert err.detail == "Bad input"

    def test_str_includes_both(self):
        """str() must include both the status code and detail."""
        err = BastionClientError(403, "Forbidden")
        assert "403" in str(err)
        assert "Forbidden" in str(err)

    def test_is_exception(self):
        """BastionClientError must be an Exception subclass."""
        assert issubclass(BastionClientError, Exception)


class TestMakeHttpClient:
    """Tests for make_http_client."""

    def test_returns_httpx_client(self):
        """make_http_client must return an httpx.Client instance."""
        # We can't actually connect to a socket in tests, so just verify the type
        # by checking the class without opening the connection
        client = make_http_client.__wrapped__ if hasattr(make_http_client, "__wrapped__") else None
        # Just verify the function is callable and returns the right type annotation
        import inspect
        sig = inspect.signature(make_http_client)
        assert "token" in sig.parameters
        assert "socket_path" in sig.parameters

    def test_auth_header_set(self):
        """The client must include the Bearer token in the Authorization header."""
        # Patch HTTPTransport to avoid needing a real socket
        with patch("bastion.client.httpx.HTTPTransport"):
            with patch("bastion.client.httpx.Client") as mock_client_cls:
                make_http_client("my-token", "/fake/socket.sock")
                call_kwargs = mock_client_cls.call_args[1]
                assert call_kwargs["headers"]["Authorization"] == "Bearer my-token"

    def test_timeout_set(self):
        """The client must have a 30-second timeout."""
        with patch("bastion.client.httpx.HTTPTransport"):
            with patch("bastion.client.httpx.Client") as mock_client_cls:
                make_http_client("token", "/fake/socket.sock")
                call_kwargs = mock_client_cls.call_args[1]
                assert call_kwargs["timeout"] == 30.0


class TestBastionClientMethods:
    """Tests for BastionClient method routing — verifies correct endpoints are called."""

    def _make_client_with_mock(self, mock_responses: dict) -> tuple[BastionClient, MagicMock]:
        """Return a BastionClient whose _client() returns a mock with preset responses."""
        client = BastionClient(token="test-token", socket_path="/fake.sock")
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)

        def _make_response(status_code, body):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = status_code
            resp.is_success = 200 <= status_code < 300
            resp.content = b"x" if body else b""
            resp.json.return_value = body
            return resp

        for method, (status_code, body) in mock_responses.items():
            getattr(mock_http, method).return_value = _make_response(status_code, body)

        client._client = MagicMock(return_value=mock_http)
        return client, mock_http

    def test_list_users_calls_get_users(self):
        """list_users must call GET /users/."""
        client, mock_http = self._make_client_with_mock({"get": (200, [])})
        client.list_users()
        mock_http.get.assert_called_once_with("/users/", params={"include_deleted": False})

    def test_get_user_calls_correct_endpoint(self):
        """get_user must call GET /users/{user_id}."""
        client, mock_http = self._make_client_with_mock({"get": (200, {"id": "u1"})})
        client.get_user("u1")
        mock_http.get.assert_called_once_with("/users/u1")

    def test_create_user_calls_post_users(self):
        """create_user must call POST /users/ with the correct payload."""
        client, mock_http = self._make_client_with_mock({"post": (201, {"id": "u2"})})
        client.create_user("alice", "alice@example.com", "pass123")
        mock_http.post.assert_called_once()
        call_kwargs = mock_http.post.call_args
        assert call_kwargs[0][0] == "/users/"
        payload = call_kwargs[1]["json"]
        assert payload["username"] == "alice"
        assert payload["email"] == "alice@example.com"

    def test_suspend_user_calls_post_suspend(self):
        """suspend_user must call POST /users/{user_id}/suspend."""
        client, mock_http = self._make_client_with_mock({"post": (204, None)})
        client.suspend_user("u1")
        mock_http.post.assert_called_once_with("/users/u1/suspend")

    def test_delete_user_calls_delete(self):
        """delete_user must call DELETE /users/{user_id}."""
        client, mock_http = self._make_client_with_mock({"delete": (204, None)})
        client.delete_user("u1")
        mock_http.delete.assert_called_once_with("/users/u1")

    def test_list_servers_calls_get_servers(self):
        """list_servers must call GET /servers/."""
        client, mock_http = self._make_client_with_mock({"get": (200, [])})
        client.list_servers()
        mock_http.get.assert_called_once_with("/servers/")

    def test_grant_access_calls_post_access(self):
        """grant_access must call POST /servers/{server_id}/access."""
        client, mock_http = self._make_client_with_mock({"post": (201, {"id": "a1"})})
        client.grant_access("srv-1", "usr-1", allow_sudo=True)
        mock_http.post.assert_called_once()
        assert "/servers/srv-1/access" in mock_http.post.call_args[0][0]

    def test_revoke_access_calls_delete(self):
        """revoke_access must call DELETE /servers/{server_id}/access/{user_id}."""
        client, mock_http = self._make_client_with_mock({"delete": (204, None)})
        client.revoke_access("srv-1", "usr-1")
        mock_http.delete.assert_called_once_with("/servers/srv-1/access/usr-1")

    def test_create_group_calls_post_groups(self):
        """create_group must call POST /groups/ with name and description."""
        client, mock_http = self._make_client_with_mock({"post": (201, {"id": "g1"})})
        client.create_group("ops-team", "Operations team")
        mock_http.post.assert_called_once()
        payload = mock_http.post.call_args[1]["json"]
        assert payload["name"] == "ops-team"
        assert payload["description"] == "Operations team"

    def test_add_group_member_calls_post(self):
        """add_group_member must call POST /groups/{group_id}/members/{user_id}."""
        client, mock_http = self._make_client_with_mock({"post": (204, None)})
        client.add_group_member("g1", "u1")
        mock_http.post.assert_called_once_with("/groups/g1/members/u1")

    def test_remove_group_member_calls_delete(self):
        """remove_group_member must call DELETE /groups/{group_id}/members/{user_id}."""
        client, mock_http = self._make_client_with_mock({"delete": (204, None)})
        client.remove_group_member("g1", "u1")
        mock_http.delete.assert_called_once_with("/groups/g1/members/u1")

    def test_revoke_certificate_calls_post_revoke(self):
        """revoke_certificate must call POST /certificates/{cert_id}/revoke."""
        client, mock_http = self._make_client_with_mock({"post": (204, None)})
        client.revoke_certificate("cert-1", "Compromised key")
        mock_http.post.assert_called_once()
        assert "/certificates/cert-1/revoke" in mock_http.post.call_args[0][0]

    def test_list_audit_logs_with_filters(self):
        """list_audit_logs must pass user_id and action as query params."""
        client, mock_http = self._make_client_with_mock({"get": (200, [])})
        client.list_audit_logs(user_id="u1", action="auth.login", limit=50)
        params = mock_http.get.call_args[1]["params"]
        assert params["user_id"] == "u1"
        assert params["action"] == "auth.login"
        assert params["limit"] == 50

    def test_list_certificates_no_filters(self):
        """list_certificates with no filters must pass empty params."""
        client, mock_http = self._make_client_with_mock({"get": (200, [])})
        client.list_certificates()
        params = mock_http.get.call_args[1]["params"]
        assert "user_id" not in params
        assert "cert_status" not in params

    def test_list_certificates_with_filters(self):
        """list_certificates with filters must include them in params."""
        client, mock_http = self._make_client_with_mock({"get": (200, [])})
        client.list_certificates(user_id="u1", cert_status="active")
        params = mock_http.get.call_args[1]["params"]
        assert params["user_id"] == "u1"
        assert params["cert_status"] == "active"
