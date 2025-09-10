# tests/unit/api/helpers/test_api_base.py

import json
import time
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    ConfigurationError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def api_base_inst(mock_session):
    """Create an BaseAPI instance with a properly mocked session."""
    # Create a new instance
    api_base = BaseAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    # Replace the session with our mock
    api_base.session = mock_session
    return api_base


# --- Test BaseAPI init ---
def test_api_base_init_url_fix():
    api_base = BaseAPI(api_url="http://dummy.com", api_user="user", api_token="token")
    assert api_base.api_url == "http://dummy.com/api.php"


def test_api_base_init_url_correct():
    api_base = BaseAPI(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert api_base.api_url == "http://dummy.com/api.php"


# --- Test _send_request ---
def test_send_request_success(api_base_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"status": "1", "data": {"key": "value"}}
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "test"}
    result = api_base_inst._send_request(payload)
    mock_session.post.assert_called_once()
    assert result == {"status": "1", "data": {"key": "value"}}


def test_send_request_api_error(api_base_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {
        "status": "0",
        "error": "A generic failure",
    }  # API error status
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "fail"}
    with pytest.raises(ApiError, match="A generic failure"):
        api_base_inst._send_request(payload)


def test_send_request_network_error(api_base_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.ConnectionError("Failed to connect")
    payload = {"group": "test", "action": "connectfail"}
    with pytest.raises(NetworkError, match="Connection error:"):
        api_base_inst._send_request(payload)


def test_send_request_timeout(api_base_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.Timeout("Request timed out")
    payload = {"group": "test", "action": "timeout"}
    with pytest.raises(NetworkError, match="Request timeout after"):
        api_base_inst._send_request(payload)


def test_send_request_json_decode_error(api_base_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}  # Claims JSON
    mock_response.text = "This is not JSON"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "This is not JSON", 0)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "badjson"}
    with pytest.raises(ApiError, match="Invalid JSON response:"):
        api_base_inst._send_request(payload)


def test_send_request_sync_response(api_base_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html"}
    mock_response.content = b"<html>Report Content</html>"
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "sync"}
    result = api_base_inst._send_request(payload)
    assert "_raw_response" in result
    assert result["_raw_response"] == mock_response


def test_send_request_http_error(api_base_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 401  # Unauthorized
    mock_response.headers = {}  # Add this line to avoid AttributeError
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "401 Client Error", response=mock_response
    )
    mock_session.post.return_value = mock_response

    payload = {"group": "test", "action": "authfail"}
    try:
        api_base_inst._send_request(payload)
        pytest.fail("Expected AuthenticationError to be raised")
    except AuthenticationError as e:
        # This will pass if the exception is raised with the correct type
        assert "Invalid credentials or expired token" in str(e)


def test_send_request_git_repository_access_error(api_base_inst, mock_session):
    """Test detection of Git repository access errors."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {
        "status": "0",
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [
            {
                "code": "RequestData.Base.issue_with_executing_command",
                "message": "Field git_repo_url: there was an issue executing command: timeout 200 git ls-remote 'https://github.com/fake/repo' 2>&1.",
                "message_parameters": {
                    "fieldname": "git_repo_url",
                    "cmd": "timeout 200 git ls-remote 'https://github.com/fake/repo' 2>&1",
                    "exitStatus": 128,
                    "out": "fatal: could not read Username for 'https://github.com': No such device or address",
                },
            }
        ],
    }
    mock_session.post.return_value = mock_response

    payload = {
        "group": "scans",
        "action": "create",
        "data": {"git_repo_url": "https://github.com/fake/repo"},
    }

    with pytest.raises(ApiError) as exc_info:
        api_base_inst._send_request(payload)

    assert "RequestData.Base.issues_while_parsing_request" in str(exc_info.value)
    # The API error should contain the parsing issue message
