# tests/unit/api/test_download_api.py

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import from the package structure
from workbench_agent.api.download_api import DownloadAPI
from workbench_agent.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    ConfigurationError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectExistsError,
    ProjectNotFoundError,
    ScanExistsError,
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
def download_api_inst(mock_session):
    """Create a DownloadAPI instance with a properly mocked session."""

    # DownloadAPI is a mixin class that expects to be mixed into a class with required attributes
    # Create a mock class with the required attributes
    class MockDownloadAPI(DownloadAPI):
        def __init__(self):
            self.api_url = "http://dummy.com/api.php"
            self.api_user = "testuser"
            self.api_token = "testtoken"
            self.session = mock_session

    return MockDownloadAPI()


# --- Test Cases ---


def test_download_report_success(download_api_inst, mock_session):
    """Test successful report download."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {
        "content-type": "application/pdf",
        "content-disposition": "attachment; filename=report.pdf",
    }
    mock_response.raise_for_status.return_value = None

    # Use the mock_session directly
    mock_session.post.return_value = mock_response

    result = download_api_inst._download_report("scans", 12345)

    assert result == mock_response
    mock_session.post.assert_called_once()

    # Verify post call arguments
    args, kwargs = mock_session.post.call_args
    assert kwargs.get("stream") is True
    assert kwargs.get("timeout") == 1800

    # Verify the request data contains the expected payload
    request_data = kwargs.get("data", "")
    assert "download_report" in request_data
    assert '"process_id": "12345"' in request_data
    assert '"report_entity": "scans"' in request_data


def test_download_report_api_error_with_json(download_api_inst, mock_session):
    """Test download when API returns JSON error."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"status": "0", "error": "Report not found"}

    mock_session.post.return_value = mock_response

    # The actual implementation wraps this in a generic error message
    with pytest.raises(
        ApiError, match="Unexpected error during report download \\(process ID 12345\\)"
    ):
        download_api_inst._download_report("scans", 12345)


def test_download_report_api_error_invalid_json(download_api_inst, mock_session):
    """Test download when API returns invalid JSON."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_response.text = "Invalid JSON response"

    mock_session.post.return_value = mock_response

    # The actual implementation wraps this in a generic error message
    with pytest.raises(
        ApiError, match="Unexpected error during report download \\(process ID 12345\\)"
    ):
        download_api_inst._download_report("scans", 12345)


def test_download_report_network_error(download_api_inst, mock_session):
    """Test download when network request fails."""
    mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection failed")

    with pytest.raises(
        NetworkError, match="Failed to download report \\(process ID 12345\\): Connection failed"
    ):
        download_api_inst._download_report("scans", 12345)


def test_download_report_http_error(download_api_inst, mock_session):
    """Test download when HTTP request returns error status."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 404
    mock_response.headers = {"content-type": "text/html"}  # Add headers attribute
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")

    mock_session.post.return_value = mock_response

    with pytest.raises(
        NetworkError, match="Failed to download report \\(process ID 12345\\): 404 Not Found"
    ):
        download_api_inst._download_report("scans", 12345)


def test_download_report_with_content_disposition(download_api_inst, mock_session):
    """Test download with proper content-disposition header."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {
        "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "content-disposition": 'attachment; filename="project_report.xlsx"',
    }
    mock_response.raise_for_status.return_value = None

    mock_session.post.return_value = mock_response

    result = download_api_inst._download_report("projects", 54321)

    assert result == mock_response
    mock_session.post.assert_called_once()


def test_download_report_without_content_disposition_but_binary_type(
    download_api_inst, mock_session
):
    """Test download with binary content type but no content-disposition."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/octet-stream"}
    mock_response.raise_for_status.return_value = None

    mock_session.post.return_value = mock_response

    result = download_api_inst._download_report("scans", 12345)

    assert result == mock_response
    mock_session.post.assert_called_once()


def test_download_report_unexpected_error(download_api_inst, mock_session):
    """Test download when unexpected error occurs."""
    mock_session.post.side_effect = ValueError("Unexpected error")

    with pytest.raises(
        ApiError, match="Unexpected error during report download \\(process ID 12345\\)"
    ):
        download_api_inst._download_report("scans", 12345)


def test_download_api_initialization(download_api_inst):
    """Test that DownloadAPI can be initialized properly."""
    assert download_api_inst.api_url == "http://dummy.com/api.php"
    assert download_api_inst.api_user == "testuser"
    assert download_api_inst.api_token == "testtoken"
    assert download_api_inst.session is not None
