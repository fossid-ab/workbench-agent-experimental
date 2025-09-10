# tests/unit/api/test_vulnerabilities_api.py

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import from the package structure
from workbench_agent.api.vulnerabilities_api import VulnerabilitiesAPI
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
def vulnerabilities_api_inst(mock_session):
    """Create a VulnerabilitiesAPI instance with a properly mocked session."""
    # Create a new instance with required parameters
    api = VulnerabilitiesAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    # Replace the session with our mock
    api.session = mock_session
    return api


# --- Test Cases ---


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_with_data(mock_send, vulnerabilities_api_inst):
    # Mock the count request
    count_response = {"status": "1", "data": {"count_results": 2}}

    # Mock the paginated data request
    page_response = {
        "status": "1",
        "data": {
            "list": [
                {"id": 1, "severity": "HIGH", "component": "libxml2", "version": "2.9.0"},
                {"id": 2, "severity": "MEDIUM", "component": "openssl", "version": "1.0.1"},
            ]
        },
    }

    # Set up the mock to return different responses for each call
    mock_send.side_effect = [count_response, page_response]

    vulnerabilities = vulnerabilities_api_inst.list_vulnerabilities("scan1")

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0]["id"] == 1
    assert vulnerabilities[0]["severity"] == "HIGH"
    assert vulnerabilities[1]["component"] == "openssl"

    # Verify the mock was called correctly
    assert mock_send.call_count == 2

    # Check the first call (count request)
    first_call = mock_send.call_args_list[0][0][0]
    assert first_call["group"] == "vulnerabilities"
    assert first_call["action"] == "list_vulnerabilities"
    assert first_call["data"]["scan_code"] == "scan1"
    assert first_call["data"]["count_results"] == 1

    # Check the second call (data request)
    second_call = mock_send.call_args_list[1][0][0]
    assert second_call["group"] == "vulnerabilities"
    assert second_call["action"] == "list_vulnerabilities"
    assert second_call["data"]["scan_code"] == "scan1"
    assert second_call["data"]["page"] == 1


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_empty(mock_send, vulnerabilities_api_inst):
    # Mock the count request to return 0 vulnerabilities
    count_response = {"status": "1", "data": {"count_results": 0}}
    mock_send.return_value = count_response

    vulnerabilities = vulnerabilities_api_inst.list_vulnerabilities("scan1")

    assert vulnerabilities == []
    assert mock_send.call_count == 1

    # Verify only the count request was made
    call_args = mock_send.call_args[0][0]
    assert call_args["data"]["count_results"] == 1


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_multiple_pages(mock_send, vulnerabilities_api_inst):
    # Mock count response indicating 150 vulnerabilities (2 pages at 100 per page)
    count_response = {"status": "1", "data": {"count_results": 150}}

    # Mock page 1 response
    page1_response = {
        "status": "1",
        "data": {"list": [{"id": i, "severity": "HIGH"} for i in range(100)]},
    }

    # Mock page 2 response
    page2_response = {
        "status": "1",
        "data": {"list": [{"id": i, "severity": "MEDIUM"} for i in range(100, 150)]},
    }

    # Set up the mock to return different responses for each call
    mock_send.side_effect = [count_response, page1_response, page2_response]

    vulnerabilities = vulnerabilities_api_inst.list_vulnerabilities("scan1")

    assert len(vulnerabilities) == 150
    assert vulnerabilities[0]["id"] == 0
    assert vulnerabilities[99]["id"] == 99
    assert vulnerabilities[100]["id"] == 100
    assert vulnerabilities[149]["id"] == 149

    # Verify all calls were made
    assert mock_send.call_count == 3


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_count_api_error(mock_send, vulnerabilities_api_inst):
    # Mock the count request to fail
    count_response = {"status": "0", "error": "Scan not found"}
    mock_send.return_value = count_response

    with pytest.raises(
        ApiError, match="Failed to get vulnerability count for scan 'scan1': Scan not found"
    ):
        vulnerabilities_api_inst.list_vulnerabilities("scan1")


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_page_api_error(mock_send, vulnerabilities_api_inst):
    # Mock the count to succeed but page request to fail
    count_response = {"status": "1", "data": {"count_results": 50}}
    page_error_response = {"status": "0", "error": "Page not found"}

    mock_send.side_effect = [count_response, page_error_response]

    with pytest.raises(
        ApiError, match="Failed to fetch vulnerabilities page 1 for scan 'scan1': Page not found"
    ):
        vulnerabilities_api_inst.list_vulnerabilities("scan1")


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_unexpected_data_format(mock_send, vulnerabilities_api_inst):
    # Mock count response
    count_response = {"status": "1", "data": {"count_results": 1}}

    # Mock page response with unexpected data format
    page_response = {
        "status": "1",
        "data": {"list": "not_a_list"},  # Should be a list but it's a string
    }

    mock_send.side_effect = [count_response, page_response]

    # Should handle gracefully and log warning
    vulnerabilities = vulnerabilities_api_inst.list_vulnerabilities("scan1")

    # Should still return empty list despite bad data
    assert vulnerabilities == []


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_empty_page_data(mock_send, vulnerabilities_api_inst):
    # Mock count response
    count_response = {"status": "1", "data": {"count_results": 50}}

    # Mock page response with empty/unexpected data
    page_response = {"status": "1", "data": {}}

    mock_send.side_effect = [count_response, page_response]

    # Should handle gracefully and continue
    vulnerabilities = vulnerabilities_api_inst.list_vulnerabilities("scan1")

    assert vulnerabilities == []
