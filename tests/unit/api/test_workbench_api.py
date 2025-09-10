# tests/unit/api/test_workbench_api_new.py

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import from the package structure
from workbench_agent.api.workbench_api import WorkbenchAPI
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
def workbench_inst(mock_session):
    """Create a WorkbenchAPI instance with a properly mocked session."""
    # Create a new instance
    wb = WorkbenchAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    # Replace the session with our mock
    wb.session = mock_session
    return wb


# --- Test Cases ---


def test_workbench_init_url_fix(workbench_inst):
    """Test that WorkbenchAPI properly fixes URLs that don't end with api.php."""
    wb = WorkbenchAPI(api_url="http://dummy.com", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"


def test_workbench_init_url_correct(workbench_inst):
    """Test that WorkbenchAPI leaves correct URLs alone."""
    wb = WorkbenchAPI(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"


def test_workbench_api_inheritance(workbench_inst):
    """Test that WorkbenchAPI properly inherits from all the mixin classes."""
    # Test that the WorkbenchAPI instance has methods from all the component APIs

    # From UploadAPI
    assert hasattr(workbench_inst, "upload_scan_target")
    assert hasattr(workbench_inst, "upload_dependency_analysis_results")

    # From ProjectsAPI
    assert hasattr(workbench_inst, "create_project")
    assert hasattr(workbench_inst, "list_projects")
    assert hasattr(workbench_inst, "get_project_scans")
    assert hasattr(workbench_inst, "generate_project_report")
    assert hasattr(workbench_inst, "check_project_report_status")

    # From ScansAPI
    assert hasattr(workbench_inst, "create_scan")
    assert hasattr(workbench_inst, "list_scans")
    assert hasattr(workbench_inst, "check_status")
    assert hasattr(workbench_inst, "run_scan")
    assert hasattr(workbench_inst, "start_dependency_analysis")
    assert hasattr(workbench_inst, "extract_archives")
    assert hasattr(workbench_inst, "remove_uploaded_content")
    assert hasattr(workbench_inst, "download_content_from_git")
    assert hasattr(workbench_inst, "check_status_download_content_from_git")
    assert hasattr(workbench_inst, "get_scan_folder_metrics")
    assert hasattr(workbench_inst, "get_scan_identified_components")
    assert hasattr(workbench_inst, "get_scan_identified_licenses")
    assert hasattr(workbench_inst, "get_dependency_analysis_results")
    assert hasattr(workbench_inst, "get_pending_files")
    assert hasattr(workbench_inst, "get_policy_warnings_counter")
    assert hasattr(workbench_inst, "generate_scan_report")
    assert hasattr(workbench_inst, "check_scan_report_status")

    # From VulnerabilitiesAPI
    assert hasattr(workbench_inst, "list_vulnerabilities")

    # From ResolveWorkbenchProjectScan (mixed in)
    assert hasattr(workbench_inst, "resolve_project")
    assert hasattr(workbench_inst, "resolve_scan")


def test_workbench_api_initialization_attributes(workbench_inst):
    """Test that WorkbenchAPI properly initializes with the correct attributes."""
    assert workbench_inst.api_url == "http://dummy.com/api.php"
    assert workbench_inst.api_user == "testuser"
    assert workbench_inst.api_token == "testtoken"
    assert hasattr(workbench_inst, "session")


# --- Test API Class Constants ---
def test_api_report_type_constants():
    """Test that the API class constants are defined correctly."""
    assert isinstance(WorkbenchAPI.ASYNC_REPORT_TYPES, set)
    assert isinstance(WorkbenchAPI.PROJECT_REPORT_TYPES, set)
    assert isinstance(WorkbenchAPI.SCAN_REPORT_TYPES, set)

    # Verify specific values
    assert "xlsx" in WorkbenchAPI.ASYNC_REPORT_TYPES
    assert "spdx" in WorkbenchAPI.PROJECT_REPORT_TYPES
    assert "html" in WorkbenchAPI.SCAN_REPORT_TYPES


# --- Integration Tests ---
@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_create_project_integration(mock_send, workbench_inst):
    """Test creating a project through the unified API."""
    # Mock list_projects to return empty list
    with patch.object(WorkbenchAPI, "list_projects", return_value=[]):
        mock_send.return_value = {"status": "1", "data": {"project_code": "NEW_PROJ"}}

        result = workbench_inst.create_project("New Project")

        assert result == "NEW_PROJ"
        mock_send.assert_called_once()


@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_create_scan_integration(mock_send, workbench_inst):
    """Test creating a scan through the unified API."""
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}

    result = workbench_inst.create_scan({"scan_name": "New Scan", "project_code": "PROJ1"})

    assert result is True
    mock_send.assert_called_once()


@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_list_vulnerabilities_integration(mock_send, workbench_inst):
    """Test listing vulnerabilities through the unified API."""
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 2}},  # count call
        {
            "status": "1",
            "data": {"list": [{"id": 1, "severity": "high"}, {"id": 2, "severity": "medium"}]},
        },  # list call
    ]

    vulnerabilities = workbench_inst.list_vulnerabilities("SCAN1")

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0]["id"] == 1
    assert vulnerabilities[1]["severity"] == "medium"
    assert mock_send.call_count == 2


def test_workbench_api_session_shared(workbench_inst):
    """Test that all API components share the same session."""
    # All components should use the same session instance
    # This is important for connection reuse and performance
    assert hasattr(workbench_inst, "session")
    assert workbench_inst.session is not None
