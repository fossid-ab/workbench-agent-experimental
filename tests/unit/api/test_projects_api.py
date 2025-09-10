# tests/unit/api/test_projects_api.py

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import from the package structure
from workbench_agent.api.projects_api import ProjectsAPI
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
def projects_api_inst(mock_session):
    """Create a ProjectsAPI instance with a properly mocked session."""
    # Create a new instance with required parameters
    api = ProjectsAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    # Replace the session with our mock
    api.session = mock_session
    return api


# --- Test Cases ---


# --- Test create_project ---
@patch.object(ProjectsAPI, "list_projects", return_value=[])
@patch.object(ProjectsAPI, "_send_request")
def test_create_project_success(mock_send, mock_list_projects, projects_api_inst):
    # Configure the API response for project creation
    mock_send.return_value = {"status": "1", "data": {"project_code": "NEW_PROJ"}}

    result = projects_api_inst.create_project("New Project")

    # Verify the result
    assert result == "NEW_PROJ"

    # Verify _send_request was called with correct parameters
    assert mock_send.call_count >= 1  # At least one call
    # Find the create call
    create_call = None
    for call in mock_send.call_args_list:
        payload = call[0][0]
        if payload.get("action") == "create":
            create_call = payload
            break

    assert create_call is not None, "No create action call was made"
    assert create_call["group"] == "projects"
    assert create_call["data"]["project_name"] == "New Project"


@patch.object(ProjectsAPI, "list_projects")
def test_create_project_already_exists(mock_list_proj, projects_api_inst):
    # Setup projects list with existing project
    mock_list_proj.return_value = [{"name": "New Project", "code": "EXISTING_PROJ"}]

    # Should raise ProjectExistsError
    with pytest.raises(ProjectExistsError, match="Project 'New Project' already exists"):
        projects_api_inst.create_project("New Project")

    mock_list_proj.assert_called_once()


# --- Test list_projects ---
@patch.object(ProjectsAPI, "_send_request")
def test_list_projects_success(mock_send, projects_api_inst):
    mock_send.return_value = {
        "status": "1",
        "data": [{"name": "Project A", "code": "PROJ_A"}, {"name": "Project B", "code": "PROJ_B"}],
    }
    projects = projects_api_inst.list_projects()
    assert len(projects) == 2
    assert projects[0]["name"] == "Project A"
    assert projects[1]["code"] == "PROJ_B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "list_projects"


@patch.object(ProjectsAPI, "_send_request")
def test_list_projects_empty(mock_send, projects_api_inst):
    mock_send.return_value = {"status": "1", "data": []}
    projects = projects_api_inst.list_projects()
    assert projects == []


@patch.object(ProjectsAPI, "_send_request")
def test_list_projects_api_error(mock_send, projects_api_inst):
    mock_send.return_value = {"status": "0", "error": "API error"}
    with pytest.raises(ApiError, match="Failed to list projects: API error"):
        projects_api_inst.list_projects()


# --- Test get_project_scans ---
@patch.object(ProjectsAPI, "_send_request")
def test_get_project_scans_success(mock_send, projects_api_inst):
    mock_send.return_value = {
        "status": "1",
        "data": [{"code": "SCAN_A", "name": "Scan A"}, {"code": "SCAN_B", "name": "Scan B"}],
    }
    scans = projects_api_inst.get_project_scans("PROJ_A")
    assert len(scans) == 2
    assert scans[0]["code"] == "SCAN_A"
    assert scans[1]["name"] == "Scan B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "get_all_scans"
    assert payload["data"]["project_code"] == "PROJ_A"


@patch.object(ProjectsAPI, "_send_request")
def test_get_project_scans_project_not_found(mock_send, projects_api_inst):
    mock_send.return_value = {"status": "0", "error": "Project code does not exist"}
    # Should return empty list, not raise
    scans = projects_api_inst.get_project_scans("NONEXISTENT")
    assert scans == []


# --- Test project report generation ---
@patch.object(ProjectsAPI, "_send_request")
def test_generate_project_report_success(mock_send, projects_api_inst):
    mock_send.return_value = {"status": "1", "data": {"process_queue_id": 54321}}
    result = projects_api_inst.generate_project_report(
        project_code="PROJ_A",
        report_type="xlsx",
        selection_type="include_all_licenses",
        disclaimer="Test disclaimer",
        include_vex=False,
    )
    assert result == 54321
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "generate_report"
    assert payload["data"]["project_code"] == "PROJ_A"
    assert payload["data"]["report_type"] == "xlsx"
    assert payload["data"]["async"] == "1"
    assert payload["data"]["selection_type"] == "include_all_licenses"
    assert payload["data"]["disclaimer"] == "Test disclaimer"
    assert payload["data"]["include_vex"] is False


@patch.object(ProjectsAPI, "_send_request")
def test_check_project_report_status_success(mock_send, projects_api_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "FINISHED", "progress": 100}}
    status = projects_api_inst.check_project_report_status(process_id=12345, project_code="PROJ_A")
    assert status["status"] == "FINISHED"
    assert status["progress"] == 100
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "check_status"
    assert payload["data"]["process_id"] == "12345"
    assert payload["data"]["type"] == "REPORT_GENERATION"


@patch.object(ProjectsAPI, "_send_request")
def test_download_project_report_success(mock_send, projects_api_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {
        "content-type": "application/pdf",
        "content-disposition": "attachment; filename=report.pdf",
    }

    # Use the mock_session directly
    mock_session.post.return_value = mock_response

    result = projects_api_inst.download_report(12345)

    assert result == mock_response
    mock_session.post.assert_called_once()

    # Verify post call arguments
    args, kwargs = mock_session.post.call_args
    assert kwargs.get("stream") is True
    assert "download_report" in str(kwargs.get("data", ""))
