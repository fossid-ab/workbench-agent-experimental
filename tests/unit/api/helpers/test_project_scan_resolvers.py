# tests/unit/api/helpers/test_project_scan_resolvers.py

import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.helpers.project_scan_resolvers import ResolveWorkbenchProjectScan
from workbench_agent.exceptions import (
    ApiError,
    ConfigurationError,
    ProjectExistsError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
)


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock()
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def resolver_inst(mock_session):
    """Create a ResolveWorkbenchProjectScan instance with mocked methods."""
    resolver = ResolveWorkbenchProjectScan(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    resolver.session = mock_session

    # Mock the methods that would be inherited from other classes
    resolver.list_projects = MagicMock()
    resolver.create_project = MagicMock()
    resolver.get_project_scans = MagicMock()
    resolver.create_scan = MagicMock()
    resolver.list_scans = MagicMock()

    return resolver


# --- Test resolve_project ---
def test_resolve_project_existing(resolver_inst):
    """Test resolving an existing project."""
    # Mock project list with existing project
    resolver_inst.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"},
        {"project_name": "OtherProject", "project_code": "PROJ456"},
    ]

    result = resolver_inst.resolve_project("TestProject", create_if_missing=False)

    assert result == "PROJ123"
    resolver_inst.list_projects.assert_called_once()
    resolver_inst.create_project.assert_not_called()


def test_resolve_project_not_found_no_create(resolver_inst):
    """Test resolving non-existent project without creation."""
    resolver_inst.list_projects.return_value = [
        {"project_name": "OtherProject", "project_code": "PROJ456"}
    ]

    with pytest.raises(ProjectNotFoundError, match="Project 'NonExistent' not found"):
        resolver_inst.resolve_project("NonExistent", create_if_missing=False)


def test_resolve_project_create_success(resolver_inst):
    """Test resolving project with successful creation."""
    # First call returns empty list, second call returns created project
    resolver_inst.list_projects.side_effect = [
        [],  # First call - project doesn't exist
        [{"project_name": "NewProject", "project_code": "PROJ789"}],  # Second call after creation
    ]
    resolver_inst.create_project.return_value = "PROJ789"

    result = resolver_inst.resolve_project("NewProject", create_if_missing=True)

    assert result == "PROJ789"
    resolver_inst.create_project.assert_called_once_with("NewProject")


def test_resolve_project_create_race_condition(resolver_inst):
    """Test resolving project with race condition during creation."""
    # First call returns empty list
    resolver_inst.list_projects.side_effect = [
        [],  # First call - project doesn't exist
        [
            {"project_name": "RaceProject", "project_code": "PROJ999"}
        ],  # Second call after race condition
    ]
    resolver_inst.create_project.side_effect = ProjectExistsError("Project already exists")

    result = resolver_inst.resolve_project("RaceProject", create_if_missing=True)

    assert result == "PROJ999"
    resolver_inst.create_project.assert_called_once_with("RaceProject")
    assert resolver_inst.list_projects.call_count == 2


# --- Test resolve_scan ---
def test_resolve_scan_existing_in_project(resolver_inst):
    """Test resolving existing scan in specific project."""
    resolver_inst.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    resolver_inst.get_project_scans.return_value = [
        {"name": "TestScan", "code": "SCAN456", "id": "789"},
        {"name": "OtherScan", "code": "SCAN789", "id": "101"},
    ]

    params = argparse.Namespace(command="scan")
    result_code, result_id = resolver_inst.resolve_scan(
        scan_name="TestScan", project_name="TestProject", create_if_missing=False, params=params
    )

    assert result_code == "SCAN456"
    assert result_id == 789
    resolver_inst.get_project_scans.assert_called_once_with("PROJ123")


def test_resolve_scan_not_found_in_project(resolver_inst):
    """Test resolving non-existent scan in project."""
    resolver_inst.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    resolver_inst.get_project_scans.return_value = [
        {"name": "OtherScan", "code": "SCAN789", "id": "101"}
    ]

    params = argparse.Namespace(command="scan")

    with pytest.raises(
        ScanNotFoundError, match="Scan 'NonExistent' not found in project 'TestProject'"
    ):
        resolver_inst.resolve_scan(
            scan_name="NonExistent",
            project_name="TestProject",
            create_if_missing=False,
            params=params,
        )


def test_resolve_scan_create_in_project(resolver_inst):
    """Test creating scan in specific project."""
    resolver_inst.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    resolver_inst.get_project_scans.side_effect = [
        [],  # First call - scan doesn't exist
        [{"name": "NewScan", "code": "SCAN999", "id": "888"}],  # Second call after creation
    ]
    resolver_inst.create_scan.return_value = True

    params = argparse.Namespace(command="scan")

    with patch("time.sleep"):  # Mock sleep
        result_code, result_id = resolver_inst.resolve_scan(
            scan_name="NewScan", project_name="TestProject", create_if_missing=True, params=params
        )

    assert result_code == "SCAN999"
    assert result_id == 888
    resolver_inst.create_scan.assert_called_once()


def test_resolve_scan_global_search_single_result(resolver_inst):
    """Test global scan search with single result."""
    resolver_inst.list_scans.return_value = [
        {"name": "GlobalScan", "code": "SCAN111", "id": "222", "project_code": "PROJ123"}
    ]

    params = argparse.Namespace(command="scan")
    result_code, result_id = resolver_inst.resolve_scan(
        scan_name="GlobalScan", project_name=None, create_if_missing=False, params=params
    )

    assert result_code == "SCAN111"
    assert result_id == 222
    resolver_inst.list_scans.assert_called_once()


def test_resolve_scan_global_search_multiple_results(resolver_inst):
    """Test global scan search with multiple results."""
    resolver_inst.list_scans.return_value = [
        {"name": "DupeScan", "code": "SCAN111", "id": "222", "project_code": "PROJ123"},
        {"name": "DupeScan", "code": "SCAN333", "id": "444", "project_code": "PROJ456"},
    ]

    params = argparse.Namespace(command="scan")

    with pytest.raises(ValidationError, match="Multiple scans found with name 'DupeScan'"):
        resolver_inst.resolve_scan(
            scan_name="DupeScan", project_name=None, create_if_missing=False, params=params
        )


def test_resolve_scan_global_search_not_found(resolver_inst):
    """Test global scan search with no results."""
    resolver_inst.list_scans.return_value = []

    params = argparse.Namespace(command="scan")

    with pytest.raises(ScanNotFoundError, match="Scan 'NotFound' not found in any project"):
        resolver_inst.resolve_scan(
            scan_name="NotFound", project_name=None, create_if_missing=False, params=params
        )


def test_resolve_scan_global_create_not_allowed(resolver_inst):
    """Test global scan creation not allowed."""
    params = argparse.Namespace(command="scan")

    with pytest.raises(
        ConfigurationError, match="Cannot create a scan without specifying a project"
    ):
        resolver_inst.resolve_scan(
            scan_name="NewScan", project_name=None, create_if_missing=True, params=params
        )


# --- Test _get_git_params ---
def test_get_git_params_scan_command(resolver_inst):
    """Test git parameters extraction for scan command."""
    params = argparse.Namespace(command="scan")

    result = resolver_inst._get_git_params(params)

    assert result == {}


def test_get_git_params_scan_git_command(resolver_inst):
    """Test git parameters extraction for scan-git command."""
    params = argparse.Namespace(
        command="scan-git",
        git_url="https://github.com/test/repo",
        git_branch="main",
        git_tag=None,
        git_depth=1,
    )

    result = resolver_inst._get_git_params(params)

    expected = {
        "git_url": "https://github.com/test/repo",
        "git_branch": "main",
        "git_tag": None,
        "git_depth": 1,
    }
    assert result == expected


def test_get_git_params_scan_git_with_tag(resolver_inst):
    """Test git parameters extraction for scan-git command with tag."""
    params = argparse.Namespace(
        command="scan-git",
        git_url="https://github.com/test/repo",
        git_branch=None,
        git_tag="v1.0.0",
        git_depth=5,
    )

    result = resolver_inst._get_git_params(params)

    expected = {
        "git_url": "https://github.com/test/repo",
        "git_branch": None,
        "git_tag": "v1.0.0",
        "git_depth": 5,
    }
    assert result == expected
