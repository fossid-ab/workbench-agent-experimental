import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.exceptions import (
    ApiError,
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
from workbench_agent.utilities.scan_target_validators import (
    ensure_scan_compatibility,
    validate_reuse_source,
)


# --- Fixtures ---
@pytest.fixture
def mock_workbench(mocker):
    workbench = mocker.MagicMock()
    workbench.list_projects.return_value = [
        {
            "name": "test_project",
            "code": "TEST_PROJECT",
            "project_name": "test_project",
            "project_code": "TEST_PROJECT",
        }
    ]
    workbench.get_project_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123", "project_code": "TEST_PROJECT"}
    ]
    workbench.list_scans.return_value = [{"name": "test_scan", "code": "TEST_SCAN", "id": "123"}]
    workbench.assert_process_can_start = mocker.MagicMock(return_value=None)
    workbench.resolve_project = mocker.MagicMock()
    workbench.resolve_scan = mocker.MagicMock()
    return workbench


@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.command = None
    params.project_name = None
    params.scan_name = None
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_depth = None
    params.id_reuse = False
    params.id_reuse_type = None
    params.id_reuse_source = None
    return params


# --- Tests for ensure_scan_compatibility ---
def test_ensure_scan_compatibility_scan_command_success(mock_workbench, mock_params):
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    mock_params.command = "scan"
    ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")


def test_ensure_scan_compatibility_scan_git_command_success(mock_workbench, mock_params):
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None
    ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")


def test_ensure_scan_compatibility_scan_command_incompatible(mock_workbench, mock_params):
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.command = "scan"
    with pytest.raises(CompatibilityError, match=r"cannot be reused for code upload"):
        ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")


def test_ensure_scan_compatibility_scan_git_command_incompatible_url(mock_workbench, mock_params):
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/example/different.git"
    mock_params.git_branch = "main"
    with pytest.raises(CompatibilityError, match=r"configured for a different Git repository"):
        ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")


def test_ensure_scan_compatibility_scan_git_command_incompatible_ref_type(
    mock_workbench, mock_params
):
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_tag = "v1.0.0"
    with pytest.raises(CompatibilityError, match=r"exists with ref type"):
        ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")


def test_ensure_scan_compatibility_scan_not_found(mock_workbench, mock_params):
    mock_workbench.get_scan_information.side_effect = ScanNotFoundError("Scan not found")
    mock_params.command = "scan"
    # Should NOT raise, just log and return
    ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")


def test_ensure_scan_compatibility_api_error(mock_workbench, mock_params):
    mock_workbench.get_scan_information.side_effect = ApiError("API error")
    mock_params.command = "scan"
    # Should NOT raise, just log and return
    ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")


# --- Tests for validate_reuse_source ---
def test_validate_reuse_source_none_when_disabled(mock_workbench, mock_params):
    mock_params.id_reuse = False
    mock_params.id_reuse_type = None
    mock_params.id_reuse_source = None
    result = validate_reuse_source(mock_workbench, mock_params)
    assert result == (None, None)


def test_validate_reuse_source_project_success(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "test_project"
    mock_workbench.resolve_project.return_value = "TEST_PROJECT"
    result = validate_reuse_source(mock_workbench, mock_params)
    assert result == ("specific_project", "TEST_PROJECT")
    mock_workbench.resolve_project.assert_called_once_with("test_project", create_if_missing=False)


def test_validate_reuse_source_project_not_found(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "nonexistent_project"
    mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
    with pytest.raises(ValidationError, match="does not exist in Workbench"):
        validate_reuse_source(mock_workbench, mock_params)


def test_validate_reuse_source_scan_local_success(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "test_scan"
    mock_params.project_name = "test_project"
    mock_workbench.resolve_scan.return_value = ("TEST_SCAN", 123)
    result = validate_reuse_source(mock_workbench, mock_params)
    assert result == ("specific_scan", "TEST_SCAN")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="test_scan",
        project_name="test_project",
        create_if_missing=False,
        params=mock_params,
    )


def test_validate_reuse_source_scan_global_success(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "test_project:test_scan"
    mock_workbench.resolve_scan.return_value = ("TEST_SCAN", 123)
    result = validate_reuse_source(mock_workbench, mock_params)
    assert result == ("specific_scan", "TEST_SCAN")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="test_project:test_scan",
        project_name=None,
        create_if_missing=False,
        params=mock_params,
    )


def test_validate_reuse_source_scan_not_found(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "test_scan"
    mock_params.project_name = "test_project"
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
    with pytest.raises(ValidationError, match="does not exist in Workbench"):
        validate_reuse_source(mock_workbench, mock_params)


def test_validate_reuse_source_missing_source_project(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = None
    with pytest.raises(ConfigurationError, match="Missing project name"):
        validate_reuse_source(mock_workbench, mock_params)


def test_validate_reuse_source_missing_source_scan(mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = None
    with pytest.raises(ConfigurationError, match="Missing scan name"):
        validate_reuse_source(mock_workbench, mock_params)


# --- Tests for import-sbom compatibility ---
def test_ensure_scan_compatibility_import_sbom_with_report_scan_compatible(
    mock_workbench, mock_params
):
    """Test that import-sbom can reuse SBOM import scans."""
    mock_params.command = "import-sbom"
    mock_workbench.get_scan_information.return_value = {"is_from_report": "1"}

    ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")


def test_ensure_scan_compatibility_import_sbom_with_code_scan_incompatible(
    mock_workbench, mock_params
):
    """Test that import-sbom cannot reuse code upload scans."""
    mock_params.command = "import-sbom"
    mock_workbench.get_scan_information.return_value = {"is_from_report": "0", "git_repo_url": None}

    with pytest.raises(
        CompatibilityError,
        match="was not created for SBOM import and cannot be reused for SBOM import",
    ):
        ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")


def test_ensure_scan_compatibility_import_sbom_with_git_scan_incompatible(
    mock_workbench, mock_params
):
    """Test that import-sbom cannot reuse git scans."""
    mock_params.command = "import-sbom"
    mock_workbench.get_scan_information.return_value = {
        "is_from_report": "0",
        "git_repo_url": "https://github.com/test/repo.git",
    }

    with pytest.raises(
        CompatibilityError,
        match="was not created for SBOM import and cannot be reused for SBOM import",
    ):
        ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")


def test_ensure_scan_compatibility_scan_with_report_scan_incompatible(mock_workbench, mock_params):
    """Test that scan command cannot reuse SBOM import scans."""
    mock_params.command = "scan"
    mock_workbench.get_scan_information.return_value = {"is_from_report": "1"}

    with pytest.raises(
        CompatibilityError, match="was created for SBOM import and cannot be reused for code upload"
    ):
        ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")


def test_ensure_scan_compatibility_scan_git_with_report_scan_incompatible(
    mock_workbench, mock_params
):
    """Test that scan-git command cannot reuse SBOM import scans."""
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/test/repo.git"
    mock_params.git_branch = "main"
    mock_workbench.get_scan_information.return_value = {"is_from_report": "1"}

    with pytest.raises(
        CompatibilityError,
        match="was created for SBOM import and cannot be reused for Git scanning",
    ):
        ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")


def test_ensure_scan_compatibility_import_da_with_report_scan_incompatible(
    mock_workbench, mock_params
):
    """Test that import-da cannot reuse SBOM import scans."""
    mock_params.command = "import-da"
    mock_workbench.get_scan_information.return_value = {"is_from_report": "1"}

    with pytest.raises(
        CompatibilityError,
        match="was created for SBOM import and cannot be reused for dependency analysis import",
    ):
        ensure_scan_compatibility(mock_workbench, mock_params, "test_scan_code")
