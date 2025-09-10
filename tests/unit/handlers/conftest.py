# tests/unit/handlers/conftest.py

import argparse
from unittest.mock import MagicMock

import pytest

# Import dependencies needed for fixtures
from workbench_agent.api import WorkbenchAPI


# Fixture for mock Workbench instance
@pytest.fixture
def mock_workbench():
    """Provides a mocked WorkbenchAPI instance for handler tests."""
    # Mock methods used across handlers
    mock = MagicMock(spec=WorkbenchAPI)

    # Common methods used across handlers
    mock.resolve_project = MagicMock(return_value="TEST_PROJ_CODE")
    mock.resolve_scan = MagicMock(return_value=("TEST_SCAN_CODE", 123))
    mock.ensure_scan_is_idle = MagicMock()
    mock.upload_dependency_analysis_results = MagicMock()
    mock.start_dependency_analysis = MagicMock()
    mock.wait_for_scan_to_finish = MagicMock(return_value=({}, 5.0))
    mock.check_status = MagicMock(return_value={"status": "FINISHED"})

    # Status check support
    mock._is_status_check_supported = MagicMock(return_value=True)

    # List methods
    mock.list_projects = MagicMock(
        return_value=[{"name": "test_project", "code": "TEST_PROJECT"}]
    )
    mock.list_scans = MagicMock(
        return_value=[{"name": "test_scan", "code": "TEST_SCAN", "id": "123"}]
    )

    # Required attributes for ScanOperationsAPI constructor
    mock.api_url = "http://localhost/api.php"
    mock.api_user = "test_user"
    mock.api_token = "test_token"

    return mock


# Fixture for mock params object (parsed arguments)
@pytest.fixture
def mock_params():
    """Provides a mocked argparse.Namespace for handler tests."""
    params = MagicMock(spec=argparse.Namespace)
    # Set common parameters used across handlers
    params.api_url = "http://localhost/api.php"
    params.api_user = "test_user"
    params.api_token = "test_token"
    params.verbose = False
    params.log = "INFO"

    # Set scan parameters (used in scan handler tests)
    params.scan_number_of_tries = 30
    params.scan_wait_time = 5
    params.output_format = "text"

    # Common handler parameters
    params.command = "test-command"
    params.project_name = "TestProject"
    params.scan_name = "TestScan"
    params.no_wait = False

    # Show results parameters
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.show_vulnerabilities = False

    # Import DA parameters
    params.path = "/fake/path"

    # Download reports parameters
    params.report_type = "html"
    params.report_scope = "scan"
    params.report_save_path = "reports"
    params.selection_type = None
    params.selection_view = None
    params.disclaimer = None
    params.include_vex = True

    # Scan git parameters
    params.git_url = "https://github.com/example/repo.git"
    params.git_branch = "main"
    params.git_tag = None
    params.git_commit = None
    params.limit = 100
    params.sensitivity = 5
    params.autoid_file_licenses = True
    params.autoid_file_copyrights = True
    params.autoid_pending_ids = True
    params.delta_scan = False
    params.id_reuse = False
    params.run_dependency_analysis = True
    params.dependency_analysis_only = False

    # Regular scan parameters
    params.recursively_extract_archives = True
    params.jar_file_extraction = True

    return params
