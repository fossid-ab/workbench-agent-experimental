# tests/unit/api/helpers/test_process_status_checkers.py

from unittest.mock import MagicMock, patch

import pytest
import requests

from workbench_agent.api.helpers.process_status_checkers import ProcessStatusCheckers, StatusResult
from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    UnsupportedStatusCheck,
)


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def status_checker_inst(mock_session):
    """Create a ProcessStatusCheckers instance with a properly mocked session."""

    # Create a concrete instance for testing
    class TestStatusChecker(ProcessStatusCheckers):
        def __init__(self, api_url, api_user, api_token):
            self.api_url = api_url
            self.api_user = api_user
            self.api_token = api_token
            self.session = mock_session

        def _send_request(self, payload, timeout=1800):
            # Mock implementation
            return {}

        def check_status(self, scan_code, operation_type, process_id=None):
            # Mock implementation for abstract method
            return {"status": "NEW"}

        def check_status_download_content_from_git(self, scan_code):
            # Mock implementation for abstract method
            return {"data": "FINISHED"}

        def check_project_report_status(self, process_id, project_code):
            # Mock implementation for abstract method
            return {"status": "FINISHED"}

    checker = TestStatusChecker(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    return checker


# --- Test StatusResult dataclass ---
def test_status_result_creation():
    """Test StatusResult object creation and auto-calculation."""
    result = StatusResult(status="FINISHED", raw_data={"test": "data"})
    assert result.status == "FINISHED"
    assert result.is_finished is True
    assert result.is_failed is False
    assert result.raw_data == {"test": "data"}


def test_status_result_failed_status():
    """Test StatusResult with failed status."""
    result = StatusResult(status="FAILED", raw_data={"error": "Something went wrong"})
    assert result.status == "FAILED"
    assert result.is_finished is False
    assert result.is_failed is True
    assert result.error_message == "Something went wrong"


def test_status_result_progress_extraction():
    """Test progress information extraction."""
    raw_data = {
        "state": "RUNNING",
        "current_step": "Processing files",
        "percentage_done": "45%",
        "total_files": 100,
        "current_file": "test.py",
    }
    result = StatusResult(status="RUNNING", raw_data=raw_data)
    assert result.progress_info is not None
    assert result.progress_info["state"] == "RUNNING"
    assert result.progress_info["percentage_done"] == "45%"


# --- Test standard_scan_status_accessor ---
def test_standard_scan_status_accessor_with_is_finished(status_checker_inst):
    data = {"is_finished": "1"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"

    data = {"is_finished": True}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"


def test_standard_scan_status_accessor_with_status(status_checker_inst):
    data = {"status": "RUNNING"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"

    data = {"status": "running"}  # Lowercase
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"  # Should be uppercase


def test_standard_scan_status_accessor_unknown(status_checker_inst):
    data = {"some_other_key": "value"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "UNKNOWN"


def test_standard_scan_status_accessor_access_error(status_checker_inst):
    data = 123  # Not a dict, will cause AttributeError
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "ACCESS_ERROR"


# --- Test specialized status checking methods ---
def test_check_scan_status(status_checker_inst):
    """Test check_scan_status method."""
    with patch.object(
        status_checker_inst, "check_status", return_value={"status": "FINISHED", "is_finished": "1"}
    ) as mock_check:
        result = status_checker_inst.check_scan_status("scan123")

        assert isinstance(result, StatusResult)
        assert result.status == "FINISHED"
        assert result.is_finished is True
        mock_check.assert_called_once_with("scan123", "SCAN")


def test_check_dependency_analysis_status(status_checker_inst):
    """Test check_dependency_analysis_status method."""
    with patch.object(
        status_checker_inst,
        "check_status",
        return_value={"status": "RUNNING", "percentage_done": "75%"},
    ) as mock_check:
        result = status_checker_inst.check_dependency_analysis_status("scan456")

        assert isinstance(result, StatusResult)
        assert result.status == "RUNNING"
        assert result.is_finished is False
        mock_check.assert_called_once_with("scan456", "DEPENDENCY_ANALYSIS")


def test_check_extract_archives_status(status_checker_inst):
    """Test check_extract_archives_status method."""
    with patch.object(
        status_checker_inst,
        "check_status",
        return_value={"status": "FAILED", "error": "Archive corrupted"},
    ) as mock_check:
        result = status_checker_inst.check_extract_archives_status("scan789")

        assert isinstance(result, StatusResult)
        assert result.status == "FAILED"
        assert result.is_failed is True
        assert result.error_message == "Archive corrupted"
        mock_check.assert_called_once_with("scan789", "EXTRACT_ARCHIVES")


def test_check_scan_report_status(status_checker_inst):
    """Test check_scan_report_status method."""
    with patch.object(
        status_checker_inst, "check_status", return_value={"status": "FINISHED", "is_finished": "1"}
    ) as mock_check:
        result = status_checker_inst.check_scan_report_status("scan123", "proc456")

        assert isinstance(result, StatusResult)
        assert result.status == "FINISHED"
        assert result.is_finished is True
        mock_check.assert_called_once_with("scan123", "REPORT_GENERATION", process_id="proc456")


def test_check_delete_scan_status(status_checker_inst):
    """Test check_delete_scan_status method."""
    with patch.object(
        status_checker_inst, "check_status", return_value={"status": "FINISHED", "is_finished": "1"}
    ) as mock_check:
        result = status_checker_inst.check_delete_scan_status("scan123", "proc789")

        assert isinstance(result, StatusResult)
        assert result.status == "FINISHED"
        assert result.is_finished is True
        mock_check.assert_called_once_with("scan123", "DELETE_SCAN", process_id="proc789")


# --- Additional coverage tests for ProcessStatusCheckers ---


def test_git_status_accessor_variants(status_checker_inst):
    # Direct string
    assert status_checker_inst._git_status_accessor("finished") == "FINISHED"
    # Dict with 'data'
    assert status_checker_inst._git_status_accessor({"data": "running"}) == "RUNNING"
    # NOT STARTED maps to FINISHED (idle)
    assert status_checker_inst._git_status_accessor({"data": "NOT STARTED"}) == "FINISHED"
    # Unexpected type -> ACCESS_ERROR
    assert status_checker_inst._git_status_accessor(123) == "ACCESS_ERROR"


def test_project_report_status_accessor(status_checker_inst):
    # NEW -> FINISHED
    assert (
        status_checker_inst._project_report_status_accessor({"progress_state": "NEW"}) == "FINISHED"
    )
    # RUNNING -> RUNNING
    assert (
        status_checker_inst._project_report_status_accessor({"progress_state": "RUNNING"})
        == "RUNNING"
    )
    # Missing -> UNKNOWN
    assert status_checker_inst._project_report_status_accessor({}) == "UNKNOWN"


def test_handle_unsupported_status_check_decorator_maps_api_error(mocker):
    # Create a minimal class to exercise decorator
    from workbench_agent.api.helpers.process_status_checkers import handle_unsupported_status_check

    class Dummy:
        @handle_unsupported_status_check
        def func(self, scan_code, operation_type):
            from workbench_agent.exceptions import ApiError

            raise ApiError("Field_not_valid_option: type")

    with pytest.raises(UnsupportedStatusCheck):
        Dummy().func("SCN", "SCAN")


def test_handle_unsupported_status_check_decorator_passthrough(mocker):
    # NetworkError should pass through
    from workbench_agent.api.helpers.process_status_checkers import handle_unsupported_status_check

    class Dummy:
        @handle_unsupported_status_check
        def func(self):
            from workbench_agent.exceptions import NetworkError

            raise NetworkError("network")

    with pytest.raises(NetworkError):
        Dummy().func()
