# tests/unit/api/helpers/test_process_waiters.py

import time
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.helpers.process_waiters import ProcessWaiters, WaitResult
from workbench_agent.api.helpers.process_status_checkers import StatusResult
from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
)


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock()
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def process_waiter_inst(mock_session):
    """Create a ProcessWaiters instance with a properly mocked session."""

    # Create a concrete instance for testing
    class TestProcessWaiter(ProcessWaiters):
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
            return {"status": "FINISHED"}

        def check_status_download_content_from_git(self, scan_code):
            # Mock implementation for abstract method
            return {"data": "FINISHED"}

        def check_project_report_status(self, process_id, project_code):
            # Mock implementation for abstract method
            return {"status": "FINISHED"}

        # Mock status checking methods that waiters call
        def check_scan_status(self, scan_code):
            return StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

        def check_dependency_analysis_status(self, scan_code):
            return StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

        def check_extract_archives_status(self, scan_code):
            return StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

        def check_scan_report_status(self, scan_code, process_id):
            return StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

    waiter = TestProcessWaiter(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    return waiter


# --- Test WaitResult dataclass ---
def test_wait_result_creation():
    """Test WaitResult object creation."""
    result = WaitResult(
        status_data={"test": "data"}, duration=10.5, success=True, error_message=None
    )
    assert result.status_data == {"test": "data"}
    assert result.duration == 10.5
    assert result.success is True
    assert result.error_message is None


# --- Test wait_for_completion ---
def test_wait_for_completion_success(process_waiter_inst, mocker):
    """Test successful completion waiting."""
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
        StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
        StatusResult(status="FINISHED", raw_data={"state": "FINISHED"}),
    ]

    with patch("time.sleep", return_value=None):
        with patch("time.time", side_effect=[0, 5, 10, 15]):
            result = process_waiter_inst.wait_for_completion(
                check_function=mock_check_func,
                max_tries=5,
                wait_interval=1,
                operation_name="Test Process",
            )

    assert isinstance(result, WaitResult)
    assert result.success is True
    assert result.duration is None  # Client-side duration calculation was removed
    assert mock_check_func.call_count == 3


def test_wait_for_completion_timeout(process_waiter_inst, mocker):
    """Test timeout during completion waiting."""
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = StatusResult(status="RUNNING", raw_data={"state": "RUNNING"})

    with patch("time.sleep", return_value=None):
        with patch("time.time", side_effect=[0, 5, 10, 15]):
            with pytest.raises(ProcessTimeoutError, match="Test Timeout timed out"):
                process_waiter_inst.wait_for_completion(
                    check_function=mock_check_func,
                    max_tries=3,
                    wait_interval=1,
                    operation_name="Test Timeout",
                )
    assert mock_check_func.call_count == 3


def test_wait_for_completion_failure(process_waiter_inst, mocker):
    """Test failure during completion waiting."""
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = StatusResult(
        status="FAILED", raw_data={"status": "FAILED", "error": "Disk full"}
    )

    with patch("time.sleep", return_value=None):
        with patch("time.time", side_effect=[0, 1, 2, 3, 4, 5]):
            with pytest.raises(ProcessError, match="Error during Test Failure operation"):
                process_waiter_inst.wait_for_completion(
                    check_function=mock_check_func,
                    max_tries=5,
                    wait_interval=1,
                    operation_name="Test Failure",
                )
    assert mock_check_func.call_count == 5  # Retries max_tries times before giving up


# --- Test wait_for_git_clone ---
def test_wait_for_git_clone_success(process_waiter_inst, mocker):
    """Test successful git clone waiting."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"data": "FINISHED"}, duration=12.0, success=True
        )

        result = process_waiter_inst.wait_for_git_clone("scan123", 8, 3)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 12.0
        mock_wait.assert_called_once()


def test_wait_for_git_clone_failure(process_waiter_inst, mocker):
    """Test git clone failure."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.side_effect = ProcessError("Git Clone failed for scan 'scan123': Git error")

        with pytest.raises(ProcessError, match="Git Clone failed for scan 'scan123'"):
            process_waiter_inst.wait_for_git_clone("scan123", 5, 3)


# --- Test specialized waiting methods ---
def test_wait_for_scan_completion(process_waiter_inst, mocker):
    """Test wait_for_scan_completion method."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=20.0, success=True
        )

        result = process_waiter_inst.wait_for_scan_completion("scan123", 10, 5)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 20.0
        mock_wait.assert_called_once()


def test_wait_for_dependency_analysis_completion(process_waiter_inst, mocker):
    """Test wait_for_dependency_analysis_completion method."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=15.0, success=True
        )

        result = process_waiter_inst.wait_for_dependency_analysis_completion("scan456", 8, 3)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 15.0
        mock_wait.assert_called_once()


def test_wait_for_extract_archives_completion(process_waiter_inst, mocker):
    """Test wait_for_extract_archives_completion method."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=10.0, success=True
        )

        result = process_waiter_inst.wait_for_extract_archives_completion("scan789", 5, 2)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 10.0
        mock_wait.assert_called_once()


def test_wait_for_scan_report_completion(process_waiter_inst, mocker):
    """Test wait_for_scan_report_completion method."""
    with patch.object(process_waiter_inst, "wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=25.0, success=True
        )

        result = process_waiter_inst.wait_for_scan_report_completion("scan123", "proc456", 12, 4)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 25.0
        mock_wait.assert_called_once()


# --- Additional coverage tests for ProcessWaiters internals ---


def test__extract_server_duration_valid(process_waiter_inst):
    """Server duration extracted when started/finished present."""
    raw = {"started": "2025-08-08 00:00:00", "finished": "2025-08-08 00:00:05"}
    duration = process_waiter_inst._extract_server_duration(raw)
    assert duration == 5.0


def test__extract_server_duration_git_format(process_waiter_inst):
    """Git format data should return None for duration."""
    raw = {"data": "FINISHED"}
    assert process_waiter_inst._extract_server_duration(raw) is None


def test__extract_server_duration_missing(process_waiter_inst):
    """Missing timestamps -> None."""
    raw = {"status": "FINISHED"}
    assert process_waiter_inst._extract_server_duration(raw) is None


def test__extract_server_duration_invalid(process_waiter_inst):
    """Invalid timestamp format -> None."""
    raw = {"started": "invalid", "finished": "invalid"}
    assert process_waiter_inst._extract_server_duration(raw) is None


def test_wait_for_completion_with_server_duration(process_waiter_inst, mocker, capsys):
    """When finished data has timestamps, duration is set and message printed."""
    running = StatusResult(status="RUNNING", raw_data={"status": "RUNNING"})
    finished = StatusResult(
        status="FINISHED",
        raw_data={
            "status": "FINISHED",
            "started": "2025-08-08 00:00:00",
            "finished": "2025-08-08 00:00:10",
        },
    )
    check_function = mocker.MagicMock(side_effect=[running, finished])

    with patch("time.sleep", return_value=None):
        result = process_waiter_inst.wait_for_completion(
            check_function=check_function,
            max_tries=5,
            wait_interval=1,
            operation_name="Test Proc",
        )

    # Duration should be server-side 10s
    assert isinstance(result, WaitResult)
    assert result.duration == 10.0
    out = capsys.readouterr().out
    assert "completed successfully" in out


def test_wait_for_completion_unsupported_operation_returns_success(process_waiter_inst, mocker):
    """UnsupportedStatusCheck should immediately return success with message."""
    from workbench_agent.exceptions import UnsupportedStatusCheck

    def raise_unsupported():
        raise UnsupportedStatusCheck("unsupported")

    with patch("time.sleep", return_value=None):
        result = process_waiter_inst.wait_for_completion(
            check_function=raise_unsupported,
            max_tries=3,
            wait_interval=1,
            operation_name="Unsupported Op",
        )

    assert isinstance(result, WaitResult)
    assert result.success is True
    assert result.status_data.get("message", "").lower().startswith("skipped")


def test_wait_for_completion_retry_on_exception_then_success(process_waiter_inst, mocker):
    """Generic exception should retry and then succeed."""
    running = StatusResult(status="RUNNING", raw_data={"status": "RUNNING"})
    finished = StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

    call_states = [Exception("transient"), running, finished]

    def side_effect():
        state = call_states.pop(0)
        if isinstance(state, Exception):
            raise state
        return state

    with patch("time.sleep", return_value=None):
        result = process_waiter_inst.wait_for_completion(
            check_function=side_effect,
            max_tries=5,
            wait_interval=1,
            operation_name="Retry Op",
        )

    assert isinstance(result, WaitResult)
    assert result.success is True


def test_check_and_wait_for_process_single_and_multi(process_waiter_inst, mocker):
    """Delegation to single and multiple process types returns expected structures."""
    # Patch specialized waiters to return recognizable results
    mock_result_scan = WaitResult(status_data={"ok": True}, duration=1.0, success=True)
    mock_result_da = WaitResult(status_data={"ok": True}, duration=2.0, success=True)

    mocker.patch.object(
        process_waiter_inst, "wait_for_scan_completion", return_value=mock_result_scan
    )
    mocker.patch_object = mocker.patch.object  # alias to satisfy type checker in some envs
    mocker.patch.object(
        process_waiter_inst, "wait_for_dependency_analysis_completion", return_value=mock_result_da
    )

    # Single
    single = process_waiter_inst.check_and_wait_for_process(
        process_types="SCAN", scan_code="SCN", max_tries=1, wait_interval=0
    )
    assert isinstance(single, WaitResult)

    # Multi
    multi = process_waiter_inst.check_and_wait_for_process(
        process_types=["SCAN", "DEPENDENCY_ANALYSIS"], scan_code="SCN", max_tries=1, wait_interval=0
    )
    assert isinstance(multi, dict)
    assert set(multi.keys()) == {"SCAN", "DEPENDENCY_ANALYSIS"}


def test_check_and_wait_for_process_validations(process_waiter_inst):
    """Missing required args should raise ValueError for certain types."""
    with pytest.raises(ValueError):
        process_waiter_inst.check_and_wait_for_process(
            process_types="SCAN_REPORT_GENERATION", scan_code="SCN"
        )
    with pytest.raises(ValueError):
        process_waiter_inst.check_and_wait_for_process(process_types="PROJECT_REPORT_GENERATION")
