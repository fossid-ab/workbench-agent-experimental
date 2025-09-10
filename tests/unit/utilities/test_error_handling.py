import argparse
import functools
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

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
from workbench_agent.utilities.error_handling import format_and_print_error, handler_error_wrapper


# --- Fixtures ---
@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = "scan"
    params.project_name = "test_project"
    params.scan_name = "test_scan"
    params.api_url = "https://api.example.com"
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.verbose = False
    params.path = "/test/path"
    return params


# --- Tests for format_and_print_error ---
@patch("builtins.print")
def test_format_and_print_error_project_not_found_read_only(mock_print, mock_params):
    """Test error formatting for ProjectNotFoundError in read-only operations."""
    mock_params.command = "show-results"  # Read-only command
    error = ProjectNotFoundError("Project not found")

    format_and_print_error(error, "test_handler", mock_params)

    # Check that print was called with appropriate messages
    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any(
        "Cannot continue: The requested project does not exist" in call for call in print_calls
    )
    assert any("Project 'test_project' was not found" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_project_not_found_write_operation(mock_print, mock_params):
    """Test error formatting for ProjectNotFoundError in write operations."""
    mock_params.command = "scan"  # Write operation
    error = ProjectNotFoundError("Project not found")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Error executing 'scan' command" in call for call in print_calls)
    assert any("--create-project to create it" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_scan_not_found_read_only(mock_print, mock_params):
    """Test error formatting for ScanNotFoundError in read-only operations."""
    mock_params.command = "show-results"
    error = ScanNotFoundError("Scan not found")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Cannot continue: The requested scan does not exist" in call for call in print_calls)
    assert any(
        "Scan 'test_scan' was not found in project 'test_project'" in call for call in print_calls
    )


@patch("builtins.print")
def test_format_and_print_error_scan_not_found_no_project(mock_print, mock_params):
    """Test error formatting for ScanNotFoundError without project context."""
    mock_params.command = "show-results"
    mock_params.project_name = None
    error = ScanNotFoundError("Scan not found")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any(
        "Scan 'test_scan' was not found in your Workbench instance" in call for call in print_calls
    )


@patch("builtins.print")
def test_format_and_print_error_network_error(mock_print, mock_params):
    """Test error formatting for NetworkError."""
    error = NetworkError("Connection failed")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Network connectivity issue" in call for call in print_calls)
    assert any("Connection failed" in call for call in print_calls)
    assert any("The API URL is correct: https://api.example.com" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_api_error(mock_print, mock_params):
    """Test error formatting for ApiError."""
    error = ApiError("Invalid request", code="invalid_request")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Workbench API error" in call for call in print_calls)
    assert any("Invalid request" in call for call in print_calls)
    assert any("Error code: invalid_request" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_api_error_git_access(mock_print, mock_params):
    """Test error formatting for ApiError with git repository access error."""
    error = ApiError("Git access denied", code="git_repository_access_error")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Git repository access issue" in call for call in print_calls)
    assert any("Check that the Git URL is correct" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_process_timeout(mock_print, mock_params):
    """Test error formatting for ProcessTimeoutError."""
    error = ProcessTimeoutError("Operation timed out")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Operation timed out" in call for call in print_calls)
    assert any("--scan-number-of-tries (current: 60)" in call for call in print_calls)
    assert any("--scan-wait-time (current: 5)" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_process_error(mock_print, mock_params):
    """Test error formatting for ProcessError."""
    error = ProcessError("Process failed")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Workbench process error" in call for call in print_calls)
    assert any("Process failed" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_file_system_error(mock_print, mock_params):
    """Test error formatting for FileSystemError."""
    error = FileSystemError("File not found")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("File system error" in call for call in print_calls)
    assert any("File not found" in call for call in print_calls)
    assert any("Path specified: /test/path" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_validation_error(mock_print, mock_params):
    """Test error formatting for ValidationError."""
    error = ValidationError("Invalid input")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Invalid input or configuration" in call for call in print_calls)
    assert any("Invalid input" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_configuration_error(mock_print, mock_params):
    """Test error formatting for ConfigurationError."""
    error = ConfigurationError("Bad config")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Configuration error" in call for call in print_calls)
    assert any("Bad config" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_compatibility_error(mock_print, mock_params):
    """Test error formatting for CompatibilityError."""
    error = CompatibilityError("Incompatible")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Compatibility issue" in call for call in print_calls)
    assert any("Incompatible" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_authentication_error(mock_print, mock_params):
    """Test error formatting for AuthenticationError."""
    error = AuthenticationError("Auth failed")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [str(call) for call in mock_print.call_args_list]
    # AuthenticationError inherits from ApiError, so it gets handled as an ApiError
    assert any("Workbench API error" in call for call in print_calls)
    assert any("Auth failed" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_generic_error(mock_print, mock_params):
    """Test error formatting for generic exceptions."""
    error = ValueError("Generic error")

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Error executing 'scan' command: Generic error" in call for call in print_calls)


@patch("builtins.print")
def test_format_and_print_error_with_verbose(mock_print, mock_params):
    """Test error formatting with verbose mode."""
    mock_params.verbose = True
    error = ApiError("API error", details={"request_id": "123", "timestamp": "2023-01-01"})

    format_and_print_error(error, "test_handler", mock_params)

    print_calls = [call.args[0] for call in mock_print.call_args_list]
    assert any("Detailed error information:" in call for call in print_calls)
    assert any("request_id: 123" in call for call in print_calls)
    assert any("timestamp: 2023-01-01" in call for call in print_calls)


# --- Tests for handler_error_wrapper ---
def test_handler_error_wrapper_success():
    """Test that wrapper doesn't interfere with successful execution."""

    @handler_error_wrapper
    def dummy_handler(workbench, params):
        return True

    workbench = MagicMock()
    params = MagicMock()

    result = dummy_handler(workbench, params)
    assert result is True


def test_handler_error_wrapper_preserves_function_metadata():
    """Test that wrapper preserves original function metadata."""

    @handler_error_wrapper
    def dummy_handler(workbench, params):
        """Test handler function."""
        return True

    assert dummy_handler.__name__ == "dummy_handler"
    assert dummy_handler.__doc__ == "Test handler function."


@patch("workbench_agent.utilities.error_handling.format_and_print_error")
def test_handler_error_wrapper_handles_exception(mock_format_error):
    """Test that wrapper handles exceptions and re-raises them."""

    @handler_error_wrapper
    def failing_handler(workbench, params):
        raise ValidationError("Test error")

    workbench = MagicMock()
    params = MagicMock()

    with pytest.raises(ValidationError, match="Test error"):
        failing_handler(workbench, params)

    # Verify that format_and_print_error was called
    mock_format_error.assert_called_once()
    args = mock_format_error.call_args[0]
    assert isinstance(args[0], ValidationError)
    assert args[1] == "failing_handler"
    assert args[2] is params


@patch("workbench_agent.utilities.error_handling.format_and_print_error")
def test_handler_error_wrapper_handles_generic_exception(mock_format_error):
    """Test that wrapper handles generic exceptions."""

    @handler_error_wrapper
    def failing_handler(workbench, params):
        raise ValueError("Generic error")

    workbench = MagicMock()
    params = MagicMock()

    # Generic exceptions get wrapped in WorkbenchAgentError
    with pytest.raises(WorkbenchAgentError):
        failing_handler(workbench, params)

    # Should have been called twice - once for the wrapped error
    assert mock_format_error.call_count == 1


@patch("workbench_agent.utilities.error_handling.format_and_print_error")
def test_handler_error_wrapper_preserves_return_value(mock_format_error):
    """Test that wrapper preserves return values."""

    @handler_error_wrapper
    def handler_with_return(workbench, params):
        return {"result": "success", "count": 42}

    workbench = MagicMock()
    params = MagicMock()

    result = handler_with_return(workbench, params)
    assert result == {"result": "success", "count": 42}

    # No error formatting should have been called
    mock_format_error.assert_not_called()


def test_handler_error_wrapper_preserves_none_return():
    """Test that wrapper preserves None return values."""

    @handler_error_wrapper
    def handler_with_none(workbench, params):
        return None

    workbench = MagicMock()
    params = MagicMock()

    result = handler_with_none(workbench, params)
    assert result is None


def test_handler_error_wrapper_preserves_arguments():
    """Test that wrapper passes arguments correctly."""

    @handler_error_wrapper
    def handler_with_args(workbench, params):
        # Verify we receive the correct arguments
        assert workbench.test_method is not None
        assert params.test_attr == "test_value"
        return True

    workbench = MagicMock()
    workbench.test_method = MagicMock()
    params = MagicMock()
    params.test_attr = "test_value"

    result = handler_with_args(workbench, params)
    assert result is True


@patch("builtins.print")
def test_format_and_print_error_credential_error(mock_print, mock_params):
    """Test that credential errors are formatted with user-friendly messages."""
    # Set up mock params with credential info
    mock_params.api_user = "testuser"
    mock_params.api_url = "https://example.com/api.php"

    # Create an API error with the credential error message
    error = ApiError("Classes.FossID.user_not_found_or_api_key_is_not_correct")

    # Call the error formatting function
    format_and_print_error(error, "test_handler", mock_params)

    # Check that print was called with credential-specific messages
    print_calls = [call.args[0] for call in mock_print.call_args_list]

    # Verify the credential-specific message is shown
    assert any("❌ Invalid credentials" in call for call in print_calls)
    assert any("The username or API token provided is incorrect" in call for call in print_calls)
    assert any("testuser" in call for call in print_calls)  # Should show the username
    assert any(
        "https://example.com/api.php" in call for call in print_calls
    )  # Should show the API URL

    # Verify generic API error message is NOT shown
    assert not any("❌ Workbench API error" in call for call in print_calls)
    assert not any(
        "Classes.FossID.user_not_found_or_api_key_is_not_correct" in call for call in print_calls
    )
