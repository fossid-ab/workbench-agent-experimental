# tests/unit/utilities/test_cli_wrapper.py

import os
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.exceptions import FileSystemError, ProcessError
from workbench_agent.utilities.cli_wrapper import CliWrapper


class TestCliWrapperInitialization:
    """Test CliWrapper initialization and validation."""

    def test_init_success(self, mocker):
        """Test successful CliWrapper initialization."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=True)

        cli_wrapper = CliWrapper(cli_path="/usr/bin/fossid-cli", timeout="120")

        assert cli_wrapper.cli_path == "/usr/bin/fossid-cli"
        assert cli_wrapper.timeout == "120"

    def test_init_with_default_timeout(self, mocker):
        """Test initialization with default timeout."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=True)

        cli_wrapper = CliWrapper(cli_path="/usr/bin/fossid-cli")

        assert cli_wrapper.timeout == "120"

    def test_init_cli_not_found(self, mocker):
        """Test initialization when CLI path doesn't exist."""
        mocker.patch("os.path.exists", return_value=False)

        with pytest.raises(FileSystemError, match="FossID CLI not found at path"):
            CliWrapper(cli_path="/nonexistent/fossid-cli")

    def test_init_cli_not_executable(self, mocker):
        """Test initialization when CLI is not executable."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=False)

        with pytest.raises(FileSystemError, match="FossID CLI not executable"):
            CliWrapper(cli_path="/usr/bin/fossid-cli")


class TestCliWrapperGetVersion:
    """Test the get_version method."""

    @pytest.fixture
    def cli_wrapper(self, mocker):
        """Create a CliWrapper instance for testing."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=True)
        return CliWrapper("/usr/bin/fossid-cli")

    def test_get_version_success(self, cli_wrapper, mocker):
        """Test successful version retrieval."""
        # Simulate real CLI output format
        expected_output = "FossID Command Line Interface (CLI) 3.4.9 (build 4242ba3, RELEASE)"
        mock_result = (expected_output + "\n").encode("utf-8")
        mocker.patch("subprocess.check_output", return_value=mock_result)

        version = cli_wrapper.get_version()

        assert version == expected_output

    def test_get_version_timeout(self, cli_wrapper, mocker):
        """Test version retrieval timeout."""
        mocker.patch(
            "subprocess.check_output",
            side_effect=subprocess.TimeoutExpired(cmd=["fossid-cli", "--version"], timeout=120),
        )

        with pytest.raises(ProcessError, match="CLI version check timed out"):
            cli_wrapper.get_version()

    def test_get_version_process_error(self, cli_wrapper, mocker):
        """Test version retrieval process error."""
        mocker.patch(
            "subprocess.check_output",
            side_effect=subprocess.CalledProcessError(
                returncode=1, cmd=["fossid-cli", "--version"]
            ),
        )

        with pytest.raises(ProcessError, match="CLI version check failed"):
            cli_wrapper.get_version()

    def test_get_version_unexpected_error(self, cli_wrapper, mocker):
        """Test version retrieval unexpected error."""
        mocker.patch("subprocess.check_output", side_effect=Exception("Unexpected error"))

        with pytest.raises(ProcessError, match="Unexpected error getting CLI version"):
            cli_wrapper.get_version()


class TestCliWrapperBlindScan:
    """Test the blind_scan method."""

    @pytest.fixture
    def cli_wrapper(self, mocker):
        """Create a CliWrapper instance for testing."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=True)
        return CliWrapper("/usr/bin/fossid-cli")

    def test_blind_scan_success(self, cli_wrapper, mocker):
        """Test successful blind scan."""
        # Mock file system checks
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.getsize", return_value=1024)

        # Mock file operations
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)

        # Mock subprocess.run
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stderr = ""
        mock_subprocess_run = mocker.patch("subprocess.run", return_value=mock_process)

        # Mock randstring to ensure predictable temp file name
        mocker.patch.object(CliWrapper, "randstring", return_value="TESTRAND")

        result = cli_wrapper.blind_scan("/test/path")

        expected_temp_file = "/tmp/blind_scan_result_TESTRAND.fossid"
        assert result == expected_temp_file

        # Verify command construction
        expected_cmd = ["/usr/bin/fossid-cli", "--local", "--enable-sha1=1", "/test/path"]
        mock_subprocess_run.assert_called_once()
        actual_cmd = mock_subprocess_run.call_args[0][0]
        assert actual_cmd == expected_cmd

    def test_blind_scan_with_dependency_analysis(self, cli_wrapper, mocker):
        """Test blind scan with dependency analysis enabled."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.getsize", return_value=1024)
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stderr = ""
        mock_subprocess_run = mocker.patch("subprocess.run", return_value=mock_process)
        mocker.patch.object(CliWrapper, "randstring", return_value="TESTRAND")

        result = cli_wrapper.blind_scan("/test/path", run_dependency_analysis=True)

        # Verify dependency analysis flag is included
        expected_cmd = [
            "/usr/bin/fossid-cli",
            "--local",
            "--enable-sha1=1",
            "--dependency-analysis=1",
            "/test/path",
        ]
        mock_subprocess_run.assert_called_once()
        actual_cmd = mock_subprocess_run.call_args[0][0]
        assert actual_cmd == expected_cmd

    def test_blind_scan_path_not_exists(self, cli_wrapper, mocker):
        """Test blind scan when input path doesn't exist."""
        mocker.patch("os.path.exists", return_value=False)

        with pytest.raises(FileSystemError, match="Scan path does not exist"):
            cli_wrapper.blind_scan("/nonexistent/path")

    def test_blind_scan_temp_file_creation_fails(self, cli_wrapper, mocker):
        """Test blind scan when temporary file creation fails."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("builtins.open", side_effect=OSError("Permission denied"))

        with pytest.raises(FileSystemError, match="Failed to create temporary file"):
            cli_wrapper.blind_scan("/test/path")

    def test_blind_scan_process_failure(self, cli_wrapper, mocker):
        """Test blind scan when CLI process fails."""
        mocker.patch("os.path.exists", return_value=True)
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)

        # Mock failed process
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "CLI error occurred"
        mocker.patch("subprocess.run", return_value=mock_process)

        # Mock file removal for cleanup
        mocker.patch("os.remove")

        with pytest.raises(ProcessError, match="Blind scan failed with exit code 1"):
            cli_wrapper.blind_scan("/test/path")

    def test_blind_scan_timeout(self, cli_wrapper, mocker):
        """Test blind scan timeout."""
        mocker.patch("os.path.exists", return_value=True)
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)
        mocker.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["fossid-cli"], timeout=120)
        )
        mocker.patch("os.remove")

        with pytest.raises(ProcessError, match="Blind scan timed out"):
            cli_wrapper.blind_scan("/test/path")

    def test_blind_scan_temp_file_not_created(self, cli_wrapper, mocker):
        """Test blind scan when temporary file is not created by CLI."""
        # First call: path exists (True), second call: temp file doesn't exist (False)
        exists_calls = [True, False]
        mocker.patch(
            "os.path.exists", side_effect=lambda x: exists_calls.pop(0) if exists_calls else False
        )
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)
        mock_process = MagicMock()
        mock_process.returncode = 0
        mocker.patch("subprocess.run", return_value=mock_process)

        with pytest.raises(ProcessError, match="Temporary file was not created"):
            cli_wrapper.blind_scan("/test/path")

    def test_blind_scan_empty_output(self, cli_wrapper, mocker):
        """Test blind scan with empty output file (warning case)."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.getsize", return_value=0)  # Empty file
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)
        mock_process = MagicMock()
        mock_process.returncode = 0
        mocker.patch("subprocess.run", return_value=mock_process)
        mocker.patch.object(CliWrapper, "randstring", return_value="TESTRAND")

        # Should not raise an error, but should log a warning
        result = cli_wrapper.blind_scan("/test/path")
        assert result == "/tmp/blind_scan_result_TESTRAND.fossid"

    def test_blind_scan_unexpected_error_cleanup(self, cli_wrapper, mocker):
        """Test blind scan cleanup on unexpected error."""
        mocker.patch("os.path.exists", return_value=True)
        mock_file = mock_open()
        mocker.patch("builtins.open", mock_file)
        mocker.patch("subprocess.run", side_effect=Exception("Unexpected error"))
        mock_remove = mocker.patch("os.remove")

        with pytest.raises(ProcessError, match="Unexpected error during blind scan"):
            cli_wrapper.blind_scan("/test/path")

        # Verify cleanup was attempted
        mock_remove.assert_called_once()


class TestCliWrapperRandstring:
    """Test the randstring static method."""

    def test_randstring_default_length(self):
        """Test randstring with default length."""
        result = CliWrapper.randstring()
        assert len(result) == 10
        assert result.isalpha()
        assert result.isupper()

    def test_randstring_custom_length(self):
        """Test randstring with custom length."""
        result = CliWrapper.randstring(5)
        assert len(result) == 5
        assert result.isalpha()
        assert result.isupper()

    def test_randstring_zero_length(self):
        """Test randstring with zero length."""
        result = CliWrapper.randstring(0)
        assert len(result) == 0
        assert result == ""

    def test_randstring_only_valid_chars(self):
        """Test that randstring only contains valid characters."""
        result = CliWrapper.randstring(100)
        valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for char in result:
            assert char in valid_chars


class TestCliWrapperCleanupTempFile:
    """Test the cleanup_temp_file method."""

    @pytest.fixture
    def cli_wrapper(self, mocker):
        """Create a CliWrapper instance for testing."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.access", return_value=True)
        return CliWrapper("/usr/bin/fossid-cli")

    def test_cleanup_success(self, cli_wrapper, mocker):
        """Test successful file cleanup."""
        mocker.patch("os.path.exists", return_value=True)
        mock_remove = mocker.patch("os.remove")

        result = cli_wrapper.cleanup_temp_file("/tmp/test_file.fossid")

        assert result is True
        mock_remove.assert_called_once_with("/tmp/test_file.fossid")

    def test_cleanup_file_not_exists(self, cli_wrapper, mocker):
        """Test cleanup when file doesn't exist."""
        mocker.patch("os.path.exists", return_value=False)
        mock_remove = mocker.patch("os.remove")

        result = cli_wrapper.cleanup_temp_file("/tmp/nonexistent.fossid")

        assert result is False
        mock_remove.assert_not_called()

    def test_cleanup_removal_fails(self, cli_wrapper, mocker):
        """Test cleanup when file removal fails."""
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.remove", side_effect=OSError("Permission denied"))

        result = cli_wrapper.cleanup_temp_file("/tmp/test_file.fossid")

        assert result is False

    def test_cleanup_empty_path(self, cli_wrapper):
        """Test cleanup with empty file path."""
        result = cli_wrapper.cleanup_temp_file("")
        assert result is False

    def test_cleanup_none_path(self, cli_wrapper):
        """Test cleanup with None file path."""
        result = cli_wrapper.cleanup_temp_file(None)
        assert result is False
