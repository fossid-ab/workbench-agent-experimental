# tests/unit/cli/test_validation_edge_cases.py

import os
from argparse import Namespace
from unittest.mock import patch

import pytest

from workbench_agent.cli.validators import (
    _validate_api_credentials,
    _validate_scan_commands,
    validate_parsed_args,
)
from workbench_agent.exceptions import ValidationError


class TestValidationEdgeCases:
    """Test edge cases in validation that are missing coverage."""

    def test_missing_api_credentials_raises_error(self):
        """Test that missing API credentials raises ValidationError."""
        # Test case for line 39 in validators.py
        args = Namespace(api_url=None, api_user="test", api_token="token")

        with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
            _validate_api_credentials(args)

    def test_missing_api_user_raises_error(self):
        """Test that missing API user raises ValidationError."""
        args = Namespace(api_url="https://test.com", api_user=None, api_token="token")

        with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
            _validate_api_credentials(args)

    def test_missing_api_token_raises_error(self):
        """Test that missing API token raises ValidationError."""
        args = Namespace(api_url="https://test.com", api_user="test", api_token=None)

        with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
            _validate_api_credentials(args)

    def test_missing_all_api_credentials_raises_error(self):
        """Test that missing all API credentials raises ValidationError."""
        args = Namespace(api_url=None, api_user=None, api_token=None)

        with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
            _validate_api_credentials(args)

    def test_scan_command_missing_path_raises_error(self):
        """Test that scan command without path raises ValidationError."""
        # Test case for line 76 in validators.py
        args = Namespace(command="scan", path=None)

        with pytest.raises(ValidationError, match="Path is required for scan command"):
            _validate_scan_commands(args)

    def test_blind_scan_command_missing_path_raises_error(self):
        """Test that blind-scan command without path raises ValidationError."""
        args = Namespace(command="blind-scan", path=None)

        with pytest.raises(ValidationError, match="Path is required for blind-scan command"):
            _validate_scan_commands(args)

    @patch("os.path.exists", return_value=False)
    def test_scan_command_nonexistent_path_raises_error(self, mock_exists):
        """Test that scan command with non-existent path raises ValidationError."""
        args = Namespace(command="scan", path="/non/existent/path")

        with pytest.raises(ValidationError, match="Path does not exist: /non/existent/path"):
            _validate_scan_commands(args)

    @patch("os.path.exists", return_value=False)
    def test_blind_scan_command_nonexistent_path_raises_error(self, mock_exists):
        """Test that blind-scan command with non-existent path raises ValidationError."""
        args = Namespace(command="blind-scan", path="/non/existent/path")

        with pytest.raises(ValidationError, match="Path does not exist: /non/existent/path"):
            _validate_scan_commands(args)

    def test_scan_git_command_no_path_validation(self):
        """Test that scan-git command doesn't require path validation."""
        args = Namespace(command="scan-git", git_url="https://github.com/user/repo.git")

        # Should not raise an exception
        _validate_scan_commands(args)

    @patch("os.path.exists", return_value=True)
    def test_valid_scan_command_passes(self, mock_exists):
        """Test that valid scan command passes validation."""
        args = Namespace(command="scan", path="/valid/path")

        # Should not raise an exception
        _validate_scan_commands(args)

    @patch("os.path.exists", return_value=True)
    def test_valid_blind_scan_command_passes(self, mock_exists):
        """Test that valid blind-scan command passes validation."""
        args = Namespace(command="blind-scan", path="/valid/path")

        # Should not raise an exception
        _validate_scan_commands(args)

    def test_full_validation_with_missing_credentials(self):
        """Test full validation flow with missing credentials."""
        args = Namespace(
            command="scan", api_url=None, api_user=None, api_token=None, path="/some/path"
        )

        with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
            validate_parsed_args(args)

    @patch("os.path.exists", return_value=False)
    def test_full_validation_with_missing_path(self, mock_exists):
        """Test full validation flow with missing path."""
        args = Namespace(
            command="scan",
            api_url="https://test.com",
            api_user="test",
            api_token="token",
            path="/non/existent/path",
        )

        with pytest.raises(ValidationError, match="Path does not exist"):
            validate_parsed_args(args)

    def test_validation_success_path(self):
        """Test successful validation path."""
        with patch("os.path.exists", return_value=True):
            args = Namespace(
                command="scan",
                api_url="https://test.com/api.php",
                api_user="test",
                api_token="token",
                path="/valid/path",
            )

            # Should not raise an exception
            validate_parsed_args(args)

    def test_api_url_formatting_applied(self):
        """Test that API URL formatting is applied during validation."""
        with patch("os.path.exists", return_value=True):
            args = Namespace(
                command="scan",
                api_url="https://test.com",  # Missing /api.php
                api_user="test",
                api_token="token",
                path="/valid/path",
            )

            validate_parsed_args(args)

            # Should have been fixed to include /api.php
            assert args.api_url == "https://test.com/api.php"


class TestValidationSpecialCases:
    """Test special validation cases for different commands."""

    def test_import_commands_validation_coverage(self):
        """Test that import commands go through validation."""
        with patch("os.path.exists", return_value=True):
            args = Namespace(
                command="import-da",
                api_url="https://test.com",
                api_user="test",
                api_token="token",
                path="/valid/path/to/results.json",
            )

            # Should not raise for import commands when path is provided
            validate_parsed_args(args)

    def test_download_reports_command_validation_coverage(self):
        """Test that download-reports command goes through validation."""
        args = Namespace(
            command="download-reports",
            api_url="https://test.com",
            api_user="test",
            api_token="token",
        )

        # Should not raise for download-reports command
        validate_parsed_args(args)

    def test_show_results_command_validation_coverage(self):
        """Test that show-results command goes through validation."""
        args = Namespace(
            command="show-results",
            api_url="https://test.com",
            api_user="test",
            api_token="token",
            show_components=True,  # Need at least one show flag
        )

        # Should not raise for show-results command when show flags are provided
        validate_parsed_args(args)

    def test_unknown_command_passes_basic_validation(self):
        """Test that unknown commands pass basic validation."""
        args = Namespace(
            command="unknown-command",
            api_url="https://test.com",
            api_user="test",
            api_token="token",
        )

        # Should not raise - command-specific validation only applies to known commands
        validate_parsed_args(args)
