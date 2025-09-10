"""Test main() function orchestration and exception handling."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from workbench_agent.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    ConfigurationError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
)
from workbench_agent.main import main


class TestMainFunctionSuccess:
    """Test successful main() function execution."""

    def test_main_success_with_scan_handler(self, mock_main_dependencies):
        """Test successful main() execution with scan handler."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan"].assert_called_once()
        mock_main_dependencies["workbench_api"].assert_called_once_with(
            api_url=mock_args.api_url, api_user=mock_args.api_user, api_token=mock_args.api_token
        )

    def test_main_success_with_scan_git_handler(self, mock_main_dependencies):
        """Test successful main() execution with scan-git handler."""
        mock_args = MagicMock(command="scan-git", log="INFO")
        mock_main_dependencies["handle_scan_git"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan_git"].assert_called_once()

    def test_main_success_with_import_da_handler(self, mock_main_dependencies):
        """Test successful main() execution with import-da handler."""
        mock_args = MagicMock(command="import-da", log="INFO")
        mock_main_dependencies["handle_import_da"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_import_da"].assert_called_once()

    def test_main_success_with_import_sbom_handler(self, mock_main_dependencies):
        """Test successful main() execution with import-sbom handler."""
        mock_args = MagicMock(command="import-sbom", log="INFO")
        mock_main_dependencies["handle_import_sbom"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_import_sbom"].assert_called_once()

    def test_main_success_with_show_results_handler(self, mock_main_dependencies):
        """Test successful main() execution with show-results handler."""
        mock_args = MagicMock(command="show-results", log="INFO")
        mock_args.result_save_path = None  # Don't trigger save functionality
        mock_main_dependencies["handle_show_results"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_show_results"].assert_called_once()

    def test_main_success_with_download_reports_handler(self, mock_main_dependencies):
        """Test successful main() execution with download-reports handler."""
        mock_args = MagicMock(command="download-reports", log="INFO")
        mock_main_dependencies["handle_download_reports"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_download_reports"].assert_called_once()


class TestMainFunctionExceptionHandling:
    """Test main() function exception handling."""

    def test_main_validation_error_during_parsing(self):
        """Test main() handling validation error during argument parsing."""
        with patch("workbench_agent.main.parse_cmdline_args") as mock_parse:
            mock_parse.side_effect = ValidationError("Test validation error")

            result = main()

            assert result == 2  # Validation error exit code

    def test_main_configuration_error_during_api_init(self):
        """Test main() handling configuration error during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")

        with (
            patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args),
            patch("workbench_agent.main.WorkbenchAPI") as mock_api,
        ):
            mock_api.side_effect = ConfigurationError("Test config error")

            result = main()

            assert result == 2

    def test_main_authentication_error_during_api_init(self):
        """Test main() handling authentication error during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")

        with (
            patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args),
            patch("workbench_agent.main.WorkbenchAPI") as mock_api,
        ):
            mock_api.side_effect = AuthenticationError("Auth error")

            result = main()

            assert result == 2

    @pytest.mark.parametrize(
        "exception_class,exception_msg",
        [
            (ApiError, "API error"),
            (NetworkError, "Network error"),
            (ProcessError, "Process error"),
            (ProcessTimeoutError, "Timeout error"),
            (FileSystemError, "FS error"),
            (CompatibilityError, "Compatibility error"),
            (ProjectNotFoundError, "Project not found"),
            (ScanNotFoundError, "Scan not found"),
        ],
    )
    def test_main_specific_exception_handling(
        self, exception_class, exception_msg, mock_main_dependencies
    ):
        """Test main() handling specific exception types in handlers."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].side_effect = exception_class(exception_msg)

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 1  # Handler error exit code

    def test_main_unexpected_exception_handling(self, mock_main_dependencies):
        """Test main() handling unexpected exceptions."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].side_effect = ValueError("Unexpected error")

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 1  # Unexpected error exit code


class TestEvaluateGatesSpecialHandling:
    """Test special exit code handling for evaluate-gates command."""

    def test_evaluate_gates_success_returns_0(self, mock_main_dependencies):
        """Test evaluate-gates command returns 0 on success (gates pass)."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_main_dependencies["handle_evaluate_gates"].return_value = True  # Gates pass

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0

    def test_evaluate_gates_failure_returns_1(self, mock_main_dependencies):
        """Test evaluate-gates command returns 1 on failure (gates fail)."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_main_dependencies["handle_evaluate_gates"].return_value = False  # Gates fail

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 1


class TestHandlerReturnValues:
    """Test that different command handlers properly handle return values."""

    @pytest.mark.parametrize(
        "command,handler_name",
        [
            ("scan", "handle_scan"),
            ("scan-git", "handle_scan_git"),
            ("import-da", "handle_import_da"),
            ("show-results", "handle_show_results"),
            ("download-reports", "handle_download_reports"),
        ],
    )
    def test_non_evaluate_gates_handlers_ignore_return_value(
        self, command, handler_name, mock_main_dependencies
    ):
        """Test that non-evaluate-gates handlers return 0 regardless of return value."""
        mock_args = MagicMock(command=command, log="INFO")
        mock_main_dependencies[handler_name].return_value = True  # Handler succeeds

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0


class TestLoggingConfiguration:
    """Test proper logging configuration."""

    def test_main_handles_log_level(self, mock_main_dependencies):
        """Test that main() properly handles different log levels."""
        mock_args = MagicMock(command="scan", log="DEBUG")
        mock_main_dependencies["handle_scan"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0


class TestMainIntegration:
    """Integration tests for main function behavior."""

    def test_main_full_success_flow(self, mock_main_dependencies):
        """Test a complete success flow."""
        mock_args = MagicMock()
        mock_args.command = "scan"

        mock_args.api_url = "https://test.com/api.php"
        mock_args.api_user = "testuser"
        mock_args.api_token = "****"
        mock_args.log = "INFO"

        mock_main_dependencies["handle_scan"].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan"].assert_called_once()

    @pytest.mark.parametrize(
        "command,handler_name",
        [
            ("scan", "handle_scan"),
            ("scan-git", "handle_scan_git"),
            ("import-da", "handle_import_da"),
            ("show-results", "handle_show_results"),
            ("download-reports", "handle_download_reports"),
            ("evaluate-gates", "handle_evaluate_gates"),
        ],
    )
    def test_main_command_dispatch_logic(self, command, handler_name, mock_main_dependencies):
        """Test that commands are properly dispatched to their handlers."""
        mock_args = MagicMock(command=command, log="INFO")
        mock_main_dependencies[handler_name].return_value = True

        with patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args):
            result = main()

        # All commands should succeed
        assert result == 0 if command != "evaluate-gates" else result in [0, 1]
        mock_main_dependencies[handler_name].assert_called_once()


class TestLegacyRouting:
    """Test legacy interface detection and routing in main()."""

    def test_legacy_routing_with_project_code(self):
        """Test that legacy --project_code argument routes to legacy handler."""
        legacy_args = [
            "workbench-agent.py",
            "--project_code",
            "my_project",
            "--scan_code",
            "my_scan",
        ]

        with (
            patch("sys.argv", legacy_args),
            patch(
                "workbench_agent.main.uses_legacy_interface", return_value=True
            ) as mock_legacy_check,
            patch(
                "workbench_agent.main.handle_legacy_request", return_value=0
            ) as mock_legacy_handler,
        ):

            result = main()

            assert result == 0
            mock_legacy_check.assert_called_once_with(
                ["--project_code", "my_project", "--scan_code", "my_scan"]
            )
            mock_legacy_handler.assert_called_once()

    def test_legacy_routing_with_various_legacy_args(self):
        """Test legacy routing with different legacy argument patterns."""
        test_cases = [
            ["--project_code=my_project"],
            ["--scan_code", "scan123"],
            ["--blind_scan"],
            ["--api_url=https://test.com"],
            ["--run_dependency_analysis", "--project_code", "test"],
            ["--identification_reuse_type=specific_project"],
        ]

        for legacy_args in test_cases:
            with (
                patch("sys.argv", ["workbench-agent.py"] + legacy_args),
                patch(
                    "workbench_agent.main.uses_legacy_interface", return_value=True
                ) as mock_legacy_check,
                patch(
                    "workbench_agent.main.handle_legacy_request", return_value=42
                ) as mock_legacy_handler,
            ):

                result = main()

                assert result == 42  # Return code from legacy handler
                mock_legacy_check.assert_called_once_with(legacy_args)
                mock_legacy_handler.assert_called_once()

    def test_modern_routing_bypasses_legacy(self, mock_main_dependencies):
        """Test that modern commands bypass legacy routing."""
        modern_args = [
            "workbench-agent.py",
            "scan",
            "--project-name",
            "test",
            "--scan-name",
            "test",
        ]
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].return_value = True

        with (
            patch("sys.argv", modern_args),
            patch(
                "workbench_agent.main.uses_legacy_interface", return_value=False
            ) as mock_legacy_check,
            patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args) as mock_parse,
        ):

            result = main()

            assert result == 0
            mock_legacy_check.assert_called_once_with(
                ["scan", "--project-name", "test", "--scan-name", "test"]
            )
            mock_parse.assert_called_once()
            mock_main_dependencies["handle_scan"].assert_called_once()

    def test_empty_args_uses_modern_interface(self, mock_main_dependencies):
        """Test that empty arguments default to modern interface (will fail parsing)."""
        with (
            patch("sys.argv", ["workbench-agent.py"]),
            patch(
                "workbench_agent.main.uses_legacy_interface", return_value=False
            ) as mock_legacy_check,
            patch("workbench_agent.main.parse_cmdline_args", side_effect=SystemExit(2)),
        ):

            with pytest.raises(SystemExit):
                main()

            mock_legacy_check.assert_called_once_with([])

    def test_legacy_handler_exception_propagates(self):
        """Test that exceptions from legacy handler are caught and converted to exit code 1."""
        legacy_args = ["workbench-agent.py", "--project_code", "test"]

        with (
            patch("sys.argv", legacy_args),
            patch("workbench_agent.main.uses_legacy_interface", return_value=True),
            patch(
                "workbench_agent.main.handle_legacy_request",
                side_effect=RuntimeError("Legacy error"),
            ),
        ):

            result = main()
            # Legacy handler exceptions are caught by main() and converted to exit code 1
            assert result == 1

    def test_legacy_detection_with_mixed_args(self):
        """Test legacy detection when legacy and modern-style args are mixed."""
        mixed_args = [
            "workbench-agent.py",
            "scan",
            "--project_code",
            "test",
            "--scan-name",
            "modern",
        ]

        with (
            patch("sys.argv", mixed_args),
            patch(
                "workbench_agent.main.uses_legacy_interface", return_value=True
            ) as mock_legacy_check,
            patch(
                "workbench_agent.main.handle_legacy_request", return_value=0
            ) as mock_legacy_handler,
        ):

            result = main()

            assert result == 0
            mock_legacy_check.assert_called_once_with(
                ["scan", "--project_code", "test", "--scan-name", "modern"]
            )
            mock_legacy_handler.assert_called_once()

    def test_legacy_routing_preserves_exit_codes(self):
        """Test that legacy handler exit codes are preserved."""
        test_exit_codes = [0, 1, 2, 42, 127]

        for expected_code in test_exit_codes:
            legacy_args = ["workbench-agent.py", "--project_code", "test"]

            with (
                patch("sys.argv", legacy_args),
                patch("workbench_agent.main.uses_legacy_interface", return_value=True),
                patch("workbench_agent.main.handle_legacy_request", return_value=expected_code),
            ):

                result = main()
                assert result == expected_code

    def test_legacy_detection_function_delegation(self):
        """Test that main() properly delegates to cli_common.uses_legacy_interface."""
        args_list = ["--project_code", "test"]

        with (
            patch("sys.argv", ["workbench-agent.py"] + args_list),
            patch(
                "workbench_agent.cli.common.uses_legacy_interface", return_value=True
            ) as mock_cli_common_check,
            patch("workbench_agent.main.handle_legacy_request", return_value=0),
        ):

            result = main()

            assert result == 0
            # Verify that the main function's uses_legacy_interface delegates to cli_common
            mock_cli_common_check.assert_called_once_with(args_list)

    def test_legacy_import_isolation(self):
        """Test that legacy imports are properly isolated and don't affect main flow."""
        modern_args = [
            "workbench-agent.py",
            "scan",
            "--project-name",
            "test",
            "--scan-name",
            "test",
        ]
        mock_args = MagicMock(command="scan", log="INFO")

        with (
            patch("sys.argv", modern_args),
            patch("workbench_agent.main.uses_legacy_interface", return_value=False),
            patch("workbench_agent.main.parse_cmdline_args", return_value=mock_args),
            patch("workbench_agent.main.WorkbenchAPI") as mock_api,
            patch("workbench_agent.main.handle_scan", return_value=True) as mock_handler,
        ):

            # Should not import legacy modules when using modern interface
            result = main()

            assert result == 0
            mock_handler.assert_called_once()
            # Verify no legacy imports were triggered (indirectly tested by successful completion)
