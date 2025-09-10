# tests/unit/cli/test_show_argument_usage.py

from argparse import Namespace
from unittest.mock import patch

import pytest

from workbench_agent.cli.parser import show_argument_usage


class TestShowArgumentUsage:
    """Test the show_argument_usage function."""

    def test_with_user_provided_tracking(self, capsys):
        """Test function when user-provided argument tracking is available."""
        # Create args namespace with tracking
        args = Namespace(
            command="scan",
            project_name="test-project",
            scan_name="test-scan",
            api_url="https://test.com",
            log="INFO",
            no_wait=False,
            _user_provided={"project_name", "api_url", "log"},
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        # Verify header
        assert "📋 Argument Usage Summary:" in output
        assert "=" * 50 in output

        # Verify user-provided section
        assert "✅ User-Provided Arguments:" in output
        assert "--project-name: test-project" in output
        assert "--api-url: https://test.com" in output
        assert "--log: INFO" in output

        # Verify defaults section
        assert "🔧 Arguments Using Defaults:" in output
        assert "--scan-name: test-scan" in output  # Should be in defaults since not user-provided
        assert "--no-wait: False" in output

    def test_with_no_user_provided_args(self, capsys):
        """Test when no arguments were user-provided."""
        args = Namespace(
            command="scan",
            project_name="test-project",
            api_url="https://test.com",
            _user_provided=set(),  # Empty set
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        # Should only show defaults section
        assert "📋 Argument Usage Summary:" in output
        assert "✅ User-Provided Arguments:" not in output
        assert "🔧 Arguments Using Defaults:" in output
        assert "--project-name: test-project" in output
        assert "--api-url: https://test.com" in output

    def test_with_only_user_provided_args(self, capsys):
        """Test when all arguments were user-provided."""
        args = Namespace(
            command="scan", project_name="test-project", _user_provided={"project_name"}
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        # Should only show user-provided section
        assert "✅ User-Provided Arguments:" in output
        assert "--project-name: test-project" in output
        assert "🔧 Arguments Using Defaults:" not in output

    def test_without_tracking_attribute(self, capsys):
        """Test function when _user_provided attribute is missing."""
        args = Namespace(
            command="scan",
            project_name="test-project",
            # No _user_provided attribute
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "No user-provided argument tracking available." in output
        assert "📋 Argument Usage Summary:" not in output

    def test_argument_name_conversion(self, capsys):
        """Test that argument names are properly converted from underscores to dashes."""
        args = Namespace(
            command="scan",
            project_name="test",
            scan_name="test",
            api_url="test",
            show_components=True,
            run_dependency_analysis=True,
            _user_provided={"project_name", "run_dependency_analysis"},
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        # Verify underscore to dash conversion
        assert "--project-name:" in output
        assert "--run-dependency-analysis:" in output
        assert "--show-components:" in output
        assert "--scan-name:" in output
        assert "--api-url:" in output

    def test_excludes_command_and_tracking_from_output(self, capsys):
        """Test that 'command' and '_user_provided' are excluded from argument lists."""
        args = Namespace(command="scan", project_name="test", _user_provided={"project_name"})

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        # These should not appear in the output
        assert "--command:" not in output
        assert "--user-provided:" not in output
        assert "_user_provided" not in output

    def test_handles_none_values(self, capsys):
        """Test handling of None values in arguments."""
        args = Namespace(
            command="scan",
            project_name=None,
            scan_name="test",
            optional_arg=None,
            _user_provided={"scan_name"},
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "--scan-name: test" in output
        assert "--project-name: None" in output
        assert "--optional-arg: None" in output

    def test_handles_boolean_values(self, capsys):
        """Test handling of boolean values."""
        args = Namespace(
            command="scan",
            no_wait=True,
            verbose=False,
            show_components=True,
            _user_provided={"no_wait", "show_components"},
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "--no-wait: True" in output
        assert "--show-components: True" in output
        assert "--verbose: False" in output

    def test_handles_list_values(self, capsys):
        """Test handling of list values."""
        args = Namespace(
            command="download-reports", report_type=["xlsx", "spdx"], _user_provided={"report_type"}
        )

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "--report-type: ['xlsx', 'spdx']" in output

    def test_empty_namespace(self, capsys):
        """Test with minimal namespace."""
        args = Namespace(_user_provided=set())

        show_argument_usage(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "📋 Argument Usage Summary:" in output
        assert "🔧 Arguments Using Defaults:" not in output  # Should be empty after filtering
