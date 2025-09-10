# tests/unit/cli/test_scan_operations_parser.py

import pytest

from workbench_agent.cli.parent_parsers import create_scan_operations_parser


class TestScanOperationsParser:
    """Test the new scan_operations parent parser functionality."""

    def test_create_scan_operations_parser(self):
        """Test that the scan operations parser is created with correct arguments."""
        parser = create_scan_operations_parser()

        # Test that it's a valid parser
        assert parser is not None
        assert hasattr(parser, "parse_args")
        assert hasattr(parser, "add_help")
        assert parser.add_help is False  # Should be a parent parser

    def test_scan_operations_arguments_present(self):
        """Test that all expected scan operation arguments are present."""
        parser = create_scan_operations_parser()

        # Parse with all scan operation arguments
        args = parser.parse_args(
            ["--run-dependency-analysis", "--dependency-analysis-only", "--no-wait"]
        )

        assert hasattr(args, "run_dependency_analysis")
        assert hasattr(args, "dependency_analysis_only")
        assert hasattr(args, "no_wait")

        assert args.run_dependency_analysis is True
        assert args.dependency_analysis_only is True
        assert args.no_wait is True

    def test_scan_operations_defaults(self):
        """Test default values for scan operation arguments."""
        parser = create_scan_operations_parser()

        # Parse with no arguments
        args = parser.parse_args([])

        assert args.run_dependency_analysis is False
        assert args.dependency_analysis_only is False
        assert args.no_wait is False

    def test_individual_scan_operation_flags(self):
        """Test each scan operation flag individually."""
        parser = create_scan_operations_parser()

        # Test --run-dependency-analysis
        args1 = parser.parse_args(["--run-dependency-analysis"])
        assert args1.run_dependency_analysis is True
        assert args1.dependency_analysis_only is False
        assert args1.no_wait is False

        # Test --dependency-analysis-only
        args2 = parser.parse_args(["--dependency-analysis-only"])
        assert args2.run_dependency_analysis is False
        assert args2.dependency_analysis_only is True
        assert args2.no_wait is False

        # Test --no-wait
        args3 = parser.parse_args(["--no-wait"])
        assert args3.run_dependency_analysis is False
        assert args3.dependency_analysis_only is False
        assert args3.no_wait is True

    def test_scan_operations_combinations(self):
        """Test valid combinations of scan operation arguments."""
        parser = create_scan_operations_parser()

        # Test --run-dependency-analysis with --no-wait
        args1 = parser.parse_args(["--run-dependency-analysis", "--no-wait"])
        assert args1.run_dependency_analysis is True
        assert args1.dependency_analysis_only is False
        assert args1.no_wait is True

        # Test --dependency-analysis-only with --no-wait
        args2 = parser.parse_args(["--dependency-analysis-only", "--no-wait"])
        assert args2.run_dependency_analysis is False
        assert args2.dependency_analysis_only is True
        assert args2.no_wait is True

    def test_conflicting_dependency_analysis_flags(self):
        """Test that conflicting DA flags can be parsed (validation happens elsewhere)."""
        parser = create_scan_operations_parser()

        # The parser should accept both flags - validation logic handles conflicts
        args = parser.parse_args(["--run-dependency-analysis", "--dependency-analysis-only"])
        assert args.run_dependency_analysis is True
        assert args.dependency_analysis_only is True
        # Validation logic elsewhere should catch this conflict

    def test_scan_operations_argument_group_name(self):
        """Test that arguments are properly grouped."""
        parser = create_scan_operations_parser()

        # Check that the argument group was created
        # (This is more about ensuring the structure is correct)
        help_text = parser.format_help()
        assert "Scan Operations" in help_text
        assert "--run-dependency-analysis" in help_text
        assert "--dependency-analysis-only" in help_text
        assert "--no-wait" in help_text

    def test_scan_operations_help_text(self):
        """Test that help text is appropriate for each argument."""
        parser = create_scan_operations_parser()
        help_text = parser.format_help()

        # Check for key phrases in help text
        assert "Run dependency analysis after KB scan" in help_text
        assert "Run dependency analysis without performing a KB scan" in help_text
        assert "Mutually exclusive with --run-dependency-analysis" in help_text
        assert "Exit after confirming scan has started" in help_text
        assert "waiting for completion" in help_text

    def test_scan_operations_action_types(self):
        """Test that all scan operation arguments are store_true actions."""
        parser = create_scan_operations_parser()

        # Parse and verify the action behavior
        args_empty = parser.parse_args([])
        args_with_flags = parser.parse_args(
            ["--run-dependency-analysis", "--dependency-analysis-only", "--no-wait"]
        )

        # Verify boolean behavior
        for attr in ["run_dependency_analysis", "dependency_analysis_only", "no_wait"]:
            assert getattr(args_empty, attr) is False
            assert getattr(args_with_flags, attr) is True

    def test_unknown_arguments_rejected(self):
        """Test that unknown arguments are rejected."""
        parser = create_scan_operations_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["--unknown-argument"])

        with pytest.raises(SystemExit):
            parser.parse_args(["--invalid-flag"])
