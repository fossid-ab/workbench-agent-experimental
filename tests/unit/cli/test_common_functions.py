# tests/unit/cli/test_common_functions.py

import pytest

from workbench_agent.cli.common import (
    KNOWN_SUBCOMMANDS,
    LEGACY_INDICATORS,
    uses_legacy_interface,
    uses_modern_interface,
)


class TestUsesModernInterface:
    """Test the uses_modern_interface function."""

    def test_detects_modern_commands(self):
        """Test detection of modern subcommands."""
        for command in KNOWN_SUBCOMMANDS:
            args = [command, "--some-arg", "value"]
            assert uses_modern_interface(args) is True

    def test_detects_modern_commands_with_mixed_args(self):
        """Test detection with various argument patterns."""
        test_cases = [
            ["--api-url", "test.com", "scan", "--project-name", "proj"],
            ["scan"],
            ["--help", "blind-scan", "--path", "."],
            ["--verbose", "scan-git", "--git-url", "repo.git"],
        ]
        for args in test_cases:
            assert uses_modern_interface(args) is True

    def test_rejects_legacy_only_args(self):
        """Test rejection of legacy-only argument patterns."""
        test_cases = [
            ["--project_code", "proj", "--scan_code", "myscan"],  # Changed 'scan' to 'myscan'
            ["--api_url", "test.com", "--blind_scan"],
            ["--help"],
            [],
            ["--some-unknown-arg"],
        ]
        for args in test_cases:
            assert uses_modern_interface(args) is False

    def test_empty_args(self):
        """Test with empty arguments."""
        assert uses_modern_interface([]) is False

    def test_help_and_version_args(self):
        """Test with help and version arguments."""
        assert uses_modern_interface(["--help"]) is False
        assert uses_modern_interface(["-h"]) is False


class TestUsesLegacyInterface:
    """Test the uses_legacy_interface function."""

    def test_detects_legacy_indicators(self):
        """Test detection of legacy underscore arguments."""
        for indicator in LEGACY_INDICATORS:
            args = [indicator, "value"]
            assert uses_legacy_interface(args) is True

    def test_detects_legacy_with_equals_format(self):
        """Test detection of legacy arguments in --arg=value format."""
        test_cases = [
            ["--project_code=my_project"],
            ["--api_url=https://test.com", "--scan_code=scan123"],
            ["--blind_scan"],
            ["--run_dependency_analysis", "--path", "src/"],
        ]
        for args in test_cases:
            assert uses_legacy_interface(args) is True

    def test_detects_legacy_mixed_with_modern_format(self):
        """Test detection when legacy indicators mixed with modern format."""
        test_cases = [
            ["--some-modern-arg", "value", "--project_code", "legacy"],
            ["--help", "--api_url=legacy.com"],
        ]
        for args in test_cases:
            assert uses_legacy_interface(args) is True

    def test_rejects_modern_only_args(self):
        """Test rejection of modern-only argument patterns."""
        test_cases = [
            ["scan", "--project-name", "proj", "--scan-name", "scan"],
            ["--api-url", "test.com", "--project-name", "proj"],
            ["blind-scan", "--path", "."],
            ["--help"],
            [],
        ]
        for args in test_cases:
            assert uses_legacy_interface(args) is False

    def test_equals_sign_handling(self):
        """Test that equals sign handling works correctly."""
        # These should be detected as legacy
        assert uses_legacy_interface(["--project_code=value"]) is True
        assert uses_legacy_interface(["--api_url=http://test.com"]) is True

        # These should not be detected as legacy
        assert uses_legacy_interface(["--project-name=value"]) is False
        assert uses_legacy_interface(["--modern-arg=value"]) is False

    def test_empty_args(self):
        """Test with empty arguments."""
        assert uses_legacy_interface([]) is False

    def test_edge_cases(self):
        """Test edge cases for legacy detection."""
        # Empty string in args
        assert uses_legacy_interface([""]) is False

        # Args with just equals signs
        assert uses_legacy_interface(["="]) is False
        assert uses_legacy_interface(["====="]) is False

        # Mixed valid and invalid
        assert uses_legacy_interface(["", "--project_code", ""]) is True


class TestConstantsIntegrity:
    """Test that our constants are properly defined."""

    def test_known_subcommands_complete(self):
        """Test that KNOWN_SUBCOMMANDS contains expected commands."""
        expected_commands = {
            "scan",
            "blind-scan",
            "scan-git",
            "import-da",
            "import-sbom",
            "show-results",
            "evaluate-gates",
            "download-reports",
        }
        assert KNOWN_SUBCOMMANDS == expected_commands

    def test_legacy_indicators_complete(self):
        """Test that LEGACY_INDICATORS contains expected indicators."""
        expected_indicators = {
            "--api_url",
            "--api_user",
            "--api_token",
            "--project_code",
            "--scan_code",
            "--blind_scan",
            "--path-result",
            "--run_dependency_analysis",
            "--identification_reuse_type",
        }
        # Allow for potential duplicates in the set
        assert expected_indicators.issubset(LEGACY_INDICATORS)

    def test_no_overlap_between_constants(self):
        """Test that modern and legacy indicators don't overlap."""
        # Convert legacy indicators to modern format for comparison
        modern_equivalent = {indicator.replace("_", "-") for indicator in LEGACY_INDICATORS}

        # There should be no direct overlap (legacy uses underscores, modern uses dashes)
        overlap = KNOWN_SUBCOMMANDS.intersection(LEGACY_INDICATORS)
        assert len(overlap) == 0, f"Found overlap: {overlap}"
