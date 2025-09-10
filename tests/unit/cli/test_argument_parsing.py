"""Test basic argument parsing functionality."""

import os
import sys
from unittest.mock import patch

import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from workbench_agent.cli import parse_cmdline_args


class TestBasicCommandParsing:
    """Test basic command parsing without validation logic."""

    def test_parse_scan_command(self, args, arg_parser, mock_path_exists):
        """Test basic scan command parsing."""
        cmd_args = args().scan(project="MyProject", scan="MyScan", path=".").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "scan"
        assert parsed.project_name == "MyProject"
        assert parsed.scan_name == "MyScan"
        assert parsed.path == "."
        assert parsed.api_url == "https://test.com/api.php"  # Check URL fix
        assert parsed.limit == 10  # Check default
        assert parsed.log == "WARNING"  # Check default

    def test_parse_scan_git_with_branch(self, args, arg_parser):
        """Test scan-git command with branch."""
        cmd_args = (
            args()
            .scan_git(
                project="GitProject", scan="GitScan", git_url="https://github.com/owner/repo.git"
            )
            .git_branch("develop")
            .build()
        )
        parsed = arg_parser(cmd_args)

        assert parsed.command == "scan-git"
        assert parsed.project_name == "GitProject"
        assert parsed.scan_name == "GitScan"
        assert parsed.git_url == "https://github.com/owner/repo.git"
        assert parsed.git_branch == "develop"
        assert parsed.git_tag is None
        assert parsed.git_commit is None

    def test_parse_scan_git_with_tag(self, args, arg_parser):
        """Test scan-git command with tag."""
        cmd_args = args().scan_git().git_tag("v2.0").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "scan-git"
        assert parsed.git_tag == "v2.0"
        assert parsed.git_branch is None
        assert parsed.git_commit is None

    def test_parse_scan_git_with_commit(self, args, arg_parser):
        """Test scan-git command with commit."""
        cmd_args = args().scan_git().git_commit("abc123def").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "scan-git"
        assert parsed.git_commit == "abc123def"
        assert parsed.git_branch is None
        assert parsed.git_tag is None

    def test_parse_import_da_command(self, args, arg_parser, mock_path_exists):
        """Test import-da command parsing."""
        cmd_args = args().import_da(project="DAProject", scan="DAScan", path="results.json").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "import-da"
        assert parsed.project_name == "DAProject"
        assert parsed.scan_name == "DAScan"
        assert parsed.path == "results.json"

    def test_parse_import_sbom_command(self, args, arg_parser, mock_path_exists):
        """Test import-sbom command parsing."""
        cmd_args = (
            args().import_sbom(project="SBOMProject", scan="SBOMScan", path="bom.json").build()
        )
        parsed = arg_parser(cmd_args)

        assert parsed.command == "import-sbom"
        assert parsed.project_name == "SBOMProject"
        assert parsed.scan_name == "SBOMScan"
        assert parsed.path == "bom.json"

    def test_parse_download_reports_scan_scope(self, args, arg_parser):
        """Test download-reports with scan scope."""
        cmd_args = args().download_reports(scope="scan").scan_name("TestScan").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "download-reports"
        assert parsed.report_scope == "scan"
        assert parsed.scan_name == "TestScan"
        assert parsed.report_type == "ALL"  # Default
        assert parsed.report_save_path == "."  # Default

    def test_parse_download_reports_project_scope(self, args, arg_parser):
        """Test download-reports with project scope."""
        cmd_args = args().download_reports(scope="project").project_name("TestProject").build()
        parsed = arg_parser(cmd_args)

        assert parsed.command == "download-reports"
        assert parsed.report_scope == "project"
        assert parsed.project_name == "TestProject"
        assert parsed.scan_name is None

    def test_parse_show_results_command(self, args, arg_parser):
        """Test show-results command parsing."""
        cmd_args = (
            args().show_results(project="ShowProject", scan="ShowScan").show_licenses().build()
        )
        parsed = arg_parser(cmd_args)

        assert parsed.command == "show-results"
        assert parsed.project_name == "ShowProject"
        assert parsed.scan_name == "ShowScan"
        assert parsed.show_licenses is True
        assert parsed.show_components is False  # Default


class TestFlagsAndDefaults:
    """Test flag parsing and default values."""

    def test_parse_flags_and_log_level(self, args, arg_parser, mock_path_exists):
        """Test various flags and log level."""
        cmd_args = args().log_level("DEBUG").scan().build()
        # Add flags manually for this test
        cmd_args.extend(["--delta-scan", "--autoid-pending-ids"])

        parsed = arg_parser(cmd_args)

        assert parsed.log == "DEBUG"
        assert parsed.delta_scan is True
        assert parsed.autoid_pending_ids is True
        assert parsed.autoid_file_licenses is False  # Default
        assert parsed.run_dependency_analysis is False  # Default

    def test_id_reuse_parameters(self, args, arg_parser, mock_path_exists):
        """Test new mutually exclusive ID reuse parameter parsing."""
        # Test project reuse type
        cmd_args = args().scan().id_reuse(reuse_type="project", source="ReusePrj").build()
        parsed = arg_parser(cmd_args)

        # Check that new arguments are parsed correctly
        assert parsed.reuse_project_ids == "ReusePrj"
        assert parsed.reuse_any_identification is False
        assert parsed.reuse_my_identifications is False
        assert parsed.reuse_scan_ids is None

        # Test scan reuse type
        cmd_args = args().scan().id_reuse(reuse_type="scan", source="ReuseScan").build()
        parsed = arg_parser(cmd_args)

        # Check that new arguments are parsed correctly
        assert parsed.reuse_scan_ids == "ReuseScan"
        assert parsed.reuse_any_identification is False
        assert parsed.reuse_my_identifications is False
        assert parsed.reuse_project_ids is None

        # Test any reuse type
        cmd_args = args().scan().id_reuse(reuse_type="any").build()
        parsed = arg_parser(cmd_args)

        assert parsed.reuse_any_identification is True
        assert parsed.reuse_my_identifications is False
        assert parsed.reuse_scan_ids is None
        assert parsed.reuse_project_ids is None

        # Test only_me reuse type
        cmd_args = args().scan().id_reuse(reuse_type="only_me").build()
        parsed = arg_parser(cmd_args)

        assert parsed.reuse_my_identifications is True
        assert parsed.reuse_any_identification is False
        assert parsed.reuse_scan_ids is None
        assert parsed.reuse_project_ids is None


class TestEnvironmentVariables:
    """Test environment variable handling."""

    def test_credentials_from_env_vars(self, arg_parser, mock_path_exists):
        """Test parsing credentials from environment variables."""
        env_vars = {
            "WORKBENCH_URL": "http://env.com",
            "WORKBENCH_USER": "env_user",
            "WORKBENCH_TOKEN": "env_token",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # No credential args in command line
            cmd_args = [
                "workbench-agent",
                "scan",
                "--project-name",
                "P",
                "--scan-name",
                "S",
                "--path",
                ".",
            ]
            parsed = arg_parser(cmd_args)

            assert parsed.api_url == "http://env.com/api.php"  # Check URL fix
            assert parsed.api_user == "env_user"
            assert parsed.api_token == "env_token"


class TestUrlHandling:
    """Test API URL handling and normalization."""

    def test_api_url_normalization(self, args, arg_parser, mock_path_exists):
        """Test that API URLs are properly normalized."""
        # Test URL without /api.php
        scan_cmd = [
            "workbench-agent",
            "scan",
            "--api-url",
            "https://example.com",
            "--api-user",
            "user",
            "--api-token",
            "token",
            "--project-name",
            "P",
            "--scan-name",
            "S",
            "--path",
            ".",
        ]

        parsed = arg_parser(scan_cmd)
        assert parsed.api_url == "https://example.com/api.php"

        # Test URL with trailing slash
        scan_cmd = [
            "workbench-agent",
            "scan",
            "--api-url",
            "https://example.com/",
            "--api-user",
            "user",
            "--api-token",
            "token",
            "--project-name",
            "P",
            "--scan-name",
            "S",
            "--path",
            ".",
        ]

        parsed = arg_parser(scan_cmd)
        assert parsed.api_url == "https://example.com/api.php"

        # Test URL already with /api.php
        scan_cmd = [
            "workbench-agent",
            "scan",
            "--api-url",
            "https://example.com/api.php",
            "--api-user",
            "user",
            "--api-token",
            "token",
            "--project-name",
            "P",
            "--scan-name",
            "S",
            "--path",
            ".",
        ]

        parsed = arg_parser(scan_cmd)
        assert parsed.api_url == "https://example.com/api.php"
