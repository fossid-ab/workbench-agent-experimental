# tests/integration/test_evaluate_gates_integration.py

import sys
from unittest.mock import patch

from workbench_agent.exceptions import ProjectNotFoundError
from workbench_agent.main import main


class TestEvaluateGatesIntegration:
    """Integration tests for the evaluate-gates command"""

    def test_evaluate_gates_pass_no_issues(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command when no issues are found (should pass).
        """
        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScan",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert return_code == 0, "evaluate-gates should pass when no issues found"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_pending(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command when pending files are found and --fail-on-pending is set.
        """
        mock_workbench_api.get_pending_files.return_value = {
            "file1.cpp": {"status": "pending"},
            "file2.h": {"status": "pending"},
        }

        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScan",
            "--fail-on-pending",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert (
            return_code != 0
        ), "evaluate-gates should fail when pending files found and --fail-on-pending is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_policy_warnings(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command when policy warnings are found and --fail-on-policy is set.
        """
        mock_workbench_api.get_policy_warnings_counter.return_value = {"policy_warnings_total": 2}

        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScan",
            "--fail-on-policy",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert (
            return_code != 0
        ), "evaluate-gates should fail when policy warnings found and --fail-on-policy is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_vulnerabilities(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command when vulnerabilities are found and --fail-on-vuln-severity is set.
        """
        mock_workbench_api.list_vulnerabilities.return_value = [
            {
                "id": "CVE-2021-1234",
                "severity": "critical",
                "description": "Critical vulnerability",
            },
            {
                "id": "CVE-2021-5678",
                "severity": "high",
                "description": "High severity vulnerability",
            },
        ]

        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScan",
            "--fail-on-vuln-severity",
            "high",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert (
            return_code != 0
        ), "evaluate-gates should fail when vulnerabilities found and --fail-on-vuln-severity is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_show_pending_files(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command with --show-pending-files flag.
        """
        mock_workbench_api.get_pending_files.return_value = {
            "file1.cpp": {"status": "pending", "path": "/src/file1.cpp"}
        }

        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScan",
            "--show-pending-files",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert (
            return_code == 0
        ), "evaluate-gates should pass when --fail-on-pending is not set, even with pending files"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_project_not_found(self, mock_workbench_api, capsys):
        """
        Test evaluate-gates command when project is not found (should fail).
        """
        mock_workbench_api.resolve_project.side_effect = ProjectNotFoundError(
            "Project 'NonExistentProj' not found"
        )

        args = [
            "workbench-agent",
            "evaluate-gates",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "NonExistentProj",
            "--scan-name",
            "TestScan",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert return_code != 0, "evaluate-gates should fail when project is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(term in combined_output.lower() for term in ["not found", "error", "project"])
