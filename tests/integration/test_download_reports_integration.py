# tests/integration/test_download_reports_integration.py

import sys
from unittest.mock import mock_open, patch

from workbench_agent.main import main


class TestDownloadReportsIntegration:
    """Integration tests for the download-reports command"""

    def test_download_reports_success_spdx(self, mocker, tmp_path, capsys):
        """
        Test download-reports command for SPDX report generation.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock the resolver methods
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock the report generation to return process id
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.generate_scan_report",
            return_value=12345,
        )

        # Mock unified waiter for report generation
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            return_value=None,
        )

        # Mock the report download
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.download_scan_report",
            return_value=b"Mock SPDX report content",
        )

        # Mock file operations
        mocker.patch("os.makedirs", return_value=None)
        mocker.patch("builtins.open", new_callable=mock_open)

        args = [
            "workbench-agent",
            "download-reports",
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
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert return_code == 0, "download-reports should succeed"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: download-reports" in combined_output

    def test_download_reports_success_multiple_types(self, mocker, tmp_path, capsys):
        """
        Test download-reports command for multiple report types.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock the resolver methods
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock multiple report generations
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.generate_scan_report",
            side_effect=[12345, 12346, 12347],
        )

        # Mock unified waiter for report generation
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            return_value=None,
        )

        # Mock the report downloads
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.download_scan_report",
            side_effect=[
                b"Mock SPDX report content",
                b"Mock CycloneDX report content",
                b"Mock XLSX report content",
            ],
        )

        # Mock file operations
        mocker.patch("os.makedirs", return_value=None)
        mocker.patch("builtins.open", new_callable=mock_open)

        args = [
            "workbench-agent",
            "download-reports",
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
            "--report-scope",
            "scan",
            "--report-type",
            "spdx,cyclone_dx,xlsx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert return_code == 0, "download-reports with multiple types should succeed"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: download-reports" in combined_output

    def test_download_reports_project_scope(self, mocker, tmp_path, capsys):
        """
        Test download-reports command with project scope.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock the resolver methods
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )

        # Mock project report generation
        mocker.patch(
            "workbench_agent.api.projects_api.ProjectsAPI.generate_project_report",
            return_value=12345,
        )

        # Mock unified waiter for project report generation
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            return_value=None,
        )

        # Mock the report download
        mocker.patch(
            "workbench_agent.api.projects_api.ProjectsAPI.download_project_report",
            return_value=b"Mock project SPDX report content",
        )

        # Mock file operations
        mocker.patch("os.makedirs", return_value=None)
        mocker.patch("builtins.open", new_callable=mock_open)

        args = [
            "workbench-agent",
            "download-reports",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--report-scope",
            "project",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        assert return_code == 0, "download-reports with project scope should succeed"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: download-reports" in combined_output

    def test_download_reports_project_not_found(self, mocker, tmp_path, capsys):
        """
        Test download-reports command when project is not found (should fail).
        """
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock resolver to raise ProjectNotFoundError
        from workbench_agent.exceptions import ProjectNotFoundError

        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            side_effect=ProjectNotFoundError("Project 'NonExistentProj' not found"),
        )

        args = [
            "workbench-agent",
            "download-reports",
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
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        # Should fail due to project not found
        assert return_code != 0, "download-reports should fail when project is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(term in combined_output.lower() for term in ["not found", "error", "project"])

    def test_download_reports_scan_not_found(self, mocker, tmp_path, capsys):
        """
        Test download-reports command when scan is not found (should fail).
        """
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock project resolution to succeed
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )

        # Mock scan resolver to raise ScanNotFoundError
        from workbench_agent.exceptions import ScanNotFoundError

        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            side_effect=ScanNotFoundError("Scan 'NonExistentScan' not found in project 'TestProj'"),
        )

        args = [
            "workbench-agent",
            "download-reports",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "NonExistentScan",
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        # Should fail due to scan not found
        assert return_code != 0, "download-reports should fail when scan is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(term in combined_output.lower() for term in ["not found", "error", "scan"])

    def test_download_reports_invalid_directory(self, mocker, tmp_path, capsys):
        """
        Test download-reports command with invalid save directory.
        """
        # Use a path that doesn't exist and can't be created
        invalid_path = "/root/nonexistent/path"

        # Mock the resolver methods to succeed
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock os.makedirs to raise a PermissionError
        mocker.patch("os.makedirs", side_effect=PermissionError("Permission denied"))

        args = [
            "workbench-agent",
            "download-reports",
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
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            invalid_path,
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        # Should fail due to directory creation error
        assert return_code != 0, "download-reports should fail when directory cannot be created"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(
            term in combined_output.lower() for term in ["permission", "error", "directory", "path"]
        )
