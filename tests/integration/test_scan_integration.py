# tests/integration/test_scan_integration.py

import sys
from unittest.mock import mock_open, patch
from dataclasses import dataclass
from typing import Any, Dict, Optional
import importlib

main = importlib.import_module("workbench_agent.main").main


# Local lightweight WaitResult to avoid importing heavy types during tests
@dataclass
class WaitResult:
    status_data: Dict[str, Any]
    duration: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None


# --- Helper Function to Create Dummy Files/Dirs ---
def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)


class TestScanIntegration:
    """Integration tests for the scan command"""

    def test_scan_success_flow_simple(self, mocker, tmp_path, capsys):
        """
        Integration test for a successful 'scan' command flow.
        Uses simplified mocking approach with correct API method names.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # Mock the resolver methods with correct class names
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )

        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock the core scan operations
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target",
            return_value=None,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content",
            return_value=True,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.extract_archives",
            return_value=False,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.run_scan",
            return_value=None,
        )

        # Unified waiter interface
        mocker.patch(
            "workbench_agent.api.helpers.process_waiters.ProcessWaiters."
            "check_and_wait_for_process",
            side_effect=[
                None,  # Initial idle check
                None,  # Verify can start
                {
                    "SCAN": WaitResult(
                        status_data={"status": "FINISHED"},
                        duration=10.0,
                        success=True,
                    )
                },
            ],
        )

        # File system operations
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=False)
        mocker.patch("os.path.getsize", return_value=100)
        mocker.patch(
            "builtins.open",
            new_callable=mock_open,
            read_data=b"dummy data",
        )

        args = [
            "workbench-agent",
            "scan",
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
            "--path",
            dummy_path,
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"

        # Verify we got a success message in the output
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Workbench Agent finished successfully" in combined_output

    def test_scan_with_autoid_flags(self, mocker, tmp_path, capsys):
        """
        Test scan command with AutoID flags enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # Mock the resolver methods
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock scan operations
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target",
            return_value=None,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content",
            return_value=True,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.extract_archives",
            return_value=False,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.run_scan",
            return_value=None,
        )

        # Unified waiter interface
        mocker.patch(
            "workbench_agent.api.helpers.process_waiters.ProcessWaiters."
            "check_and_wait_for_process",
            side_effect=[
                None,  # Initial idle check
                None,  # Verify can start
                {
                    "SCAN": WaitResult(
                        status_data={"status": "FINISHED"},
                        duration=10.0,
                        success=True,
                    )
                },
            ],
        )

        # File system operations
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=False)
        mocker.patch("os.path.getsize", return_value=100)
        mocker.patch(
            "builtins.open",
            new_callable=mock_open,
            read_data=b"dummy data",
        )

        args = [
            "workbench-agent",
            "scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScanAutoID",
            "--path",
            dummy_path,
            "--autoid-file-licenses",
            "--autoid-file-copyrights",
            "--autoid-pending-ids",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Scan with AutoID should succeed"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan" in combined_output

    def test_scan_with_dependency_analysis(self, mocker, tmp_path, capsys):
        """
        Test scan command with dependency analysis enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # Mock the resolver methods
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers."
            "ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("TSC", 123),
        )

        # Mock scan operations
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target",
            return_value=None,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content",
            return_value=True,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.extract_archives",
            return_value=False,
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.run_scan",
            return_value=None,
        )

        # Unified waiter interface: wait for both SCAN and DEPENDENCY_ANALYSIS
        mocker.patch(
            "workbench_agent.api.helpers.process_waiters.ProcessWaiters."
            "check_and_wait_for_process",
            side_effect=[
                None,  # Initial idle check
                None,  # Verify can start
                {
                    "SCAN": WaitResult(
                        status_data={"status": "FINISHED"},
                        duration=10.0,
                        success=True,
                    ),
                    "DEPENDENCY_ANALYSIS": WaitResult(
                        status_data={"status": "FINISHED"},
                        duration=5.0,
                        success=True,
                    ),
                },
            ],
        )

        # File system operations
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=False)
        mocker.patch("os.path.getsize", return_value=100)
        mocker.patch(
            "builtins.open",
            new_callable=mock_open,
            read_data=b"dummy data",
        )

        args = [
            "workbench-agent",
            "scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "TestScanDA",
            "--path",
            dummy_path,
            "--run-dependency-analysis",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Scan with DA should succeed"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan" in combined_output

    def test_scan_failure_invalid_path(self, tmp_path, capsys):
        """
        Test scan command with invalid path (should fail).
        """
        # Don't create the dummy path, so it doesn't exist
        invalid_path = str(tmp_path / "nonexistent_file.zip")

        args = [
            "workbench-agent",
            "scan",
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
            "--path",
            invalid_path,
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code != 0, "Scan with invalid path should fail"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        # Should contain some indication of path error
        assert any(
            term in combined_output.lower()
            for term in [
                "path",
                "file",
                "not found",
                "error",
            ]
        )
