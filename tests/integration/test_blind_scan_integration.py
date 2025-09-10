# tests/integration/test_blind_scan_integration.py

import sys
from unittest.mock import MagicMock, mock_open, patch

from workbench_agent.main import main


# --- Helper Function to Create Dummy Directories ---
def create_dummy_directory(tmp_path, content="dummy content"):
    """Create a dummy directory with some files for testing."""
    dummy_dir = tmp_path / "test_source_code"
    dummy_dir.mkdir()

    # Add some files to make it look like a real project
    (dummy_dir / "main.py").write_text("print('Hello, World!')")
    (dummy_dir / "requirements.txt").write_text("requests==2.28.0\nflask==2.2.0")
    (dummy_dir / "README.md").write_text("# Test Project\nThis is a test project.")

    # Create a subdirectory
    sub_dir = dummy_dir / "src"
    sub_dir.mkdir()
    (sub_dir / "utils.py").write_text("def helper_function(): pass")

    return str(dummy_dir)


class TestBlindScanIntegration:
    """Integration tests for the blind-scan command"""

    def test_blind_scan_success_flow(self, mocker, tmp_path, capsys):
        """
        Integration test for a successful 'blind-scan' command flow.
        Tests the complete workflow from hash generation to scan completion.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock the CLI wrapper completely - don't use the real class at all
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper.get_version.return_value = "FossID CLI version 2023.2.1"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/blind_scan_result_TESTRAND.fossid"

        mocker.patch(
            "workbench_agent.handlers.blind_scan.CliWrapper", return_value=mock_cli_wrapper
        )

        # Mock the project and scan resolution
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ001",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("BSC001", 456),
        )

        # Mock upload and scan operations
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content", return_value=None
        )
        mocker.patch("workbench_agent.api.scans_api.ScansAPI.run_scan", return_value=None)

        # Mock unified waiter
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            side_effect=[
                None,  # initial idle check
                None,  # verify can start
                {"SCAN": MagicMock(duration=15.0, success=True)},  # final wait
            ],
        )

        # Mock validation functions
        mocker.patch(
            "workbench_agent.utilities.scan_target_validators.ensure_scan_compatibility",
            return_value=None,
        )

        # Mock file system operations
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=True)

        # Mock the temporary file cleanup
        mocker.patch("workbench_agent.handlers.blind_scan.cleanup_temp_file", return_value=True)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScan",
            "--path",
            dummy_path,
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"

        # Verify CLI wrapper was called correctly
        mock_cli_wrapper.get_version.assert_called_once()
        mock_cli_wrapper.blind_scan.assert_called_once_with(
            path=dummy_path, run_dependency_analysis=False
        )

        # Verify we got success messages in the output
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "BLIND-SCAN Command" in combined_output
        assert "Generating file hashes using FossID CLI" in combined_output
        assert "Hash file uploaded successfully" in combined_output
        assert "Blind Scan completed successfully" in combined_output

    def test_blind_scan_with_dependency_analysis(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command with dependency analysis enabled.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock the CLI wrapper completely - don't use the real class at all
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper.get_version.return_value = "FossID CLI version 2023.2.1"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/blind_scan_result_TESTRAND.fossid"

        mocker.patch(
            "workbench_agent.handlers.blind_scan.CliWrapper", return_value=mock_cli_wrapper
        )

        # Mock API operations
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ002",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("BSC002", 789),
        )
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content", return_value=None
        )
        mocker.patch("workbench_agent.api.scans_api.ScansAPI.run_scan", return_value=None)
        # Unified waiter sequence: idle, verify, final wait for SCAN+DA
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            side_effect=[
                None,  # initial idle check
                None,  # verify can start
                {
                    "SCAN": MagicMock(duration=20.0, success=True),
                    "DEPENDENCY_ANALYSIS": MagicMock(duration=10.0, success=True),
                },
            ],
        )

        mocker.patch(
            "workbench_agent.utilities.scan_target_validators.ensure_scan_compatibility",
            return_value=None,
        )
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=True)
        mocker.patch("workbench_agent.handlers.blind_scan.cleanup_temp_file", return_value=True)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanDA",
            "--path",
            dummy_path,
            "--run-dependency-analysis",
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"

        # Verify dependency analysis was enabled in CLI call
        mock_cli_wrapper.blind_scan.assert_called_once_with(
            path=dummy_path, run_dependency_analysis=True
        )

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Waiting for SCAN, DEPENDENCY_ANALYSIS to complete" in combined_output

    def test_blind_scan_no_wait_mode(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command with --no-wait flag.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock the CLI wrapper completely - don't use the real class at all
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper.get_version.return_value = "FossID CLI version 2023.2.1"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/blind_scan_result_TESTRAND.fossid"

        mocker.patch(
            "workbench_agent.handlers.blind_scan.CliWrapper", return_value=mock_cli_wrapper
        )

        # Mock API operations
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ003",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("BSC003", 123),
        )
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content", return_value=None
        )
        mocker.patch("workbench_agent.api.scans_api.ScansAPI.run_scan", return_value=None)
        # Unified waiter sequence for no-wait: idle and verify only
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            side_effect=[
                None,  # initial idle check
                None,  # verify can start
            ],
        )

        # No waiting mocks needed since --no-wait should exit early
        mocker.patch(
            "workbench_agent.utilities.scan_target_validators.ensure_scan_compatibility",
            return_value=None,
        )
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=True)
        mocker.patch("workbench_agent.handlers.blind_scan.cleanup_temp_file", return_value=True)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanNoWait",
            "--path",
            dummy_path,
            "--no-wait",
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "KB Scan started successfully" in combined_output
        assert "Exiting without waiting for completion (--no-wait mode)" in combined_output

    def test_blind_scan_invalid_path(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command with an invalid path.
        """
        # Mock CLI wrapper (shouldn't be called due to early validation failure)
        mocker.patch("workbench_agent.utilities.cli_wrapper.CliWrapper")

        # Mock file system to return False for path existence
        mocker.patch("os.path.exists", return_value=False)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanBadPath",
            "--path",
            "/nonexistent/path",
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 2, "Command should exit with error code"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "does not exist" in combined_output

    def test_blind_scan_file_instead_of_directory(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command with a file path instead of directory.
        """
        # Create a file instead of directory
        dummy_file = tmp_path / "test_file.py"
        dummy_file.write_text("print('test')")

        mocker.patch("workbench_agent.utilities.cli_wrapper.CliWrapper")
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=False)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanFile",
            "--path",
            str(dummy_file),
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 2, "Command should exit with configuration error code"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "must be a directory" in combined_output

    def test_blind_scan_cli_version_warning(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command when CLI version check fails (should continue with warning).
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock CLI wrapper with version failure
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper.get_version.side_effect = Exception("Version check failed")
        mock_cli_wrapper.blind_scan.return_value = "/tmp/blind_scan_result_TESTRAND.fossid"

        mocker.patch(
            "workbench_agent.handlers.blind_scan.CliWrapper", return_value=mock_cli_wrapper
        )

        # Mock other operations for success
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ004",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("BSC004", 555),
        )
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content", return_value=None
        )
        mocker.patch("workbench_agent.api.scans_api.ScansAPI.run_scan", return_value=None)
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            side_effect=[
                None,  # initial idle check
                None,  # verify can start
                {"SCAN": MagicMock(duration=15.0, success=True)},  # final wait
            ],
        )
        mocker.patch(
            "workbench_agent.utilities.scan_target_validators.ensure_scan_compatibility",
            return_value=None,
        )
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=True)
        mocker.patch("workbench_agent.handlers.blind_scan.cleanup_temp_file", return_value=True)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanVersionWarning",
            "--path",
            dummy_path,
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should still succeed despite version warning"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Warning: Could not validate CLI version" in combined_output
        assert "Blind Scan completed successfully" in combined_output

    def test_blind_scan_dependency_analysis_only(self, mocker, tmp_path, capsys):
        """
        Test blind-scan command with dependency analysis only (no KB scan).
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock the CLI wrapper completely - don't use the real class at all
        mock_cli_wrapper = MagicMock()
        mock_cli_wrapper.get_version.return_value = "FossID CLI version 2023.2.1"
        mock_cli_wrapper.blind_scan.return_value = "/tmp/blind_scan_result_TESTRAND.fossid"

        mocker.patch(
            "workbench_agent.handlers.blind_scan.CliWrapper", return_value=mock_cli_wrapper
        )

        # Mock API operations
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project",
            return_value="PRJ005",
        )
        mocker.patch(
            "workbench_agent.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan",
            return_value=("BSC005", 999),
        )
        mocker.patch(
            "workbench_agent.api.upload_api.UploadAPI.upload_scan_target", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.remove_uploaded_content", return_value=None
        )
        mocker.patch(
            "workbench_agent.api.scans_api.ScansAPI.start_dependency_analysis", return_value=None
        )
        # Unified waiter: idle, verify, DA-only completion
        mocker.patch(
            "workbench_agent.api.workbench_api.WorkbenchAPI.check_and_wait_for_process",
            side_effect=[
                None,  # initial idle check
                None,  # verify can start
                MagicMock(duration=8.0),  # DA only wait result
            ],
        )
        mocker.patch(
            "workbench_agent.utilities.scan_target_validators.ensure_scan_compatibility",
            return_value=None,
        )
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("os.path.isdir", return_value=True)
        mocker.patch("workbench_agent.handlers.blind_scan.cleanup_temp_file", return_value=True)

        args = [
            "workbench-agent",
            "blind-scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProject",
            "--scan-name",
            "TestBlindScanDAOnly",
            "--path",
            dummy_path,
            "--dependency-analysis-only",
            "--fossid-cli-path",
            "/usr/bin/fossid-cli",
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Starting Dependency Analysis only" in combined_output
        assert "(skipping KB scan)" in combined_output
