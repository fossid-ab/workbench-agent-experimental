# tests/unit/handlers/test_show_results.py

from unittest.mock import MagicMock, call, patch

import pytest

from workbench_agent.exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
)

# Import handler and dependencies
from workbench_agent.handlers.show_results import handle_show_results


class TestShowResultsHandler:
    """Test cases for the show-results handler."""

    @patch("workbench_agent.handlers.show_results.fetch_display_save_results")
    def test_handle_show_results_success(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results success case."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = True
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
        mock_workbench.check_status.return_value = {"status": "FINISHED"}

        # Execute
        result = handle_show_results(mock_workbench, mock_params)

        # Verify
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with("ProjA", create_if_missing=False)
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="Scan1", project_name="ProjA", create_if_missing=False, params=mock_params
        )
        mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

    @patch("workbench_agent.handlers.show_results.fetch_display_save_results")
    def test_handle_show_results_scan_not_completed(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results when scan is not completed."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = True
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
        mock_workbench.check_status.return_value = {"status": "RUNNING"}

        # Execute
        result = handle_show_results(mock_workbench, mock_params)

        # Verify
        assert result is True
        mock_fetch.assert_called_once()

    @patch("workbench_agent.handlers.show_results.fetch_display_save_results")
    def test_handle_show_results_with_dependencies(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results with dependency analysis flags."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = False
        mock_params.show_components = False
        mock_params.show_dependencies = True
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = True

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)

        # Mock scan status calls - KB finished, DA not finished
        def side_effect(scan_type, scan_code):
            if scan_type == "SCAN":
                return {"status": "FINISHED"}
            elif scan_type == "DEPENDENCY_ANALYSIS":
                return {"status": "RUNNING"}

        mock_workbench.check_status.side_effect = side_effect

        # Execute
        result = handle_show_results(mock_workbench, mock_params)

        # Verify
        assert result is True
        mock_fetch.assert_called_once()

    def test_validation_error_no_show_flags(self, mock_workbench, mock_params):
        """Tests show-results when no show flags are provided."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = False
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Execute and verify
        with pytest.raises(
            ValidationError, match="At least one '--show-\\*' flag must be provided"
        ):
            handle_show_results(mock_workbench, mock_params)

    def test_handle_show_results_project_resolve_fails(self, mock_workbench, mock_params):
        """Tests show-results when project resolution fails."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "NonExistent"
        mock_params.show_licenses = True
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify
        with pytest.raises(ProjectNotFoundError):
            handle_show_results(mock_workbench, mock_params)

    def test_handle_show_results_scan_resolve_fails(self, mock_workbench, mock_params):
        """Tests show-results when scan resolution fails."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "NonExistent"
        mock_params.show_licenses = True
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

        # Execute and verify
        with pytest.raises(ScanNotFoundError):
            handle_show_results(mock_workbench, mock_params)

    @patch(
        "workbench_agent.handlers.show_results.fetch_display_save_results",
        side_effect=ApiError("API Error"),
    )
    def test_handle_show_results_fetch_api_error(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results when fetch API error occurs."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = True
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
        mock_workbench.check_status.return_value = {"status": "FINISHED"}

        # Execute and verify
        with pytest.raises(ApiError):
            handle_show_results(mock_workbench, mock_params)
        mock_fetch.assert_called_once()

    @patch("workbench_agent.handlers.show_results.fetch_display_save_results")
    def test_handle_show_results_status_check_fails(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results when status check fails but continues."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = True
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
        # Make status check fail
        mock_workbench.check_status.side_effect = ApiError("Status check failed")

        # Execute
        result = handle_show_results(mock_workbench, mock_params)

        # Verify - should still succeed despite status check failure
        assert result is True
        mock_fetch.assert_called_once()

    @patch("workbench_agent.handlers.show_results.fetch_display_save_results")
    def test_handle_show_results_multiple_show_flags(self, mock_fetch, mock_workbench, mock_params):
        """Tests show-results with multiple show flags enabled."""
        # Setup mocks
        mock_params.command = "show-results"
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = True
        mock_params.show_components = True
        mock_params.show_dependencies = True
        mock_params.show_scan_metrics = True
        mock_params.show_policy_warnings = True
        mock_params.show_vulnerabilities = True

        # Mock the resolution functions
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
        mock_workbench.check_status.return_value = {"status": "FINISHED"}

        # Execute
        result = handle_show_results(mock_workbench, mock_params)

        # Verify
        assert result is True
        mock_fetch.assert_called_once()
