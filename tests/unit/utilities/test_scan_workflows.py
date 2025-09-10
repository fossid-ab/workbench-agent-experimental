"""
Test suite for scan_workflows.py utilities.

This module contains tests for scan workflow utility functions including
link generation, scan configuration, and result processing.
"""

# mypy: disable-error-code=import-not-found,import-untyped

import argparse
import json
from typing import Dict, Optional
from unittest.mock import mock_open, patch

import pytest

from workbench_agent.exceptions import ApiError
from workbench_agent.utilities.scan_workflows import (
    determine_scans_to_run,
    display_results,
    fetch_display_save_results,
    fetch_results,
    format_duration,
    get_workbench_links,
    print_operation_summary,
    save_results_to_file,
)

# ============================================================================
# TEST CONSTANTS
# ============================================================================

# Common test data
TEST_SCAN_CODE = "TEST_SCAN_12345"
TEST_PROJECT_CODE = "TEST_PROJECT_67890"
TEST_SCAN_ID = 123456
TEST_API_URL = "https://workbench.example.com/api.php"
TEST_BASE_URL = "https://workbench.example.com"

# Sample test data
SAMPLE_PROJECT_DATA = {
    "name": "test_project",
    "code": TEST_PROJECT_CODE,
    "project_name": "test_project",
    "project_code": TEST_PROJECT_CODE,
}

SAMPLE_SCAN_DATA = {
    "name": "test_scan",
    "code": TEST_SCAN_CODE,
    "id": str(TEST_SCAN_ID),
    "project_code": TEST_PROJECT_CODE,
}

SAMPLE_VULNERABILITY_DATA = {
    "cve": "CVE-2021-1234",
    "severity": "HIGH",
    "component_name": "test_component",
    "component_version": "1.0.0",
}

SAMPLE_LICENSE_DATA = {"identifier": "MIT", "name": "MIT License"}

SAMPLE_DEPENDENCY_DATA = {
    "name": "test_dependency",
    "version": "2.1.0",
    "license_identifier": "Apache-2.0",
}

# Duration test cases
DURATION_TEST_CASES = [
    (0, "0 seconds"),
    (1, "1 second"),
    (59, "59 seconds"),
    (60, "1 minutes"),
    (61, "1 minutes, 1 seconds"),
    (119, "1 minutes, 59 seconds"),
    (120, "2 minutes"),
    (121, "2 minutes, 1 seconds"),
    (3600, "60 minutes"),
    (3661, "61 minutes, 1 seconds"),
    (7322.5, "122 minutes, 2 seconds"),  # rounding
    (None, "N/A"),
    ("invalid", "Invalid Duration"),
]

# API URL variants for testing
API_URL_VARIANTS = [
    "https://example.com/api.php",
    "https://example.com/api.php/",
    "https://example.com/",
    "https://example.com",
    "http://localhost:8080/api.php",
    "http://localhost:8080/fossid/api.php",
]

# Expected link messages
EXPECTED_MESSAGES = {
    "main": "View scan results in Workbench",
    "pending": "Review Pending IDs in Workbench",
    "policy": "Review policy warnings in Workbench",
}

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_workbench(mocker):
    """Create a mock WorkbenchAPI instance."""
    workbench = mocker.MagicMock()

    # Basic data returns
    workbench.list_projects.return_value = [SAMPLE_PROJECT_DATA]
    workbench.get_project_scans.return_value = [SAMPLE_SCAN_DATA]
    workbench.list_scans.return_value = [SAMPLE_SCAN_DATA]

    # Data retrieval used by fetch_results
    workbench.get_dependency_analysis_results = mocker.MagicMock()
    workbench.list_vulnerabilities = mocker.MagicMock()
    workbench.get_scan_identified_licenses = mocker.MagicMock()
    workbench.get_scan_identified_components = mocker.MagicMock()
    workbench.get_scan_folder_metrics = mocker.MagicMock()
    workbench.get_policy_warnings_counter = mocker.MagicMock()

    return workbench


@pytest.fixture
def mock_params(mocker):
    """Create a mock argparse.Namespace with common default values."""
    params = mocker.MagicMock(spec=argparse.Namespace)

    # Scan configuration
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.command = "scan"

    # Project and scan identification
    params.project_name = "test_project"
    params.scan_name = "test_scan"

    # Git parameters
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_depth = None

    # Reuse settings
    params.id_reuse = False
    params.id_reuse_type = None
    params.id_reuse_source = None

    # Display flags - all False by default
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.show_vulnerabilities = False

    # Output settings
    params.result_save_path = None

    # Analysis flags
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False

    return params


@pytest.fixture
def sample_results_data():
    """Provide sample results data for testing."""
    return {
        "dependency_analysis": [SAMPLE_DEPENDENCY_DATA],
        "vulnerabilities": [SAMPLE_VULNERABILITY_DATA],
        "kb_licenses": [SAMPLE_LICENSE_DATA],
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def assert_url_structure(
    url: str,
    scan_id: int,
    view_param: Optional[str] = None,
):
    """Assert that a URL has the correct Workbench structure."""
    assert "index.html" in url
    assert "form=main_interface" in url
    assert "action=scanview" in url
    assert f"sid={scan_id}" in url

    if view_param:
        assert f"current_view={view_param}" in url

    # Should not contain /api.php
    assert "/api.php" not in url


def assert_link_data_structure(link_data: Dict[str, str]):
    """Assert that link data has the correct structure."""
    assert isinstance(link_data, dict)
    assert len(link_data) == 2
    assert set(link_data.keys()) == {"url", "message"}

    # Values should be non-empty strings
    assert isinstance(link_data["url"], str)
    assert isinstance(link_data["message"], str)
    assert len(link_data["url"]) > 0
    assert len(link_data["message"]) > 0


# ============================================================================
# DURATION FORMATTING TESTS
# ============================================================================


class TestFormatDuration:
    """Test cases for the format_duration function."""

    @pytest.mark.parametrize("seconds, expected", DURATION_TEST_CASES)
    def test_format_duration_variations(self, seconds, expected):
        """Test format_duration with various input types and values."""
        assert format_duration(seconds) == expected

    def test_format_duration_edge_cases(self):
        """Test format_duration with edge cases."""
        # Test very large numbers
        assert format_duration(86400) == "1440 minutes"  # 24 hours

        # Test zero and negative (though negative shouldn't happen in practice)
        assert format_duration(0) == "0 seconds"


# ============================================================================
# FILE OPERATIONS TESTS
# ============================================================================


class TestSaveResultsToFile:
    """Test cases for the save_results_to_file function."""

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    def test_save_success(self, mock_makedirs, mock_open_file):
        """Test successful file saving."""
        filepath = "output/results.json"
        results = {"scan_id": TEST_SCAN_ID, "status": "completed"}

        save_results_to_file(filepath, results, TEST_SCAN_CODE)

        mock_makedirs.assert_called_once_with("output", exist_ok=True)
        mock_open_file.assert_any_call(filepath, "w", encoding="utf-8")

        # Verify JSON content
        handle = mock_open_file()
        written = "".join(arg[0][0] for arg in handle.write.call_args_list)
        assert json.loads(written) == results

    @patch("os.makedirs", side_effect=OSError("Permission denied"))
    def test_save_makedirs_failure(self, mock_makedirs):
        """Test handling of directory creation failure."""
        filepath = "restricted/results.json"
        results = {"test": "data"}

        # Should not raise exception
        save_results_to_file(filepath, results, TEST_SCAN_CODE)
        mock_makedirs.assert_called_once_with("restricted", exist_ok=True)

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    def test_save_write_failure(self, mock_makedirs, mock_open_file):
        """Test handling of file write failure."""
        filepath = "output/results.json"
        results = {"test": "data"}

        # Simulate write error
        handle = mock_open_file()
        handle.write.side_effect = IOError("Disk full")

        # Should not raise exception
        save_results_to_file(filepath, results, TEST_SCAN_CODE)
        mock_makedirs.assert_called_once_with("output", exist_ok=True)


# ============================================================================
# SCAN CONFIGURATION TESTS
# ============================================================================


class TestDetermineScansToRun:
    """Test cases for the determine_scans_to_run function."""

    def test_default_configuration(self, mock_params):
        """Test default behavior - only KB scan."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = False

        result = determine_scans_to_run(mock_params)

        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": False,
        }

    def test_with_dependency_analysis(self, mock_params):
        """Test with dependency analysis enabled."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = False

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": True,
        }

    def test_dependency_analysis_only(self, mock_params):
        """Test with dependency analysis only."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = True

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }

    def test_conflicting_flags_resolved(self, mock_params):
        """Test that conflicting flags are resolved (DA only takes precedence)."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = True

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }


# ============================================================================
# RESULTS PROCESSING TESTS
# ============================================================================


class TestFetchResults:
    """Test cases for the fetch_results function."""

    def test_no_flags_set(self, mock_workbench, mock_params):
        """Test when no result flags are set."""
        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)
        assert result == {}

    def test_fetch_license_results(self, mock_workbench, mock_params):
        """Test fetching license results."""
        mock_params.show_licenses = True
        mock_workbench.get_dependency_analysis_results.return_value = [SAMPLE_DEPENDENCY_DATA]

        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        assert "dependency_analysis" in result
        mock_workbench.get_dependency_analysis_results.assert_called_once_with(TEST_SCAN_CODE)

    def test_fetch_vulnerabilities(self, mock_workbench, mock_params):
        """Test fetching vulnerability results."""
        mock_params.show_vulnerabilities = True
        mock_workbench.list_vulnerabilities.return_value = [SAMPLE_VULNERABILITY_DATA]

        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        assert "vulnerabilities" in result
        mock_workbench.list_vulnerabilities.assert_called_once_with(TEST_SCAN_CODE)

    def test_api_error_handling(self, mock_workbench, mock_params):
        """Test graceful handling of API errors during result fetching."""
        mock_params.show_licenses = True
        mock_workbench.get_dependency_analysis_results.side_effect = ApiError("Service unavailable")
        mock_workbench.get_scan_identified_licenses.return_value = [SAMPLE_LICENSE_DATA]

        # Should not raise, should return partial results
        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        # Should return kb_licenses since that call succeeded
        assert "kb_licenses" in result


class TestDisplayResults:
    """Test cases for the display_results function."""

    def test_empty_results(self, mock_params):
        """Test displaying empty results."""
        result = display_results({}, mock_params)
        assert result is False  # No results to display

    def test_display_with_data(self, mock_params, sample_results_data):
        """Test displaying results with actual data."""
        mock_params.show_dependencies = True
        mock_params.show_vulnerabilities = True

        result = display_results(sample_results_data, mock_params)
        assert result is True


class TestFetchDisplaySaveResults:
    """Test cases for the fetch_display_save_results orchestration function."""

    @patch("workbench_agent.utilities.scan_workflows.fetch_results")
    @patch("workbench_agent.utilities.scan_workflows.display_results")
    @patch("workbench_agent.utilities.scan_workflows.save_results_to_file")
    def test_complete_workflow(
        self, mock_save, mock_display, mock_fetch, mock_workbench, mock_params
    ):
        """Test complete fetch, display, and save workflow."""
        mock_params.result_save_path = "output.json"
        mock_params.show_licenses = True
        mock_fetch.return_value = {"test": "data"}
        mock_display.return_value = True

        fetch_display_save_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        mock_fetch.assert_called_once_with(mock_workbench, mock_params, TEST_SCAN_CODE)
        mock_display.assert_called_once_with({"test": "data"}, mock_params)
        mock_save.assert_called_once_with("output.json", {"test": "data"}, TEST_SCAN_CODE)

    @patch("workbench_agent.utilities.scan_workflows.fetch_results")
    @patch("workbench_agent.utilities.scan_workflows.display_results")
    def test_no_save_specified(self, mock_display, mock_fetch, mock_workbench, mock_params):
        """Test fetch and display without saving."""
        mock_params.result_save_path = None
        mock_params.show_licenses = True
        mock_fetch.return_value = {"test": "data"}
        mock_display.return_value = True

        fetch_display_save_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        mock_fetch.assert_called_once_with(mock_workbench, mock_params, TEST_SCAN_CODE)
        mock_display.assert_called_once_with({"test": "data"}, mock_params)


# ============================================================================
# OPERATION SUMMARY TESTS
# ============================================================================


class TestPrintOperationSummary:
    """Test cases for the print_operation_summary function."""

    def test_basic_summary(self, mock_params):
        """Test basic operation summary."""
        mock_params.command = "scan"

        # Should complete without errors
        print_operation_summary(mock_params, True, TEST_PROJECT_CODE, TEST_SCAN_CODE)

    def test_summary_with_durations(self, mock_params):
        """Test operation summary with timing information."""
        mock_params.command = "scan"
        durations = {"kb_scan": 120.5, "dependency_analysis": 60.0}

        # Should complete without errors
        print_operation_summary(
            mock_params,
            True,
            TEST_PROJECT_CODE,
            TEST_SCAN_CODE,
            durations,
        )

    def test_summary_when_da_failed(self, mock_params):
        """Test operation summary when dependency analysis failed."""
        mock_params.command = "scan"

        # Should complete without errors
        print_operation_summary(mock_params, False, TEST_PROJECT_CODE, TEST_SCAN_CODE)


# ============================================================================
# WORKBENCH LINKS TESTS
# ============================================================================


class TestGetWorkbenchLinks:
    """Comprehensive test cases for the get_workbench_links function."""

    def test_basic_link_generation(self):
        """Test basic link generation with standard API URL."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        # Should return all expected link types
        assert set(links.keys()) == {"main", "pending", "policy"}

        # Each link should have correct structure
        for _, link_data in links.items():
            assert_link_data_structure(link_data)

    def test_url_structure_correctness(self):
        """Test that generated URLs have correct structure."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        # Test main link (no current_view parameter)
        main_url = links["main"]["url"]
        expected_main = (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action=" f"scanview&sid={TEST_SCAN_ID}"
        )
        assert main_url == expected_main

        # Test pending link (with current_view=pending_items)
        pending_url = links["pending"]["url"]
        expected_pending = f"{expected_main}&current_view=pending_items"
        assert pending_url == expected_pending

        # Test policy link (with current_view=mark_as_identified)
        policy_url = links["policy"]["url"]
        expected_policy = f"{expected_main}&current_view=mark_as_identified"
        assert policy_url == expected_policy

    def test_message_correctness(self):
        """Test that generated messages match expectations."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        for link_type, expected_message in EXPECTED_MESSAGES.items():
            assert links[link_type]["message"] == expected_message

    @pytest.mark.parametrize("api_url", API_URL_VARIANTS)
    def test_api_url_variants(self, api_url):
        """Test that function handles various API URL formats correctly."""
        links = get_workbench_links(api_url, TEST_SCAN_ID)

        # All URLs should be properly formatted regardless of input
        for _, link_data in links.items():
            url = link_data["url"]
            assert_url_structure(url, TEST_SCAN_ID)

    def test_scan_id_type_handling(self):
        """Test that function handles different scan_id types."""
        # Test with integer
        links_int = get_workbench_links(TEST_API_URL, 123)
        assert "sid=123" in links_int["main"]["url"]

        # Test with string
        links_str = get_workbench_links(TEST_API_URL, "456")
        assert "sid=456" in links_str["main"]["url"]

    def test_result_consistency(self):
        """Test that multiple calls return consistent results."""
        links1 = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)
        links2 = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)
        assert links1 == links2

    def test_base_url_stripping_variations(self):
        """Test that /api.php is properly stripped from various URL formats."""
        test_cases = [
            ("https://example.com/api.php", "https://example.com"),
            ("https://example.com/api.php/", "https://example.com"),
            ("https://example.com/fossid/api.php", "https://example.com/fossid"),
            ("https://example.com/path/to/api.php", "https://example.com/path/to"),
        ]

        for input_url, expected_base in test_cases:
            links = get_workbench_links(input_url, TEST_SCAN_ID)
            main_url = links["main"]["url"]
            assert main_url.startswith(f"{expected_base}/index.html")

    def test_required_url_elements_present(self):
        """Test that all links contain required URL elements."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        required_params = [
            "form=main_interface",
            "action=scanview",
            f"sid={TEST_SCAN_ID}",
        ]

        # All links should contain these base parameters
        for _, link_data in links.items():
            url = link_data["url"]
            for param in required_params:
                assert param in url, f"Missing '{param}' in link URL: {url}"

    def test_view_parameters_correctness(self):
        """Test that view parameters are correctly added to URLs."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        # Main link should NOT have current_view parameter
        assert "current_view" not in links["main"]["url"]

        # Pending link should have current_view=pending_items
        assert "current_view=pending_items" in links["pending"]["url"]

        # Policy link should have current_view=mark_as_identified
        assert "current_view=mark_as_identified" in links["policy"]["url"]

    def test_data_structure_compliance(self):
        """Test the exact structure of returned data."""
        links = get_workbench_links(TEST_API_URL, TEST_SCAN_ID)

        # Should be a dictionary with exactly 3 keys
        assert isinstance(links, dict)
        assert len(links) == 3
        assert set(links.keys()) == {"main", "pending", "policy"}

        # Each value should be a dict with exactly 2 keys
        for _, link_data in links.items():
            assert_link_data_structure(link_data)
