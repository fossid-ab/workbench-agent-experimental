# tests/unit/api/helpers/test_generate_download_report.py

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from workbench_agent.api.helpers.generate_download_report import ReportHelper
from workbench_agent.exceptions import FileSystemError, ValidationError


# --- Fixtures ---
@pytest.fixture
def report_helper():
    """Create a ReportHelper instance for testing."""
    return ReportHelper()


# --- Tests for _save_report_content (migrated from test_utils.py) ---
class TestSaveReportContent:
    """Test cases for the _save_report_content static method."""

    def test_save_text_response_success(self):
        """Test saving a text response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test_scan", "basic"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with("Test content")

    def test_save_binary_response_success(self):
        """Test saving a binary response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b"\x00\x01\x02\x03"
        response.headers = {"content-type": "application/octet-stream"}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test_scan", "xlsx"
                )
                mock_file.assert_called_once_with("output_dir/scan-test_scan-xlsx.xlsx", "wb")
                mock_file().write.assert_called_once_with(b"\x00\x01\x02\x03")

    def test_save_dict_success(self):
        """Test saving a dictionary as JSON successfully."""
        content = {"key": "value", "number": 42}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    content, "output_dir", "scan", "test_scan", "json"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-json.json", "w", encoding="utf-8"
                )

    def test_makedirs_error(self):
        """Test handling of directory creation errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("os.makedirs", side_effect=OSError("Cannot create directory")):
            with pytest.raises(FileSystemError, match="Could not create output directory"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test_scan", "basic"
                )

    def test_file_write_error(self):
        """Test handling of file write errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                mock_file().write.side_effect = IOError("File write error")
                with pytest.raises(FileSystemError, match="Failed to write report to"):
                    ReportHelper._save_report_content(
                        response, "output_dir", "scan", "test_scan", "basic"
                    )

    def test_save_json_response_success(self):
        """Test saving a JSON response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b'{"key": "value"}'
        response.headers = {"content-type": "application/json"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "project", "test_project", "cyclone_dx"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-cyclone_dx.json", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with('{"key": "value"}')

    def test_save_list_success(self):
        """Test saving a list as JSON successfully."""
        content = ["item1", "item2", {"nested": "object"}]

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    content, "output_dir", "project", "test_project", "results"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-results.json", "w", encoding="utf-8"
                )

    def test_save_string_success(self):
        """Test saving a string successfully."""
        content = "This is a test string content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    content, "output_dir", "scan", "test_scan", "basic"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with(content)

    def test_save_bytes_success(self):
        """Test saving bytes successfully."""
        content = b"Binary data content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    content, "output_dir", "project", "test_project", "binary"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-binary.bin", "wb"
                )
                mock_file().write.assert_called_once_with(content)

    def test_response_content_read_error(self):
        """Test handling of response content read errors."""
        response = MagicMock(spec=requests.Response)
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        # Use property descriptor to make content property raise exception
        def _content_prop():
            raise Exception("Content read error")

        type(response).content = property(lambda self: _content_prop())

        with pytest.raises(FileSystemError, match="Failed to read content from response object"):
            ReportHelper._save_report_content(response, "output_dir", "scan", "test_scan", "basic")

    def test_json_serialization_error(self):
        """Test handling of JSON serialization errors."""
        # Create a dict with non-serializable content
        content = {"function": lambda x: x}  # Functions are not JSON serializable

        with pytest.raises(
            ValidationError, match="Failed to serialize provided dictionary/list to JSON"
        ):
            ReportHelper._save_report_content(content, "output_dir", "scan", "test_scan", "json")

    def test_filename_sanitization(self):
        """Test filename sanitization with special characters."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test/scan:name*", "basic"
                )
                # Check that filename was sanitized
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan_name_-basic.txt", "w", encoding="utf-8"
                )

    @pytest.mark.parametrize(
        "report_type,expected_ext",
        [
            ("xlsx", "xlsx"),
            ("spdx", "rdf"),
            ("spdx_lite", "xlsx"),
            ("cyclone_dx", "json"),
            ("html", "html"),
            ("dynamic_top_matched_components", "html"),
            ("string_match", "xlsx"),
            ("basic", "txt"),
            ("unknown_type", "txt"),  # Default case
        ],
    )
    def test_various_report_types(self, report_type, expected_ext):
        """Test filename extensions for various report types."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "application/octet-stream"}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test_scan", report_type
                )
                expected_filename = f"output_dir/scan-test_scan-{report_type}.{expected_ext}"
                mock_file.assert_called_once_with(expected_filename, "wb")

    def test_validation_error_no_output_dir(self):
        """Test validation error when output directory is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Output directory is not specified"):
            ReportHelper._save_report_content(response, "", "scan", "test_scan", "basic")

    def test_validation_error_no_name_component(self):
        """Test validation error when name component is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Name component .* is not specified"):
            ReportHelper._save_report_content(response, "output_dir", "scan", "", "basic")

    def test_validation_error_no_report_type(self):
        """Test validation error when report type is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Report type is not specified"):
            ReportHelper._save_report_content(response, "output_dir", "scan", "test_scan", "")

    def test_unsupported_content_type(self):
        """Test validation error for unsupported content types."""
        unsupported_content = 12345  # Integer is not supported

        with pytest.raises(ValidationError, match="Unsupported content type for saving"):
            ReportHelper._save_report_content(
                unsupported_content, "output_dir", "scan", "test_scan", "basic"
            )

    def test_response_decode_fallback(self):
        """Test handling of response decode errors with fallback to binary."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content with \xff invalid utf-8"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        # The actual implementation uses errors='replace' which doesn't raise an exception
        # But we can test with invalid binary that would trigger the fallback warning
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                ReportHelper._save_report_content(
                    response, "output_dir", "scan", "test_scan", "basic"
                )
                # Due to errors='replace', it should still be text mode
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )


# --- Tests for other ReportHelper methods ---
class TestReportHelper:
    """Test cases for other ReportHelper methods."""

    def testbuild_project_report_data_success(self, report_helper):
        """Test building project report data successfully."""
        result = report_helper.build_project_report_data(
            project_code="TEST_PROJECT", report_type="xlsx", selection_type="all", include_vex=False
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "xlsx",
            "async": "1",
            "include_vex": False,
            "selection_type": "all",
        }
        assert result == expected

    def testbuild_project_report_data_invalid_type(self, report_helper):
        """Test validation error for invalid project report type."""
        with pytest.raises(
            ValidationError, match="Report type 'html' is not supported for project scope"
        ):
            report_helper.build_project_report_data(project_code="TEST_PROJECT", report_type="html")

    def testbuild_project_report_data_with_all_options(self, report_helper):
        """Test building project report data with all optional parameters."""
        result = report_helper.build_project_report_data(
            project_code="TEST_PROJECT",
            report_type="spdx_lite",
            selection_type="custom",
            selection_view="licenses",
            disclaimer="Custom disclaimer text",
            include_vex=True,
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "spdx_lite",
            "async": "1",
            "include_vex": True,
            "selection_type": "custom",
            "selection_view": "licenses",
            "disclaimer": "Custom disclaimer text",
        }
        assert result == expected

    def testbuild_scan_report_data_with_all_options(self, report_helper):
        """Test building scan report data with all optional parameters."""
        result = report_helper.build_scan_report_data(
            scan_code="TEST_SCAN",
            report_type="spdx",
            selection_type="vulnerabilities",
            selection_view="detailed",
            disclaimer="Scan disclaimer",
            include_vex=False,
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "spdx",
            "async": "1",  # spdx is async
            "include_vex": False,
            "selection_type": "vulnerabilities",
            "selection_view": "detailed",
            "disclaimer": "Scan disclaimer",
        }
        assert result == expected

    @pytest.mark.parametrize(
        "report_type,expected_async",
        [
            ("xlsx", "1"),
            ("spdx", "1"),
            ("spdx_lite", "1"),
            ("cyclone_dx", "1"),
            ("basic", "1"),
            ("html", "0"),
            ("dynamic_top_matched_components", "0"),
            ("string_match", "0"),
        ],
    )
    def test_scan_report_async_types(self, report_helper, report_type, expected_async):
        """Test async/sync behavior for different scan report types."""
        result = report_helper.build_scan_report_data(
            scan_code="TEST_SCAN", report_type=report_type
        )

        assert result["async"] == expected_async
        assert result["scan_code"] == "TEST_SCAN"
        assert result["report_type"] == report_type

    def testbuild_project_report_data_minimal(self, report_helper):
        """Test building project report data with minimal parameters."""
        result = report_helper.build_project_report_data(
            project_code="TEST_PROJECT", report_type="spdx"
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "spdx",
            "async": "1",  # Default value
            "include_vex": True,  # Default value
        }
        assert result == expected

    def testbuild_scan_report_data_async(self, report_helper):
        """Test building scan report data for async report types."""
        result = report_helper.build_scan_report_data(
            scan_code="TEST_SCAN",
            report_type="xlsx",
            selection_type="all",
            disclaimer="Test disclaimer",
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "xlsx",
            "async": "1",  # xlsx is async
            "include_vex": True,
            "selection_type": "all",
            "disclaimer": "Test disclaimer",
        }
        assert result == expected

    def testbuild_scan_report_data_sync(self, report_helper):
        """Test building scan report data for sync report types."""
        result = report_helper.build_scan_report_data(
            scan_code="TEST_SCAN", report_type="html"  # HTML is sync
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "html",
            "async": "0",  # html is sync
            "include_vex": True,
        }
        assert result == expected
