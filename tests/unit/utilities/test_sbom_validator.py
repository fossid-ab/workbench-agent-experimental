# tests/unit/utilities/test_sbom_validator.py

import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.utilities.sbom_validator import SBOMValidator


# Fixtures to provide paths to test SBOM files
@pytest.fixture
def cyclonedx_sbom_path():
    return os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "cyclonedx-bom.json")


@pytest.fixture
def spdx_sbom_path():
    return os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "spdx-document.rdf")


class TestSBOMValidatorWithFixtures:
    """Test cases using real SBOM files."""

    def test_validate_cyclonedx_from_file(self, cyclonedx_sbom_path):
        """Test successful validation of a real CycloneDX file."""
        assert os.path.exists(cyclonedx_sbom_path), "Fixture file is missing"

        format_name, version, metadata, doc = SBOMValidator.validate_sbom_file(cyclonedx_sbom_path)

        assert format_name == "cyclonedx"
        assert version == "1.5"
        assert metadata["components_count"] > 0
        assert "serial_number" in metadata
        assert doc is not None

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_validate_spdx_from_file(self, mock_validate_spdx, spdx_sbom_path):
        """Test successful validation of a real SPDX file."""
        assert os.path.exists(spdx_sbom_path), "Fixture file is missing"

        # Mock the SPDX validation to return expected values
        mock_doc = MagicMock()
        mock_validate_spdx.return_value = ("spdx", "2.3", {"packages_count": 5}, mock_doc)

        format_name, version, metadata, doc = SBOMValidator.validate_sbom_file(spdx_sbom_path)

        assert format_name == "spdx"
        assert version == "2.3"
        assert metadata["packages_count"] > 0
        assert doc is not None
        mock_validate_spdx.assert_called_once_with(spdx_sbom_path)

    def test_prepare_cyclonedx_no_conversion(self, cyclonedx_sbom_path):
        """CycloneDX should not require conversion."""
        format_name, version, metadata, doc = SBOMValidator.validate_sbom_file(cyclonedx_sbom_path)

        upload_path = SBOMValidator.prepare_sbom_for_upload(cyclonedx_sbom_path, format_name, doc)

        assert upload_path == cyclonedx_sbom_path

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_prepare_spdx_rdf_no_conversion(self, mock_validate_spdx, spdx_sbom_path):
        """SPDX RDF should not require conversion."""
        # Mock the SPDX validation to return expected values
        mock_doc = MagicMock()
        mock_validate_spdx.return_value = ("spdx", "2.3", {"packages_count": 3}, mock_doc)

        format_name, version, metadata, doc = SBOMValidator.validate_sbom_file(spdx_sbom_path)

        upload_path = SBOMValidator.prepare_sbom_for_upload(spdx_sbom_path, format_name, doc)

        assert upload_path == spdx_sbom_path
        mock_validate_spdx.assert_called_once_with(spdx_sbom_path)


class TestFormatDetection:
    """Test cases for SBOM format detection."""

    def test_detect_cyclonedx_from_file(self, cyclonedx_sbom_path):
        """Test detection of CycloneDX JSON format from a real file."""
        result = SBOMValidator._detect_sbom_format(cyclonedx_sbom_path)
        assert result == "cyclonedx"

    def test_detect_spdx_rdf_from_file(self, spdx_sbom_path):
        """Test detection of SPDX RDF format from a real file."""
        result = SBOMValidator._detect_sbom_format(spdx_sbom_path)
        assert result == "spdx"


class TestCycloneDXValidationErrors:
    """Test cases for CycloneDX validation error conditions."""

    @patch.dict(sys.modules, {"cyclonedx.validation": None, "cyclonedx.schema": None})
    def test_validate_cyclonedx_missing_library(self):
        """Test validation fails when CycloneDX library is missing."""
        with pytest.raises(ValidationError, match="CycloneDX library not available"):
            SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_invalid_format(self):
        """Test CycloneDX validation fails for invalid format."""
        invalid_json = {"bomFormat": "InvalidFormat", "specVersion": "1.6"}

        json_content = json.dumps(invalid_json)

        with patch("builtins.open", mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="does not appear to be a CycloneDX BOM"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_missing_spec_version(self):
        """Test CycloneDX validation fails for missing spec version."""
        invalid_json = {"bomFormat": "CycloneDX"}

        json_content = json.dumps(invalid_json)

        with patch("builtins.open", mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="missing specVersion field"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_unsupported_version(self):
        """Test CycloneDX validation fails for unsupported version."""
        invalid_json = {"bomFormat": "CycloneDX", "specVersion": "2.0"}  # Unsupported version

        json_content = json.dumps(invalid_json)

        with patch("builtins.open", mock_open(read_data=json_content)):
            with pytest.raises(ValidationError, match="Unknown CycloneDX version"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_unsupported_upload_version(self):
        """Test CycloneDX validation fails for versions not supported for upload."""
        invalid_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",  # Valid but not supported for upload
        }

        json_content = json.dumps(invalid_json)

        with patch("builtins.open", mock_open(read_data=json_content)):
            with patch("cyclonedx.validation.json.JsonStrictValidator") as mock_validator_class:
                mock_validator = MagicMock()
                mock_validator.validate_str.return_value = []
                mock_validator_class.return_value = mock_validator

                with pytest.raises(
                    ValidationError, match="only versions 1.4, 1.5, 1.6 are supported for import"
                ):
                    SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_validation_errors(self):
        """Test CycloneDX validation fails with schema errors."""
        valid_cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            # Missing other required fields
        }
        json_content = json.dumps(valid_cyclonedx)
        with patch("builtins.open", mock_open(read_data=json_content)):
            with patch("cyclonedx.validation.json.JsonStrictValidator") as mock_validator_class:
                mock_validator = MagicMock()
                mock_validator.validate_str.return_value = [MagicMock(message="Validation Error")]
                mock_validator_class.return_value = mock_validator
                with pytest.raises(ValidationError, match="CycloneDX validation failed"):
                    SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_invalid_json(self):
        """Test CycloneDX validation fails for invalid JSON."""
        with patch("builtins.open", mock_open(read_data="{ 'bad': json }")):
            with pytest.raises(ValidationError, match="Invalid JSON format"):
                SBOMValidator._validate_cyclonedx("/path/to/file.json")

    def test_validate_cyclonedx_file_not_found(self):
        """Test CycloneDX validation fails for non-existent file."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with pytest.raises(FileSystemError, match="SBOM file not found"):
                SBOMValidator._validate_cyclonedx("/nonexistent/file.json")


class TestSPDXValidationErrors:
    """Test cases for SPDX validation error conditions."""

    @patch.dict(sys.modules, {"spdx_tools.spdx.parser.parse_anything": None})
    def test_validate_spdx_missing_library(self):
        """Test validation fails when SPDX library is missing."""
        with pytest.raises(ValidationError, match="SPDX tools library not available"):
            SBOMValidator._validate_spdx("/path/to/file.rdf")

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_validate_spdx_invalid_document(self, mock_validate_spdx):
        """Test SPDX validation fails if file is not a valid SPDX document."""
        mock_validate_spdx.side_effect = ValidationError("does not contain a valid SPDX document")

        with pytest.raises(ValidationError, match="does not contain a valid SPDX document"):
            SBOMValidator._validate_spdx("/path/to/file.rdf")

        mock_validate_spdx.assert_called_once_with("/path/to/file.rdf")

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_validate_spdx_validation_errors(self, mock_validate_spdx):
        """Test SPDX validation fails with schema errors."""
        mock_validate_spdx.side_effect = ValidationError("SPDX document validation failed")

        with pytest.raises(ValidationError, match="SPDX document validation failed"):
            SBOMValidator._validate_spdx("/path/to/file.rdf")

        mock_validate_spdx.assert_called_once_with("/path/to/file.rdf")

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_validate_spdx_unsupported_version(self, mock_validate_spdx):
        """Test SPDX validation fails for unsupported version."""
        mock_validate_spdx.side_effect = ValidationError(
            "subsequent validation relies on the correct version"
        )

        with pytest.raises(
            ValidationError, match="subsequent validation relies on the correct version"
        ):
            SBOMValidator._validate_spdx("/path/to/file.rdf")

        mock_validate_spdx.assert_called_once_with("/path/to/file.rdf")

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._validate_spdx")
    def test_validate_spdx_file_not_found(self, mock_validate_spdx):
        """Test SPDX validation fails for non-existent file."""
        mock_validate_spdx.side_effect = FileSystemError("SBOM file not found")

        with pytest.raises(FileSystemError, match="SBOM file not found"):
            SBOMValidator._validate_spdx("/nonexistent/file.rdf")

        mock_validate_spdx.assert_called_once_with("/nonexistent/file.rdf")


class TestCleanupUtility:
    """Test cases for the cleanup utility."""

    def test_cleanup_temp_file_success(self):
        """Test successful cleanup of temporary file."""
        temp_file = "/tmp/spdx_converted_abc123.rdf"

        with patch("os.path.exists", return_value=True):
            with patch("os.unlink") as mock_unlink:
                with patch("tempfile.gettempdir", return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(temp_file)
                    mock_unlink.assert_called_once_with(temp_file)

    def test_cleanup_temp_file_not_temp(self):
        """Test cleanup skips non-temporary files."""
        regular_file = "/home/user/regular_file.rdf"

        with patch("os.path.exists", return_value=True):
            with patch("os.unlink") as mock_unlink:
                with patch("tempfile.gettempdir", return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(regular_file)
                    mock_unlink.assert_not_called()

    def test_cleanup_temp_file_not_exists(self):
        """Test cleanup handles non-existent file gracefully."""
        temp_file = "/tmp/nonexistent.rdf"

        with patch("os.path.exists", return_value=False):
            with patch("os.unlink") as mock_unlink:
                with patch("tempfile.gettempdir", return_value="/tmp"):
                    SBOMValidator.cleanup_temp_file(temp_file)
                    mock_unlink.assert_not_called()

    def test_cleanup_temp_file_failure(self):
        """Test cleanup handles unlink failure gracefully."""
        temp_file = "/tmp/spdx_converted_abc123.rdf"

        with patch("os.path.exists", return_value=True):
            with patch("os.unlink", side_effect=OSError("Permission denied")):
                with patch("tempfile.gettempdir", return_value="/tmp"):
                    with patch(
                        "workbench_agent.utilities.sbom_validator.logger.warning"
                    ) as mock_warning:
                        SBOMValidator.cleanup_temp_file(temp_file)
                        mock_warning.assert_called_once()


class TestSupportedFormatsMethod:
    """Test cases for get_supported_formats method."""

    def test_get_supported_formats_structure(self):
        """Test that get_supported_formats returns the expected structure."""
        formats = SBOMValidator.get_supported_formats()

        assert isinstance(formats, dict)
        assert "cyclonedx" in formats
        assert "spdx" in formats

        # Check CycloneDX format
        cyclonedx_info = formats["cyclonedx"]
        assert "name" in cyclonedx_info
        assert "supported_versions" in cyclonedx_info
        assert "supported_extensions" in cyclonedx_info
        assert isinstance(cyclonedx_info["supported_versions"], list)
        assert isinstance(cyclonedx_info["supported_extensions"], list)

        # Check SPDX format
        spdx_info = formats["spdx"]
        assert "name" in spdx_info
        assert "supported_versions" in spdx_info
        assert "supported_extensions" in spdx_info
        assert isinstance(spdx_info["supported_versions"], list)
        assert isinstance(spdx_info["supported_extensions"], list)

        # Check that SPDX now includes JSON extension
        assert ".json" in spdx_info["supported_extensions"]


class TestSBOMPreparation:
    """Test cases for SBOM preparation functionality."""

    def test_prepare_cyclonedx_no_conversion(self):
        """Test that CycloneDX files don't need conversion."""
        parsed_bom = {"bomFormat": "CycloneDX", "specVersion": "1.6"}

        result = SBOMValidator.prepare_sbom_for_upload(
            "/path/to/file.json", "cyclonedx", parsed_bom
        )

        assert result == "/path/to/file.json"  # Original file returned

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._prepare_spdx_for_upload")
    def test_prepare_spdx_rdf_no_conversion(self, mock_prepare_spdx):
        """Test that SPDX RDF files don't need conversion."""
        # Mock the SPDX preparation to return the original file (no conversion needed)
        mock_prepare_spdx.return_value = "/path/to/file.rdf"

        parsed_document = MagicMock()

        result = SBOMValidator.prepare_sbom_for_upload("/path/to/file.rdf", "spdx", parsed_document)

        assert result == "/path/to/file.rdf"  # Original file returned
        mock_prepare_spdx.assert_called_once_with("/path/to/file.rdf", parsed_document)

    @patch("workbench_agent.utilities.sbom_validator.SBOMValidator._prepare_spdx_for_upload")
    def test_prepare_spdx_json_with_conversion(self, mock_prepare_spdx):
        """Test that SPDX JSON files are converted to RDF."""
        # Mock the SPDX preparation to return a converted file path
        mock_prepare_spdx.return_value = "/tmp/spdx_converted_abc123.rdf"

        parsed_document = MagicMock()

        result = SBOMValidator.prepare_sbom_for_upload(
            "/path/to/file.json", "spdx", parsed_document
        )

        assert result == "/tmp/spdx_converted_abc123.rdf"
        mock_prepare_spdx.assert_called_once_with("/path/to/file.json", parsed_document)

    def test_prepare_unknown_format_error(self):
        """Test that unknown formats raise an error."""
        with pytest.raises(ValidationError, match="Unknown SBOM format: unknown"):
            SBOMValidator.prepare_sbom_for_upload("/path/to/file.json", "unknown", {})
