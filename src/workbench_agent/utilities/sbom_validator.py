# workbench_agent/utilities/sbom_validator.py

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from workbench_agent.exceptions import FileSystemError, ValidationError

logger = logging.getLogger("workbench-agent")


class SBOMValidator:
    """
    Utility class for validating SBOM files and converting them to Workbench-compatible formats.
    Supports CycloneDX JSON and SPDX in multiple formats (JSON, RDF, XML).
    """

    SUPPORTED_EXTENSIONS = {".json", ".rdf", ".xml", ".spdx"}

    @staticmethod
    def validate_sbom_file(file_path: str) -> Tuple[str, str, Dict[str, Any], Any]:
        """
        Validates an SBOM file and returns format information and parsed document.

        Args:
            file_path: Path to the SBOM file to validate

        Returns:
            Tuple[str, str, Dict[str, Any], Any]: (format, version, metadata, parsed_document)
            - format: "cyclonedx" or "spdx"
            - version: version string (e.g., "1.6", "2.3")
            - metadata: additional metadata about the document
            - parsed_document: parsed document object for reuse in preparation

        Raises:
            FileSystemError: If the file doesn't exist or can't be read
            ValidationError: If the file is not a valid SBOM or unsupported format/version
        """
        if not os.path.exists(file_path):
            raise FileSystemError(f"SBOM file does not exist: {file_path}")

        if not os.path.isfile(file_path):
            raise ValidationError(f"Path must be a file: {file_path}")

        file_ext = Path(file_path).suffix.lower()
        if file_ext not in SBOMValidator.SUPPORTED_EXTENSIONS:
            raise ValidationError(
                f"Unsupported file extension '{file_ext}'. Supported extensions: {', '.join(SBOMValidator.SUPPORTED_EXTENSIONS)}"
            )

        logger.debug(f"Validating SBOM file: {file_path}")

        # Detect format by content, not extension
        sbom_format = SBOMValidator._detect_sbom_format(file_path)
        logger.debug(f"Detected SBOM format: {sbom_format}")

        if sbom_format == "cyclonedx":
            return SBOMValidator._validate_cyclonedx(file_path)
        elif sbom_format == "spdx":
            return SBOMValidator._validate_spdx(file_path)

        # This case is defensive, as _detect_sbom_format should have already raised an error
        raise ValidationError(f"Unable to determine SBOM format for file: {file_path}")

    @staticmethod
    def prepare_sbom_for_upload(file_path: str, sbom_format: str, parsed_document: Any) -> str:
        """
        Prepares an SBOM file for upload to Workbench, converting format if needed.

        Args:
            file_path: Original file path
            sbom_format: Format detected during validation ("cyclonedx" or "spdx")
            parsed_document: Parsed document from validation step

        Returns:
            str: Path to file ready for upload (original or converted temp file)

        Raises:
            ValidationError: If conversion fails
        """
        if sbom_format == "cyclonedx":
            # CycloneDX is already in JSON format that Workbench expects
            return file_path
        elif sbom_format == "spdx":
            return SBOMValidator._prepare_spdx_for_upload(file_path, parsed_document)
        else:
            raise ValidationError(f"Unknown SBOM format: {sbom_format}")

    @staticmethod
    def validate_and_prepare_sbom(file_path: str) -> Tuple[str, str, Dict[str, Any], str]:
        """
        Validates an SBOM file and prepares it for upload to Workbench.
        This is a convenience method that combines validation and preparation.

        Args:
            file_path: Path to the SBOM file to validate

        Returns:
            Tuple[str, str, Dict[str, Any], str]: (format, version, metadata, upload_path)
            - format: "cyclonedx" or "spdx"
            - version: version string (e.g., "1.6", "2.3")
            - metadata: additional metadata about the document
            - upload_path: path to file ready for upload (original or converted temp file)

        Raises:
            FileSystemError: If the file doesn't exist or can't be read
            ValidationError: If the file is not a valid SBOM or unsupported format/version
        """
        # Validate the SBOM file
        sbom_format, version, metadata, parsed_document = SBOMValidator.validate_sbom_file(
            file_path
        )

        # Prepare for upload
        upload_path = SBOMValidator.prepare_sbom_for_upload(file_path, sbom_format, parsed_document)

        return sbom_format, version, metadata, upload_path

    @staticmethod
    def _detect_sbom_format(file_path: str) -> str:
        """
        Detects SBOM format by examining file content.

        Returns:
            str: "cyclonedx" or "spdx"
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                # Read first few KB to detect format
                content_preview = f.read(8192)
        except UnicodeDecodeError:
            # If it's not UTF-8, it might be RDF/XML
            try:
                with open(file_path, "r", encoding="latin-1") as f:
                    content_preview = f.read(8192)
            except Exception as e:
                raise ValidationError(f"Unable to read file content: {e}")
        except Exception as e:
            raise ValidationError(f"Unable to read file: {e}")

        content_lower = content_preview.lower()

        # Check for CycloneDX markers
        if '"bomformat"' in content_lower and '"cyclonedx"' in content_lower:
            return "cyclonedx"
        if '"bomFormat"' in content_preview and '"CycloneDX"' in content_preview:
            return "cyclonedx"

        # Check for SPDX markers
        spdx_markers = [
            '"spdxVersion"',
            '"spdxversion"',  # JSON format
            '"SPDXID"',
            '"spdxid"',  # JSON format
            "spdx:Document",
            "spdx:document",  # RDF format
            "<spdx:",
            "<SPDX:",  # XML format
            "SPDXVersion:",
            "spdxversion:",  # Tag-value format
        ]

        if any(marker in content_lower for marker in spdx_markers):
            return "spdx"

        # Additional checks for XML/RDF SPDX
        if ("<rdf:" in content_lower or "<RDF:" in content_lower) and "spdx" in content_lower:
            return "spdx"

        raise ValidationError(
            "Unable to detect SBOM format. File does not appear to be CycloneDX or SPDX."
        )

    @staticmethod
    def _validate_cyclonedx(file_path: str) -> Tuple[str, str, Dict[str, Any], Dict]:
        """
        Validates a CycloneDX file (JSON format).

        Returns:
            Tuple[str, str, Dict[str, Any], Dict]: (format, version, metadata, parsed_bom)
        """
        try:
            from cyclonedx.schema import SchemaVersion
            from cyclonedx.validation.json import JsonStrictValidator
        except ImportError as e:
            raise ValidationError(
                "CycloneDX library not available. Please install cyclonedx-python-lib."
            ) from e

        try:
            # Read the JSON file
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse JSON to check format and extract metadata
            bom_data = json.loads(content)

            # Check if it looks like a CycloneDX BOM
            if "bomFormat" not in bom_data or bom_data.get("bomFormat") != "CycloneDX":
                raise ValidationError(
                    "File does not appear to be a CycloneDX BOM (missing or incorrect bomFormat)"
                )

            # Get spec version
            spec_version = bom_data.get("specVersion", "")
            if not spec_version:
                raise ValidationError("CycloneDX BOM is missing specVersion field")

            # Map spec version to SchemaVersion enum
            version_mapping = {
                "1.6": SchemaVersion.V1_6,
                "1.5": SchemaVersion.V1_5,
                "1.4": SchemaVersion.V1_4,
                "1.3": SchemaVersion.V1_3,
                "1.2": SchemaVersion.V1_2,
                "1.1": SchemaVersion.V1_1,
                "1.0": SchemaVersion.V1_0,
            }

            schema_version = version_mapping.get(spec_version)
            if not schema_version:
                raise ValidationError(
                    f"Unknown CycloneDX version {spec_version}. Supported versions for validation: {', '.join(version_mapping.keys())}"
                )

            # Validate using the official validator for the detected version
            validator = JsonStrictValidator(schema_version)
            try:
                validation_errors = list(validator.validate_str(content))
                if validation_errors:
                    error_messages = [
                        str(error) for error in validation_errors[:5]
                    ]  # Show first 5 errors
                    raise ValidationError(
                        f"CycloneDX validation failed: {'; '.join(error_messages)}"
                    )
            except ValidationError:
                raise  # Re-raise validation errors as-is
            except Exception as validation_error:
                # If the validator itself fails, still try to proceed but log the issue
                logger.warning(f"CycloneDX validator encountered an issue: {validation_error}")
                # We'll still proceed if basic structure is valid

            # Check if version is supported for upload (1.4-1.6)
            supported_upload_versions = ["1.4", "1.5", "1.6"]
            if spec_version not in supported_upload_versions:
                raise ValidationError(
                    f"Valid CycloneDX {spec_version} SBOM detected, but only versions {', '.join(supported_upload_versions)} are supported for import. Please convert your SBOM to a supported version."
                )

            logger.debug(f"Successfully validated CycloneDX file, version {spec_version}")

            # Extract metadata
            metadata = {
                "spec_version": spec_version,
                "serial_number": bom_data.get("serialNumber"),
                "version": bom_data.get("version", 1),
                "components_count": len(bom_data.get("components", [])),
            }

            return "cyclonedx", spec_version, metadata, bom_data

        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON format: {e}") from e
        except FileNotFoundError:
            raise FileSystemError(f"SBOM file not found: {file_path}")
        except ValidationError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            logger.error(
                f"Unexpected error validating CycloneDX file '{file_path}': {e}", exc_info=True
            )
            raise ValidationError(f"Failed to validate CycloneDX file: {e}") from e

    @staticmethod
    def _validate_spdx(file_path: str) -> Tuple[str, str, Dict[str, Any], Any]:
        """
        Validates an SPDX file in any supported format.

        Returns:
            Tuple[str, str, Dict[str, Any], Any]: (format, version, metadata, parsed_document)
        """
        try:
            from spdx_tools.spdx.model import Document, Version
            from spdx_tools.spdx.parser.parse_anything import parse_file
            from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        except ImportError as e:
            raise ValidationError(
                "SPDX tools library not available. Please install spdx-tools."
            ) from e

        try:
            # Parse the SPDX file (handles JSON, RDF, XML, etc.)
            document = parse_file(file_path)

            if not isinstance(document, Document):
                raise ValidationError("File does not contain a valid SPDX document")

            # Validate the document
            validation_messages = validate_full_spdx_document(document)
            if validation_messages:
                error_messages = [msg.validation_message for msg in validation_messages]
                raise ValidationError(
                    f"SPDX document validation failed: {'; '.join(error_messages[:5])}"
                )  # Show first 5 errors

            # Get version
            spdx_version = document.creation_info.spdx_version
            if isinstance(spdx_version, Version):
                version_str = spdx_version.value.replace("SPDX-", "")
            else:
                version_str = str(spdx_version).replace("SPDX-", "")

            # Check if version is supported (2.0-2.3)
            supported_versions = {"2.0", "2.1", "2.2", "2.3"}
            if version_str not in supported_versions:
                raise ValidationError(
                    f"SPDX version {version_str} is not supported. Supported versions: {', '.join(supported_versions)}"
                )

            logger.debug(f"Successfully validated SPDX file, version {version_str}")

            metadata = {
                "spdx_version": version_str,
                "name": document.creation_info.name,
                "document_namespace": document.creation_info.document_namespace,
                "packages_count": len(document.packages) if document.packages else 0,
                "files_count": len(document.files) if document.files else 0,
            }

            return "spdx", version_str, metadata, document

        except ValidationError:
            raise  # Re-raise validation errors as-is
        except FileNotFoundError:
            raise FileSystemError(f"SBOM file not found: {file_path}")
        except Exception as e:
            logger.error(f"Unexpected error validating SPDX file '{file_path}': {e}", exc_info=True)
            raise ValidationError(f"Failed to validate SPDX file: {e}") from e

    @staticmethod
    def _prepare_spdx_for_upload(file_path: str, document: Any) -> str:
        """
        Prepares SPDX document for upload, converting to RDF format if needed.

        Args:
            file_path: Original file path
            document: Parsed SPDX document

        Returns:
            str: Path to file ready for upload (original or converted temp file)
        """
        # Check if we need to convert to RDF format for Workbench
        file_ext = Path(file_path).suffix.lower()
        if file_ext == ".json":
            # Convert JSON SPDX to RDF format
            logger.debug("Converting SPDX JSON to RDF format for Workbench compatibility")

            try:
                from spdx_tools.spdx.writer.write_anything import write_file
            except ImportError as e:
                raise ValidationError(
                    "SPDX tools library not available for conversion. Please install spdx-tools."
                ) from e

            # Create temporary RDF file
            temp_fd, temp_path = tempfile.mkstemp(suffix=".rdf", prefix="spdx_converted_")
            try:
                os.close(temp_fd)  # Close the file descriptor

                # Write document as RDF
                write_file(document, temp_path, validate=False)  # Already validated above

                logger.debug(f"Successfully converted SPDX to RDF format: {temp_path}")
                return temp_path

            except Exception as e:
                # Clean up temp file if conversion fails
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                raise ValidationError(f"Failed to convert SPDX JSON to RDF format: {e}") from e
        else:
            # Already in RDF/XML format, use original file
            return file_path

    @staticmethod
    def get_supported_formats() -> Dict[str, Dict[str, Any]]:
        """
        Returns information about supported SBOM formats.

        Returns:
            Dict containing supported formats and their details
        """
        return {
            "cyclonedx": {
                "name": "CycloneDX",
                "supported_versions": ["1.4", "1.5", "1.6"],
                "supported_extensions": [".json"],
                "description": "CycloneDX JSON format",
            },
            "spdx": {
                "name": "SPDX",
                "supported_versions": ["2.0", "2.1", "2.2", "2.3"],
                "supported_extensions": [".json", ".rdf", ".xml", ".spdx"],
                "description": "SPDX in JSON, RDF, or XML format (converted to RDF for upload)",
            },
        }

    @staticmethod
    def cleanup_temp_file(file_path: str) -> None:
        """
        Clean up temporary files created during conversion.

        Args:
            file_path: Path to temporary file to clean up
        """
        if file_path and os.path.exists(file_path) and file_path.startswith(tempfile.gettempdir()):
            try:
                os.unlink(file_path)
                logger.debug(f"Cleaned up temporary file: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file {file_path}: {e}")

    # Keep the old method for backward compatibility but mark as deprecated
    @staticmethod
    def validate_sbom_file_deprecated(file_path: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        DEPRECATED: Use validate_sbom_file or validate_and_prepare_sbom instead.
        This method is kept for backward compatibility.
        """
        logger.warning(
            "This validate_sbom_file method is deprecated. Use the new validate_sbom_file or validate_and_prepare_sbom instead."
        )
        format_name, version, metadata, _ = SBOMValidator.validate_sbom_file(file_path)
        return format_name, version, metadata
