# tests/unit/api/helpers/test_upload_archive_prep.py

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.utilities.prep_upload_archive import UploadArchivePrep


# --- Tests for gitignore handling ---
def test_parse_gitignore_file_exists(mocker):
    """Test parsing a .gitignore file when the file exists."""
    # Setup explicit mock content
    mock_content = "node_modules/\n*.log\n# Comment\ntemp/\n"
    expected_patterns = ["node_modules/", "*.log", "temp/"]

    # Setup mock for open function with more robust error handling
    mock_open_func = mocker.mock_open(read_data=mock_content)

    # Apply mocks with safer approach that works in both pytest-mock and our fallback
    open_patch = mocker.patch("builtins.open", mock_open_func)
    isfile_patch = mocker.patch("os.path.exists", return_value=True)

    try:
        # Ensure mocks are applied
        assert open_patch is not None, "Failed to mock 'open' function"
        assert isfile_patch is not None, "Failed to mock 'os.path.isfile' function"

        # Get gitignore patterns - now using UploadArchivePrep static method
        patterns = UploadArchivePrep._parse_gitignore("/fake/path")

        # More detailed assertions with diagnostic output
        if len(patterns) != len(expected_patterns):
            print(f"ERROR: Expected {len(expected_patterns)} patterns but got {len(patterns)}")
            print(f"Mock content lines: {mock_content.splitlines()}")
            print(f"Parsed patterns: {patterns}")
            print(f"Expected patterns: {expected_patterns}")

        # Should have 3 patterns (comment line is excluded)
        assert len(patterns) == len(
            expected_patterns
        ), f"Expected {len(expected_patterns)} patterns but got {len(patterns)}: {patterns}"

        # Check each pattern explicitly
        for pattern in expected_patterns:
            assert (
                pattern in patterns
            ), f"Pattern '{pattern}' missing from parsed patterns: {patterns}"

    except Exception as e:
        print(f"Exception in test_parse_gitignore_file_exists: {str(e)}")
        print(f"Mock content: {mock_content}")
        print(f"Open mock called: {mock_open_func.called}")
        print(
            f"Isfile mock called: {isfile_patch.called if hasattr(isfile_patch, 'called') else 'Unknown'}"
        )
        raise


def test_parse_gitignore_file_not_exists(mocker):
    # Mock os.path.exists to return False
    mocker.patch("os.path.exists", return_value=False)

    patterns = UploadArchivePrep._parse_gitignore("/fake/path")

    # Should return empty list
    assert patterns == []


def test_is_excluded_by_gitignore_exact_match():
    patterns = ["node_modules/", "*.log", "build/"]

    # Test exact matches
    assert UploadArchivePrep._is_excluded_by_gitignore("node_modules", patterns, is_dir=True)
    assert UploadArchivePrep._is_excluded_by_gitignore("build", patterns, is_dir=True)

    # Test file match
    assert UploadArchivePrep._is_excluded_by_gitignore("error.log", patterns) is True
    assert UploadArchivePrep._is_excluded_by_gitignore("logs/debug.log", patterns) is True

    # Test non-match
    assert UploadArchivePrep._is_excluded_by_gitignore("src/app.js", patterns) is False
    assert UploadArchivePrep._is_excluded_by_gitignore("package.json", patterns) is False


def test_is_excluded_by_gitignore_empty_patterns():
    # Should return False for any path if patterns is empty
    assert UploadArchivePrep._is_excluded_by_gitignore("node_modules", []) is False
    assert UploadArchivePrep._is_excluded_by_gitignore("any/path", []) is False


# --- Tests for file operations ---
def test_create_zip_archive(mocker):
    """Test creating a ZIP archive from a directory structure."""
    # Create a temporary directory structure for testing
    temp_dir = None
    zip_path = None
    extract_dir = None

    try:
        # Use context manager for temporary directory to ensure cleanup
        with tempfile.TemporaryDirectory() as temp_str:
            temp_dir = Path(temp_str)

            # Create directory structure with more robust path handling
            (temp_dir / "src").mkdir()
            (temp_dir / "docs").mkdir()
            (temp_dir / ".git").mkdir()  # Should be excluded
            (temp_dir / "__pycache__").mkdir()  # Should be excluded

            # Create some files with more robust path handling
            (temp_dir / "src" / "main.py").write_text("print('Hello, world!')")
            (temp_dir / "docs" / "readme.md").write_text("# Test Project")
            (temp_dir / ".git" / "config").write_text("# Git config")
            (temp_dir / ".gitignore").write_text("*.log\nbuild/\n")

            # Create a file that should be excluded by gitignore
            (temp_dir / "debug.log").write_text("DEBUG LOG")
            (temp_dir / "build").mkdir()
            (temp_dir / "build" / "output.txt").write_text("Build output")

            # Add debug output for CI troubleshooting
            print(f"Debug - Created test directory structure at: {temp_dir}")
            print(f"Debug - Directory contents: {list(temp_dir.glob('**/*'))}")

            # Call the method to create a zip archive - capture any exceptions for better diagnostics
            try:
                zip_path = UploadArchivePrep.create_zip_archive(str(temp_dir))
                print(f"Debug - Created ZIP archive at: {zip_path}")
            except Exception as e:
                print(f"Debug - Error creating ZIP: {str(e)}")
                raise

            # Verify the zip file was created
            assert os.path.exists(zip_path), f"ZIP file was not created at {zip_path}"

            # Extract the contents to a new temp directory for verification
            with tempfile.TemporaryDirectory() as extract_str:
                extract_dir = Path(extract_str)

                try:
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        # Print ZIP contents for debugging
                        print(f"Debug - ZIP archive contents: {zip_ref.namelist()}")
                        zip_ref.extractall(extract_dir)
                except Exception as e:
                    print(f"Debug - Error extracting ZIP: {str(e)}")
                    raise

                # Get list of all extracted files - normalize paths for cross-platform compatibility
                extracted_files = []
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        # Normalize path for cross-platform comparison
                        norm_path = rel_path.replace(os.sep, "/")
                        extracted_files.append(norm_path)

                print(f"Debug - Extracted files: {extracted_files}")

                # Check included files - archives contain relative paths from source directory
                included_files = [
                    "src/main.py",
                    "docs/readme.md",
                    ".gitignore",  # .gitignore should be included
                ]
                for file_path in included_files:
                    norm_path = file_path.replace("/", os.sep)
                    assert (
                        norm_path in extracted_files or file_path in extracted_files
                    ), f"Expected file {file_path} not found in ZIP contents: {extracted_files}"

                # Check excluded files/directories (by .gitignore)
                excluded_gitignore = [
                    "debug.log",  # *.log pattern
                    "build/output.txt",  # build/ pattern
                ]
                for file_path in excluded_gitignore:
                    norm_path = file_path.replace("/", os.sep)
                    assert (
                        norm_path not in extracted_files and file_path not in extracted_files
                    ), f"Gitignore-excluded file {file_path} found in ZIP contents: {extracted_files}"

                # Check excluded directories (always excluded)
                excluded_dirs = [".git", "__pycache__"]
                for dir_name in excluded_dirs:
                    prefix = f"{dir_name}/"
                    has_excluded = any(
                        f.startswith(prefix) or f.startswith(prefix.replace("/", os.sep))
                        for f in extracted_files
                    )
                    assert (
                        not has_excluded
                    ), f"Always-excluded directory content from {dir_name} found in ZIP: {extracted_files}"

    except Exception as e:
        print(f"Test failed with error: {str(e)}")
        # Print additional debug information
        if temp_dir and os.path.exists(str(temp_dir)):
            print(f"Temp directory exists: {temp_dir}")
        if zip_path and os.path.exists(zip_path):
            print(f"ZIP file exists: {zip_path}")
        if extract_dir and os.path.exists(str(extract_dir)):
            print(f"Extract directory exists: {extract_dir}")
        raise

    finally:
        # Ensure cleanup happens even if assertions fail
        # Note: Using context managers above should handle most cleanup,
        # but this is a backup for the zip file which may be in a separate location
        if zip_path and os.path.exists(zip_path):
            try:
                parent_dir = os.path.dirname(zip_path)
                if os.path.exists(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception as e:
                print(f"Warning: Cleanup failed for {parent_dir}: {str(e)}")
