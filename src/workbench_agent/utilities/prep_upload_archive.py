import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional, Set

from workbench_agent.exceptions import FileSystemError

logger = logging.getLogger("workbench-agent")


class UploadArchivePrep:
    """
    Handles creation and preparation of archives for upload to Workbench.
    Supports ZIP format with intelligent exclusions and validation.
    """

    # Default exclusions for cleaner archives
    DEFAULT_EXCLUSIONS: Set[str] = {
        ".git",
        ".svn",
        ".hg",  # Version control
        ".DS_Store",
        "Thumbs.db",  # OS files
        "__pycache__",
        "*.pyc",  # Python cache
        "node_modules",  # Node.js
        ".vscode",
        ".idea",  # IDE files
        "*.tmp",
        "*.temp",  # Temporary files
    }

    @staticmethod
    def should_exclude_file(file_path: str, exclusions: Optional[Set[str]] = None) -> bool:
        """
        Determines if a file should be excluded from the archive.

        Args:
            file_path: Path to the file to check
            exclusions: Set of patterns to exclude (uses defaults if None)

        Returns:
            bool: True if file should be excluded
        """
        if exclusions is None:
            exclusions = UploadArchivePrep.DEFAULT_EXCLUSIONS

        path_obj = Path(file_path)

        # Check if any part of the path matches exclusions
        for part in path_obj.parts:
            if part in exclusions:
                return True

        # Check filename patterns (basic wildcard support)
        filename = path_obj.name
        for pattern in exclusions:
            if pattern.startswith("*") and filename.endswith(pattern[1:]):
                return True

        return False

    @staticmethod
    def validate_file_for_archive(file_path: str) -> bool:
        """
        Validates if a file can be safely added to an archive.

        Args:
            file_path: Path to the file to validate

        Returns:
            bool: True if file is safe to archive
        """
        try:
            # Check if it's a regular file (not broken symlink, device file, etc.)
            if not os.path.isfile(file_path):
                return False

            # Check if file is readable
            if not os.access(file_path, os.R_OK):
                return False

            # Basic size check (skip empty files that might be problematic)
            try:
                stat_info = os.stat(file_path)
                # Allow empty files, but not special files with zero size
                if stat_info.st_size == 0 and not os.path.isfile(file_path):
                    return False
            except (OSError, IOError):
                return False

            return True

        except Exception as e:
            logger.debug(f"File validation failed for {file_path}: {e}")
            return False

    @staticmethod
    def create_zip_archive(
        source_path: str, exclusions: Optional[Set[str]] = None, archive_name: Optional[str] = None
    ) -> str:
        """
        Creates a ZIP archive from a directory, suitable for upload to Workbench.
        Respects .gitignore patterns and excludes common development files.

        Args:
            source_path: Path to the directory to archive
            exclusions: Set of patterns to exclude (uses defaults if None)
            archive_name: Custom archive name (auto-generated if None)

        Returns:
            str: Path to the created archive

        Raises:
            FileSystemError: If archive creation fails
        """
        if not os.path.isdir(source_path):
            raise FileSystemError(f"Source path is not a directory: {source_path}")

        try:
            # Create temporary directory for the archive
            temp_dir = tempfile.mkdtemp(prefix="workbench_upload_")

            # Generate archive name if not provided
            if archive_name is None:
                source_basename = os.path.basename(os.path.abspath(source_path))
                archive_name = f"{source_basename}_upload.zip"
            elif not archive_name.endswith(".zip"):
                archive_name = f"{archive_name}.zip"

            archive_path = os.path.join(temp_dir, archive_name)

            logger.debug(f"Creating ZIP archive: {archive_path}")
            logger.debug(f"Source directory: {source_path}")

            # Parse gitignore patterns for intelligent exclusions
            gitignore_patterns = UploadArchivePrep._parse_gitignore(source_path)
            has_gitignore = len(gitignore_patterns) > 0

            files_added = 0
            files_excluded = 0

            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
                abs_path = os.path.abspath(source_path)

                print("Creating zip archive (excluding system files and respecting .gitignore)...")

                for root, dirs, files in os.walk(abs_path):
                    # Get relative path from source directory
                    rel_root = os.path.relpath(root, abs_path)
                    normalized_rel_root = "" if rel_root == "." else rel_root

                    # Filter out excluded directories early
                    dirs_to_remove = []
                    for d in dirs:
                        dir_path = os.path.join(root, d)

                        # Check default exclusions
                        if UploadArchivePrep.should_exclude_file(dir_path, exclusions):
                            dirs_to_remove.append(d)
                            files_excluded += 1
                            continue

                        # Check gitignore patterns
                        if has_gitignore:
                            relative_dir_path = (
                                os.path.join(normalized_rel_root, d) if normalized_rel_root else d
                            )
                            if UploadArchivePrep._is_excluded_by_gitignore(
                                relative_dir_path, gitignore_patterns, is_dir=True
                            ):
                                dirs_to_remove.append(d)
                                files_excluded += 1

                    # Remove excluded directories from processing
                    for d in dirs_to_remove:
                        dirs.remove(d)

                    # Process files
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_file_path = os.path.relpath(file_path, abs_path)

                        # Check default exclusions
                        if UploadArchivePrep.should_exclude_file(file_path, exclusions):
                            files_excluded += 1
                            logger.debug(f"Excluded from archive: {rel_file_path}")
                            continue

                        # Check gitignore patterns
                        if has_gitignore and UploadArchivePrep._is_excluded_by_gitignore(
                            rel_file_path, gitignore_patterns
                        ):
                            files_excluded += 1
                            logger.debug(f"Excluded by .gitignore: {rel_file_path}")
                            continue

                        # Validate file
                        if not UploadArchivePrep.validate_file_for_archive(file_path):
                            files_excluded += 1
                            logger.warning(
                                f"Skipped invalid file: {rel_file_path} (type: {UploadArchivePrep._get_file_type_description(file_path)})"
                            )
                            continue

                        try:
                            zipf.write(file_path, rel_file_path)
                            files_added += 1

                            if files_added % 100 == 0:  # Progress logging
                                logger.debug(f"Archived {files_added} files...")

                        except Exception as e:
                            files_excluded += 1
                            logger.warning(f"Failed to archive {rel_file_path}: {e}")
                            continue

                print(
                    f"Added {files_added} files to archive (excluded {files_excluded} files/directories)"
                )

            # Verify the archive was created successfully
            if not os.path.exists(archive_path) or os.path.getsize(archive_path) == 0:
                raise FileSystemError("Archive creation failed - file is missing or empty")

            archive_size_mb = os.path.getsize(archive_path) / (1024 * 1024)
            logger.info(f"Archive created successfully: {archive_path}")
            logger.info(f"Archive size: {archive_size_mb:.1f}MB")
            logger.info(f"Files added: {files_added}, Files excluded: {files_excluded}")

            return archive_path

        except Exception as e:
            logger.error(f"Failed to create archive for {source_path}: {e}", exc_info=True)
            # Clean up on failure
            if "temp_dir" in locals() and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to cleanup temp directory: {cleanup_err}")
            raise FileSystemError(f"Archive creation failed: {e}") from e

    @staticmethod
    def _parse_gitignore(directory_path: str) -> List[str]:
        """
        Parses .gitignore file and returns list of patterns.

        Args:
            directory_path: Path to directory containing .gitignore

        Returns:
            List[str]: List of gitignore patterns
        """
        gitignore_path = os.path.join(directory_path, ".gitignore")
        patterns = []

        if not os.path.exists(gitignore_path):
            return patterns

        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        patterns.append(line)
            logger.debug(f"Parsed {len(patterns)} patterns from .gitignore")
        except (OSError, IOError, UnicodeDecodeError) as e:
            logger.warning(f"Could not read .gitignore file: {e}")

        return patterns

    @staticmethod
    def _get_file_type_description(file_path: str) -> str:
        """
        Gets a description of the file type for logging purposes.

        Args:
            file_path: Path to the file

        Returns:
            str: Description of file type
        """
        try:
            if os.path.islink(file_path):
                target = os.path.realpath(file_path)
                if os.path.exists(target):
                    return f"symlink -> {target}"
                else:
                    return "broken symlink"
            elif os.path.isdir(file_path):
                return "directory"
            elif os.path.isfile(file_path):
                return "regular file"
            else:
                return "special file"
        except (OSError, IOError):
            return "unknown"

    @staticmethod
    def _is_excluded_by_gitignore(
        path: str, gitignore_patterns: List[str], is_dir: bool = False
    ) -> bool:
        """
        Checks if a path should be excluded based on gitignore patterns.

        Args:
            path: Relative path from project root
            gitignore_patterns: List of patterns from .gitignore
            is_dir: Whether the path is a directory

        Returns:
            bool: True if the path should be excluded
        """
        if not gitignore_patterns:
            return False

        # Normalize path (replace backslashes with forward slashes)
        path = path.replace(os.sep, "/")
        basename = os.path.basename(path)

        # For directories, we'll check with and without trailing slash
        if is_dir and not path.endswith("/"):
            dir_path = path + "/"
        else:
            dir_path = path

        # Common directory patterns to check specifically
        if (
            is_dir
            and basename in ["build", "dist"]
            and any(
                p in [basename, basename + "/", "/" + basename, "/" + basename + "/"]
                for p in gitignore_patterns
            )
        ):
            logger.debug(f"✓ Excluded '{path}' - matched common directory pattern")
            return True

        for pattern in gitignore_patterns:
            pattern = pattern.replace(os.sep, "/")

            # Case 1: Direct matches
            if path == pattern or (is_dir and dir_path == pattern):
                return True

            # Case 2: Pattern with trailing slash (directory only)
            if (
                is_dir
                and pattern.endswith("/")
                and (dir_path.endswith(pattern) or dir_path == pattern[:-1])
            ):
                return True

            # Case 3: Pattern without leading slash (matches anywhere)
            if not pattern.startswith("/") and (
                basename == pattern
                or path.endswith("/" + pattern)
                or (is_dir and pattern.endswith("/") and dir_path.endswith("/" + pattern))
            ):
                return True

            # Case 4: Pattern with leading slash (matches from root)
            if pattern.startswith("/") and (
                path == pattern[1:] or (is_dir and dir_path == pattern[1:])
            ):
                return True

            # Case 5: Wildcard patterns (*.xyz)
            if pattern.startswith("*.") and basename.endswith(pattern[1:]):
                return True

        return False
