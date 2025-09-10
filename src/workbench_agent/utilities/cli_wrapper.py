"""
CLI Wrapper for FossID CLI interactions.

This module provides a wrapper for interacting with the FossID CLI tool,
particularly for blind scan functionality.
"""

import logging
import os
import random
import subprocess
import sys
import traceback
from typing import Optional

from workbench_agent.exceptions import FileSystemError, ProcessError

logger = logging.getLogger("workbench-agent")


class CliWrapper:
    """
    A class to interact with the FossID CLI.

    Attributes:
        cli_path (str): Path to the executable file "fossid-cli"
        timeout (str): Timeout for CLI expressed in seconds
    """

    def __init__(self, cli_path: str, timeout: str = "120"):
        """
        Initialize CliWrapper.

        Args:
            cli_path: Path to the fossid-cli executable
            timeout: Timeout in seconds (default: "120")

        Raises:
            FileSystemError: If cli_path doesn't exist or isn't executable
        """
        self.cli_path = cli_path
        self.timeout = timeout

        # Validate CLI path exists and is executable
        if not os.path.exists(cli_path):
            raise FileSystemError(f"FossID CLI not found at path: {cli_path}")
        if not os.access(cli_path, os.X_OK):
            raise FileSystemError(f"FossID CLI not executable: {cli_path}")

        logger.debug(f"CliWrapper initialized with cli_path={cli_path}, timeout={timeout}")

    def get_version(self) -> str:
        """
        Get CLI version.

        Returns:
            str: Version information from fossid-cli

        Raises:
            ProcessError: If CLI execution fails
        """
        args = [self.cli_path, "--version"]
        logger.debug(f"Getting CLI version with command: {' '.join(args)}")

        try:
            result = subprocess.check_output(
                args, stderr=subprocess.STDOUT, timeout=int(self.timeout)
            )
            version = result.decode("utf-8").strip()
            logger.info(f"FossID CLI version: {version}")
            return version
        except subprocess.TimeoutExpired as e:
            error_msg = f"CLI version check timed out after {self.timeout} seconds"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except subprocess.CalledProcessError as e:
            error_msg = f"CLI version check failed: {e.cmd} (exit code: {e.returncode})"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error getting CLI version: {e}"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e

    def blind_scan(self, path: str, run_dependency_analysis: bool = False) -> str:
        """
        Call fossid-cli on a given path to generate hashes of the files from that path.

        Args:
            path: Path of the code to be scanned
            run_dependency_analysis: Whether to run dependency analysis or not

        Returns:
            str: Path to temporary .fossid file containing generated hashes

        Raises:
            FileSystemError: If the input path doesn't exist
            ProcessError: If CLI execution fails
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Scan path does not exist: {path}")

        temporary_file_path = f"/tmp/blind_scan_result_{self.randstring(8)}.fossid"
        logger.info(f"Starting blind scan of path: {path}")
        logger.debug(f"Temporary file will be created at: {temporary_file_path}")

        # Create temporary file, make it empty if already exists
        try:
            with open(temporary_file_path, "w") as f:
                pass  # Create empty file
        except Exception as e:
            raise FileSystemError(
                f"Failed to create temporary file {temporary_file_path}: {e}"
            ) from e

        # Build command - no longer using external timeout command
        cmd_args = [self.cli_path, "--local", "--enable-sha1=1"]

        if run_dependency_analysis:
            cmd_args.append("--dependency-analysis=1")
            logger.debug("Dependency analysis enabled for blind scan")

        cmd_args.append(path)
        logger.debug(f"Executing blind scan command: {' '.join(cmd_args)}")

        try:
            # Execute command and redirect output to temporary file
            with open(temporary_file_path, "w") as outfile:
                result = subprocess.run(
                    cmd_args,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=int(self.timeout),
                )

            if result.returncode != 0:
                error_msg = f"Blind scan failed with exit code {result.returncode}: {result.stderr}"
                logger.error(error_msg)
                # Clean up temporary file
                if os.path.exists(temporary_file_path):
                    os.remove(temporary_file_path)
                raise ProcessError(error_msg)

            # Verify temporary file was created and has content
            if not os.path.exists(temporary_file_path):
                raise ProcessError(f"Temporary file was not created: {temporary_file_path}")

            file_size = os.path.getsize(temporary_file_path)
            if file_size == 0:
                logger.warning("Blind scan completed but generated empty results file")
            else:
                logger.info(
                    f"Blind scan completed successfully. Generated {file_size} bytes of hash data."
                )

            return temporary_file_path

        except subprocess.TimeoutExpired as e:
            error_msg = f"Blind scan timed out after {self.timeout} seconds"
            logger.error(error_msg)
            # Clean up temporary file
            if os.path.exists(temporary_file_path):
                os.remove(temporary_file_path)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during blind scan: {e}"
            logger.error(error_msg)
            logger.debug(traceback.format_exc())
            # Clean up temporary file
            if os.path.exists(temporary_file_path):
                os.remove(temporary_file_path)
            raise ProcessError(error_msg) from e

    @staticmethod
    def randstring(length: int = 10) -> str:
        """
        Generate a random string of a given length.

        Parameters:
            length: Length of the generated string (default: 10)

        Returns:
            str: Random string of specified length
        """
        valid_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join((random.choice(valid_letters) for i in range(length)))

    def cleanup_temp_file(self, file_path: str) -> bool:
        """
        Clean up a temporary file created by blind scan.

        Args:
            file_path: Path to the temporary file to delete

        Returns:
            bool: True if file was successfully deleted, False otherwise
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"Cleaned up temporary file: {file_path}")
                return True
            else:
                logger.warning(f"Temporary file does not exist: {file_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to clean up temporary file {file_path}: {e}")
            return False
