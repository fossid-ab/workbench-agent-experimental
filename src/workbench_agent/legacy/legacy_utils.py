"""
Legacy utilities for the Workbench Agent.

This module provides legacy utility functions including result handling
and time formatting utilities.
"""

import json
import logging
import os
from argparse import Namespace
from typing import Any, Dict, Optional, Union

from workbench_agent.exceptions import FileSystemError

logger = logging.getLogger("workbench-agent")


def save_results(params: Namespace, results: Dict[str, Any]) -> None:
    """
    Saves the scanning results to a specified path.

    Args:
        params: Parsed command line parameters containing path_result
        results: The scan results to be saved

    Note:
        If params.path_result is not provided, no action is taken.
        The function handles various path scenarios:
        - Directory: saves as wb_results.json in the directory
        - Existing file: overwrites the file
        - Non-existing path: creates directories and file as needed
    """
    if not hasattr(params, "path_result") or not params.path_result:
        return

    logger.debug(f"Saving results to path: {params.path_result}")

    try:
        if os.path.isdir(params.path_result):
            # If it's a directory, save as wb_results.json in that directory
            fname = os.path.join(params.path_result, "wb_results.json")
            _save_json_file(fname, results)

        elif os.path.isfile(params.path_result):
            # If it's an existing file, use it directly but ensure .json extension
            fname = params.path_result
            _folder = os.path.dirname(params.path_result)
            _fname = os.path.basename(params.path_result)

            if _fname and not _fname.endswith(".json"):
                try:
                    # Try to replace extension with .json
                    if "." in _fname:
                        extension = _fname.split(".")[-1]
                        _fname = _fname.replace(f".{extension}", ".json")
                    else:
                        _fname = f"{_fname}.json"
                    fname = os.path.join(_folder, _fname)
                except (TypeError, IndexError):
                    _fname = f"{_fname.replace('.', '_')}.json"
                    fname = os.path.join(_folder, _fname)

            os.makedirs(_folder, exist_ok=True)
            _save_json_file(fname, results)

        else:
            # Path doesn't exist - create it
            fname = params.path_result

            if fname.endswith(".json"):
                _folder = os.path.dirname(fname)
            else:
                if "." in fname:
                    _folder = os.path.dirname(fname)
                else:
                    # Treat as directory name
                    _folder = fname
                    fname = os.path.join(_folder, "wb_results.json")

            if _folder:
                os.makedirs(_folder, exist_ok=True)
            _save_json_file(fname, results)

    except PermissionError as e:
        logger.error(f"Permission denied when trying to save results: {e}")
        print(f"Error: Permission denied when trying to save results to {params.path_result}")
    except Exception as e:
        logger.error(f"Error trying to save results to {params.path_result}: {e}")
        print(f"Error trying to save results to {params.path_result}: {e}")


def _save_json_file(file_path: str, data: Dict[str, Any]) -> None:
    """
    Save data to a JSON file.

    Args:
        file_path: Path to save the file
        data: Data to save as JSON

    Raises:
        Exception: If file writing fails
    """
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(json.dumps(data, indent=4, ensure_ascii=False))
        print(f"Results saved to: {file_path}")
        logger.info(f"Results successfully saved to: {file_path}")
    except Exception as e:
        logger.error(f"Failed to write results to {file_path}: {e}")
        print(f"Error trying to write results to {file_path}")
        raise


def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """
    Formats a duration in seconds into a human-readable string.

    Args:
        duration_seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds))
    except (ValueError, TypeError):
        return "Invalid Duration"

    minutes, seconds = divmod(int(duration_seconds), 60)
    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0:
        return f"{minutes} minutes"
    elif seconds == 1:
        return f"1 second"
    else:
        return f"{seconds} seconds"
