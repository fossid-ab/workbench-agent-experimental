import json
import logging
import os
import re
from typing import Any, Dict, Optional, Union
import requests
from workbench_agent.api.download_api import DownloadAPI
from workbench_agent.exceptions import FileSystemError, ValidationError

logger = logging.getLogger("workbench-agent")


class ReportHelper(DownloadAPI):
    """
    Helper mixin to handle report generation payload building and downloading.
    This class is intended to be mixed into other API classes like ProjectsAPI and ScansAPI.
    """

    PROJECT_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx"}
    ASYNC_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx", "basic"}
    SCAN_REPORT_TYPES = {
        "html",
        "dynamic_top_matched_components",
        "xlsx",
        "spdx",
        "spdx_lite",
        "cyclone_dx",
        "string_match",
    }

    def build_project_report_data(
        self,
        project_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ) -> Dict[str, Any]:
        """
        Builds the data payload for a project report request.
        """
        if report_type not in self.PROJECT_REPORT_TYPES:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for project scope reports."
            )
        logger.info(
            f"Building data payload for '{report_type}' report for project '{project_code}'..."
        )
        payload_data = {
            "project_code": project_code,
            "report_type": report_type,
            "async": "1",
            "include_vex": include_vex,
        }
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer
        return payload_data

    def build_scan_report_data(
        self,
        scan_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ) -> Dict[str, Any]:
        """
        Builds the data payload for a scan report request.
        """
        use_async = report_type in self.ASYNC_REPORT_TYPES
        async_value = "1" if use_async else "0"
        logger.info(
            f"Building data payload for '{report_type}' report for scan '{scan_code}' (Async: {use_async})..."
        )
        payload_data = {
            "scan_code": scan_code,
            "report_type": report_type,
            "async": async_value,
            "include_vex": include_vex,
        }
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer
        return payload_data

    def download_project_report(self, process_id: int):
        """
        Downloads a generated project report using its process ID.
        """
        logger.debug(f"Attempting to download project report for process ID '{process_id}'...")
        return self._download_report("projects", process_id)

    def download_scan_report(self, process_id: int):
        """
        Downloads a generated scan report using its process ID.
        """
        logger.debug(f"Attempting to download scan report for process ID '{process_id}'...")
        return self._download_report("scans", process_id)

    @staticmethod
    def _save_report_content(
        response_or_content: Union[requests.Response, str, bytes, dict, list],
        output_dir: str,
        report_scope: str,
        name_component: str,
        report_type: str,
    ) -> None:
        """
        Saves report content (from response object or direct content) to a file.
        (Docstring omitted for brevity in this example, but should be kept)
        """
        if not output_dir:
            raise ValidationError("Output directory is not specified for saving report.")
        if not name_component:
            raise ValidationError(
                "Name component (scan/project name) is not specified for saving report."
            )
        if not report_type:
            raise ValidationError("Report type is not specified for saving report.")
        filename = ""
        content_to_write: Union[str, bytes] = b""
        write_mode = "wb"
        if isinstance(response_or_content, requests.Response):
            response = response_or_content
            # --- Always generate filename based on desired format ---
            safe_name = re.sub(
                r"[^\w\-]+", "_", name_component
            )  # Allow letters, numbers, underscore, hyphen
            safe_scope = report_scope  # Scope is already validated ('scan' or 'project')
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            extension_map = {
                "xlsx": "xlsx",
                "spdx": "rdf",
                "spdx_lite": "xlsx",
                "cyclone_dx": "json",
                "html": "html",
                "dynamic_top_matched_components": "html",
                "string_match": "xlsx",
                "basic": "txt",
            }
            ext = extension_map.get(report_type.lower(), "txt")  # Default to .txt if unknown
            filename = f"{safe_scope}-{safe_name}-{safe_type}.{ext}"
            logger.debug(f"Generated filename: {filename}")
            try:
                content_to_write = response.content
            except Exception as e:
                raise FileSystemError(f"Failed to read content from response object: {e}")
            content_type = response.headers.get("content-type", "").lower()
            if "text" in content_type or "json" in content_type or "html" in content_type:
                write_mode = "w"
                try:
                    content_to_write = content_to_write.decode(
                        response.encoding or "utf-8", errors="replace"
                    )
                except Exception:
                    logger.warning(
                        f"Could not decode response content as text, writing as binary. Content-Type: {content_type}"
                    )
                    write_mode = "wb"
            else:
                write_mode = "wb"
        elif isinstance(response_or_content, (dict, list)):
            # Handle direct JSON data (e.g., collected results)
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = report_scope
            safe_type = re.sub(
                r"[^\w\-]+", "_", report_type
            )  # Use report_type if available, else generic
            filename = f"{safe_scope}-{safe_name}-{safe_type}.json"
            try:
                content_to_write = json.dumps(response_or_content, indent=2)
                write_mode = "w"
            except TypeError as e:
                raise ValidationError(f"Failed to serialize provided dictionary/list to JSON: {e}")
        elif isinstance(response_or_content, str):
            # Handle direct string content
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = report_scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            filename = f"{safe_scope}-{safe_name}-{safe_type}.txt"
            content_to_write = response_or_content
            write_mode = "w"
        elif isinstance(response_or_content, bytes):
            # Handle direct bytes content
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = report_scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            filename = f"{safe_scope}-{safe_name}-{safe_type}.bin"  # Generic binary extension
            content_to_write = response_or_content
            write_mode = "wb"
        else:
            raise ValidationError(
                f"Unsupported content type for saving: {type(response_or_content)}"
            )
        filepath = os.path.join(output_dir, filename)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create output directory '{output_dir}': {e}", exc_info=True)
            raise FileSystemError(f"Could not create output directory '{output_dir}': {e}") from e
        try:
            if write_mode == "w":
                with open(filepath, write_mode, encoding="utf-8") as f:
                    f.write(content_to_write)
            else:
                with open(filepath, write_mode) as f:
                    f.write(content_to_write)
            print(f"Saved report to: {filepath}")
            logger.info(f"Successfully saved report to {filepath}")
        except IOError as e:
            logger.error(f"Failed to write report to {filepath}: {e}", exc_info=True)
            raise FileSystemError(f"Failed to write report to '{filepath}': {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error writing report to {filepath}: {e}", exc_info=True)
            raise FileSystemError(f"Unexpected error writing report to '{filepath}': {e}") from e
