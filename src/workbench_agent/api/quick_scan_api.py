import json
import logging
from typing import Any, Dict, List

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class QuickScanAPI(BaseAPI):
    """
    Workbench API Quick Scan Operations.
    """

    def quick_scan_file(
        self, file_content_b64: str, limit: int = 1, sensitivity: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Perform a quick scan of a single file using base64 content.

        Args:
            file_content_b64: Base64-encoded file content
            limit: Max number of results to consider
            sensitivity: Snippet detection sensitivity

        Returns:
            List of parsed quick scan result dictionaries

        Raises:
            ApiError: If the API call fails or unexpected response received
        """
        logger.debug(
            "Initiating quick scan (limit=%s, sensitivity=%s)...",
            limit,
            sensitivity,
        )

        payload = {
            "group": "quick_scan",
            "action": "scan_one_file",
            "data": {
                "file_content": file_content_b64,
                "limit": str(limit),
                "sensitivity": str(sensitivity),
            },
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get(
                "error", f"Unexpected response: {response}"
            )
            raise ApiError(f"Quick scan failed: {error_msg}", details=response)

        results_raw = response.get("data", [])
        if not isinstance(results_raw, list):
            logger.warning(
                "Quick scan returned unexpected data format: %s",
                type(results_raw),
            )
            return []

        parsed_results: List[Dict[str, Any]] = []
        for item in results_raw:
            if isinstance(item, dict):
                parsed_results.append(item)
                continue
            if isinstance(item, str):
                try:
                    parsed_results.append(json.loads(item))
                except json.JSONDecodeError:
                    logger.warning(
                        "Failed to parse quick scan result item as JSON; "
                        "skipping"
                    )
        logger.debug(
            "Quick scan returned %d parsed results", len(parsed_results)
        )
        return parsed_results
