import logging
from typing import Any, Dict, List

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class VulnerabilitiesAPI(BaseAPI):
    """
    Workbench API Vulnerability Operations.
    """

    def list_vulnerabilities(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves the list of vulnerabilities associated with a scan.
        Handles pagination automatically to fetch all vulnerabilities.

        Args:
            scan_code: Code of the scan to get vulnerabilities for.

        Returns:
            List[Dict[str, Any]]: List of vulnerability details.

        Raises:
            ApiError: If there are API issues.
        """
        logger.debug(f"Fetching vulnerabilities for scan '{scan_code}'...")

        # Step 1: Get the total count of vulnerabilities
        count_payload = {
            "group": "vulnerabilities",
            "action": "list_vulnerabilities",
            "data": {"scan_code": scan_code, "count_results": 1},
        }
        count_response = self._send_request(count_payload)

        if count_response.get("status") != "1":
            error_msg = count_response.get(
                "error", f"Unexpected response format or status: {count_response}"
            )
            raise ApiError(
                f"Failed to get vulnerability count for scan '{scan_code}': {error_msg}",
                details=count_response,
            )

        # Get the total count from the response
        total_count = 0
        if (
            isinstance(count_response.get("data"), dict)
            and "count_results" in count_response["data"]
        ):
            total_count = int(count_response["data"]["count_results"])

        logger.debug(f"Found {total_count} total vulnerabilities for scan '{scan_code}'")

        # If no vulnerabilities, return an empty list
        if total_count == 0:
            return []

        # Step 2: Calculate number of pages needed (default records_per_page is 100)
        records_per_page = 100
        total_pages = (total_count + records_per_page - 1) // records_per_page  # Ceiling division

        # Step 3: Fetch all pages and combine results
        all_vulnerabilities = []

        for page in range(1, total_pages + 1):
            logger.debug(
                f"Fetching vulnerabilities page {page}/{total_pages} for scan '{scan_code}'"
            )

            page_payload = {
                "group": "vulnerabilities",
                "action": "list_vulnerabilities",
                "data": {"scan_code": scan_code, "page": page},
            }
            page_response = self._send_request(page_payload)

            if page_response.get("status") != "1":
                error_msg = page_response.get(
                    "error", f"Unexpected response format or status: {page_response}"
                )
                raise ApiError(
                    f"Failed to fetch vulnerabilities page {page} for scan '{scan_code}': {error_msg}",
                    details=page_response,
                )

            data = page_response.get("data")
            # Process the page results
            if isinstance(data, dict) and "list" in data:
                vuln_list = data["list"]
                if isinstance(vuln_list, list):
                    all_vulnerabilities.extend(vuln_list)
                    logger.debug(f"Added {len(vuln_list)} vulnerabilities from page {page}")
                else:
                    logger.warning(
                        f"Unexpected vulnerability list format on page {page}: {vuln_list}"
                    )
            elif not data or (isinstance(data, dict) and not data):
                # Empty page - this is unexpected but we'll continue
                logger.warning(f"Empty data received for vulnerabilities page {page}")
            else:
                logger.warning(f"Unexpected data format for vulnerabilities page {page}: {data}")

        logger.debug(
            f"Successfully fetched all {len(all_vulnerabilities)} vulnerabilities for scan '{scan_code}'"
        )
        return all_vulnerabilities
