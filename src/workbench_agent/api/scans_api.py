import logging
from typing import Any, Dict, List, Optional

from workbench_agent.api.helpers.scan_operations_api import ScanOperationsAPI
from workbench_agent.api.helpers.generate_download_report import ReportHelper
from workbench_agent.api.helpers.process_status_checkers import handle_unsupported_status_check
from workbench_agent.exceptions import ApiError, ScanExistsError, ScanNotFoundError

logger = logging.getLogger("workbench-agent")


class ScansAPI(ScanOperationsAPI, ReportHelper):
    """
    Workbench API Scans Operations.
    """

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans.

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans...")
        payload = {"group": "scans", "action": "list_scans", "data": {}}
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # API returns a dict {id: {details}}, convert to list of dicts including the code
            if isinstance(data, dict):
                scan_list = []
                for scan_id, scan_details in data.items():
                    if isinstance(scan_details, dict):
                        try:  # Handle potential non-integer scan_id keys if API is weird
                            scan_details["id"] = int(scan_id)
                        except ValueError:
                            logger.warning(
                                f"Non-integer scan ID key found in list_scans response: {scan_id}"
                            )
                            scan_details["id"] = scan_id  # Keep original key if not int

                        if "code" not in scan_details:
                            logger.warning(
                                f"Scan details for ID {scan_id} missing 'code' field: {scan_details}"
                            )
                        scan_list.append(scan_details)
                    else:
                        logger.warning(
                            f"Unexpected format for scan details with ID {scan_id}: {type(scan_details)}"
                        )
                logger.debug(f"Successfully listed {len(scan_list)} scans.")
                return scan_list
            elif (
                isinstance(data, list) and not data
            ):  # Handle API returning empty list for no scans
                logger.debug("Successfully listed 0 scans (API returned empty list).")
                return []
            else:
                logger.warning(
                    f"API returned success for list_scans but 'data' was not a dict or empty list: {type(data)}"
                )
                return []  # Return empty list on unexpected format
        elif response.get("status") == "1":  # Status 1 but no data key
            logger.warning("API returned success for list_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list scans: {error_msg}", details=response)

    def get_scan_information(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a scan.

        Args:
            scan_code: Code of the scan to get information for

        Returns:
            Dict[str, Any]: Dictionary containing scan information

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching information for scan '{scan_code}'...")
        payload = {"group": "scans", "action": "get_information", "data": {"scan_code": scan_code}}
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "row_not_found" in error_msg or "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get information for scan '{scan_code}': {error_msg}", details=response
            )

    def get_scan_folder_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves scan folder metrics (total files, pending, identified, no match).

        Args:
            scan_code: Code of the scan to get metrics for

        Returns:
            Dict[str, Any]: Dictionary containing the metrics counts.

        Raises:
            ScanNotFoundError: If the scan doesn't exist.
            ApiError: If the API call fails for other reasons.
            NetworkError: If there are network issues.
        """
        logger.debug(f"Fetching folder metrics for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_folder_metrics",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)

        if (
            response.get("status") == "1"
            and "data" in response
            and isinstance(response["data"], dict)
        ):
            logger.debug(f"Successfully fetched folder metrics for scan '{scan_code}'.")
            return response["data"]
        elif response.get("status") == "1":  # Status 1 but no data or wrong format
            logger.warning(
                f"Folder metrics API returned success but unexpected data format for scan '{scan_code}': {response.get('data')}"
            )
            raise ApiError(
                f"Unexpected data format received for scan folder metrics: {response.get('data')}",
                details=response,
            )
        else:
            # Handle API errors (status 0)
            error_msg = response.get("error", "Unknown API error")
            if "row_not_found" in error_msg:
                logger.warning(f"Scan '{scan_code}' not found when fetching folder metrics.")
                raise ScanNotFoundError(f"Scan '{scan_code}' not found.")
            else:
                logger.error(
                    f"API error fetching folder metrics for scan '{scan_code}': {error_msg}"
                )
                raise ApiError(f"Failed to get scan folder metrics: {error_msg}", details=response)

    def get_scan_identified_components(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets identified components from KB scanning.

        Args:
            scan_code: Code of the scan to get components from

        Returns:
            List[Dict[str, Any]]: List of identified components

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            # API returns a dict { comp_id: {details} }, convert to list
            data = response["data"]
            return list(data.values()) if isinstance(data, dict) else []
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error retrieving identified components from scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_identified_licenses(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get the list of identified licenses for a scan.

        Args:
            scan_code: Code of the scan to get licenses from

        Returns:
            List[Dict[str, Any]]: List of identified licenses

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {"scan_code": scan_code, "unique": "1"},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully fetched {len(data)} unique licenses.")
                return data
            else:
                logger.warning(
                    f"API returned success for get_scan_identified_licenses but 'data' was not a list: {type(data)}"
                )
                return []
        elif response.get("status") == "1":
            logger.warning(
                "API returned success for get_scan_identified_licenses but no 'data' key found."
            )
            return []
        else:
            error_msg = response.get("error", f"Unexpected response format or status: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting identified licenses for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_dependency_analysis_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets dependency analysis results.

        Args:
            scan_code: Code of the scan to get results from

        Returns:
            List[Dict[str, Any]]: List of dependency analysis results

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return data if isinstance(data, list) else []
        elif response.get("status") == "1":  # Success but no data key
            logger.info(
                f"Dependency Analysis results requested for '{scan_code}', but no 'data' key in response. Assuming empty."
            )
            return []  # Return empty list, not an error
        else:
            # Check for specific "not run yet" error
            error_msg = response.get("error", "")
            if "Dependency analysis has not been run" in error_msg:
                logger.info(
                    f"Dependency analysis results requested for '{scan_code}', but analysis has not been run."
                )
                return []  # Return empty list, not an error
            elif "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            else:
                raise ApiError(
                    f"Error getting dependency analysis results for scan '{scan_code}': {error_msg}",
                    details=response,
                )

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Retrieves pending files for a scan.

        Args:
            scan_code: Code of the scan to check

        Returns:
            Dict[str, str]: Dictionary of pending files

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching files with Pending IDs for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(f"The scan {scan_code} has {len(data)} files pending ID'.")
                return data
            elif isinstance(data, list) and not data:  # Handle API sometimes returning empty list?
                logger.info(f"Pending files API returned empty list for scan '{scan_code}'.")
                return {}  # Return empty dict
            else:
                # Log unexpected format but return empty dict
                logger.warning(f"Pending files API returned unexpected data type: {type(data)}")
                return {}
        elif response.get("status") == "1":  # Status 1 but no data key
            logger.info(
                f"Pending files API returned success but no 'data' key for scan '{scan_code}'."
            )
            return {}
        else:
            # On API error (status 0), log but return empty dict - let handler decide gate status
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {}  # Return empty dict on error

    def get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Gets the count of policy warnings for a specific scan.

        Args:
            scan_code: Code of the scan to get policy warnings for

        Returns:
            Dict[str, Any]: The policy warnings counter data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting scan policy warnings counter for '{scan_code}': {error_msg}",
                details=response,
            )

    def create_scan(self, data: Dict[str, Any]) -> bool:
        """
        Create a new scan with the provided data.

        This method handles the core API interaction for scan creation,
        providing centralized execution logic.

        Args:
            data: Data payload for the scan creation request

        Returns:
            True if the scan was successfully created

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
            ScanExistsError: If a scan with this name already exists
        """
        scan_name = data.get("scan_name", "unknown")
        logger.debug(f"Creating scan '{scan_name}' via API")

        # Construct the full API payload
        payload = {"group": "scans", "action": "create", "data": data}

        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully created scan '{scan_name}'")
                return True
            else:
                error_msg = response.get("error", "Unknown error")
                raise ApiError(
                    f"Failed to create scan '{scan_name}': {error_msg}", details=response
                )
        except ApiError as e:
            # Transform specific API errors to domain exceptions
            if "Scan code already exists" in str(
                e
            ) or "Legacy.controller.scans.code_already_exists" in str(e):
                logger.debug(f"Scan '{scan_name}' already exists.")
                raise ScanExistsError(
                    f"Scan '{scan_name}' already exists",
                    details=getattr(e, "details", None),
                ) from e
            raise

    def update_scan(
        self,
        scan_code: str,
        scan_name: Optional[str] = None,
        project_code: Optional[str] = None,
        description: Optional[str] = None,
        target_path: Optional[str] = None,
        git_repo_url: Optional[str] = None,
        git_branch: Optional[str] = None,
        git_tag: Optional[str] = None,
        git_commit: Optional[str] = None,
        git_depth: Optional[int] = None,
        jar_file_extraction: Optional[str] = None,
    ) -> bool:
        """
        Updates an existing scan with new parameters.

        Args:
            scan_code: Code of the scan to update
            scan_name: Optional new name for the scan
            project_code: Optional new project code
            description: Optional new description (useful for tracking commit hashes for incremental scans)
            target_path: Optional target path
            git_repo_url: Optional Git repository URL
            git_branch: Optional Git branch name
            git_tag: Optional Git tag name
            git_commit: Optional Git commit hash
            git_depth: Optional Git clone depth
            jar_file_extraction: Optional JAR extraction setting

        Returns:
            True if the scan was successfully updated

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
            ScanNotFoundError: If the scan doesn't exist
        """
        logger.debug(f"Updating scan '{scan_code}'")

        payload_data = {"scan_code": scan_code}

        # Add only provided parameters to avoid overwriting with None values
        if scan_name is not None:
            payload_data["scan_name"] = scan_name
            logger.debug(f"  Updating scan name: {scan_name}")

        if project_code is not None:
            payload_data["project_code"] = project_code
            logger.debug(f"  Updating project code: {project_code}")

        if description is not None:
            payload_data["description"] = description
            logger.debug(f"  Updating description: {description}")

        if target_path is not None:
            payload_data["target_path"] = target_path
            logger.debug(f"  Updating target path: {target_path}")

        if jar_file_extraction is not None:
            payload_data["jar_file_extraction"] = jar_file_extraction
            logger.debug(f"  Updating JAR extraction: {jar_file_extraction}")

        # Handle Git parameters
        git_ref_value = None
        git_ref_type = None

        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
            logger.debug(f"  Updating Git tag: {git_tag}")
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
            logger.debug(f"  Updating Git branch: {git_branch}")
        elif git_commit:
            git_ref_value = git_commit
            git_ref_type = "commit"
            logger.debug(f"  Updating Git commit: {git_commit}")

        if git_repo_url is not None:
            payload_data["git_repo_url"] = git_repo_url
            logger.debug(f"  Updating Git URL: {git_repo_url}")

        if git_ref_value:
            payload_data["git_branch"] = git_ref_value
            if git_ref_type:
                payload_data["git_ref_type"] = git_ref_type
                logger.debug(f"  Updating Git ref type: {git_ref_type}")

        if git_depth is not None:
            payload_data["git_depth"] = str(git_depth)
            logger.debug(f"  Updating Git depth: {git_depth}")

        payload = {"group": "scans", "action": "update", "data": payload_data}

        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully updated scan '{scan_code}'")
                return True
            else:
                logger.warning(f"Unexpected response when updating scan: {response}")
                error_msg = response.get("error", "Unknown error")
                raise ApiError(f"Failed to update scan: {error_msg}", details=response)
        except ApiError as e:
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                logger.debug(f"Scan '{scan_code}' not found.")
                raise ScanNotFoundError(
                    f"Scan '{scan_code}' not found", details=getattr(e, "details", None)
                )
            raise

    def download_content_from_git(self, scan_code: str) -> bool:
        """
        Initiates the Git clone process for a scan.

        Args:
            scan_code: The code of the scan to download Git content for.

        Returns:
            True if the Git clone was successfully initiated.

        Raises:
            ApiError: If the API call fails.
            NetworkError: If there's a network issue.
        """
        logger.debug(f"Initiating Git clone for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "download_content_from_git",
            "data": {"scan_code": scan_code},
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            raise ApiError(f"Failed to initiate download from Git: {error_msg}", details=response)

        logger.debug("Successfully started Git Clone.")
        return True

    @handle_unsupported_status_check
    def check_status(
        self,
        scan_code: str,
        operation_type: str,
        process_id: Optional[str] = None,
        delay_response: Optional[int] = None,
    ) -> dict:
        """
        Retrieves the status of a scan operation using the comprehensive check_status API.

        Args:
            scan_code: Code of the scan to check
            operation_type: Type of operation to check. Valid values:
                          SCAN, EXTRACT_ARCHIVES, REPORT_IMPORT, DEPENDENCY_ANALYSIS,
                          NOTICE_EXTRACT_FILE, NOTICE_EXTRACT_COMPONENT,
                          NOTICE_EXTRACT_AGGREGATE, REPORT_GENERATION, DELETE_SCAN
            process_id: ID of the process (mandatory for REPORT_GENERATION, DELETE_SCAN)
            delay_response: Wait time before answering (max 10 seconds, for testing)

        Returns:
            dict: The operation status data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
            ValueError: If process_id is missing for operations that require it
        """
        operation_type = operation_type.upper()

        # Validate required process_id for certain operations
        if operation_type in ["REPORT_GENERATION", "DELETE_SCAN"] and not process_id:
            raise ValueError(f"process_id is mandatory for operation type '{operation_type}'")

        # Build request data
        data = {
            "scan_code": scan_code,
            "type": operation_type,
        }

        if process_id:
            data["process_id"] = process_id

        if delay_response is not None:
            if delay_response > 10:
                raise ValueError("delay_response cannot exceed 10 seconds")
            data["delay_response"] = str(delay_response)

        payload = {
            "group": "scans",
            "action": "check_status",
            "data": data,
        }

        response = self._send_request(payload)
        # _send_request handles basic API errors, check for expected data
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response format: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve {operation_type} status for scan "
                f"'{scan_code}': {error_msg}",
                details=response,
            )

    def check_status_download_content_from_git(self, scan_code: str) -> dict:
        """
        Check Git clone status for a scan.

        Args:
            scan_code: Code of the scan to check

        Returns:
            dict: Full Git clone status response data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "check_status_download_content_from_git",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response format: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve Git clone status for scan " f"'{scan_code}': {error_msg}",
                details=response,
            )

    def remove_uploaded_content(self, scan_code: str, filename: str) -> bool:
        """
        Removes uploaded content from a scan, particularly useful for removing files or folders
        prior to starting a scan.

        Args:
            scan_code: Code of the scan to remove content from
            filename: Name/path of the file or directory to remove (e.g., ".git/")

        Returns:
            bool: True if the operation was successful

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Removing '{filename}' from scan '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": {"scan_code": scan_code, "filename": filename},
        }

        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully removed '{filename}' from scan '{scan_code}'.")
                return True
            else:
                error_msg = response.get("error", "Unknown error")

                # Check if this is the specific "file not found" error
                if error_msg == "RequestData.Base.issues_while_parsing_request":
                    data = response.get("data", [])
                    if isinstance(data, list) and len(data) > 0:
                        error_code = data[0].get("code", "")
                        if error_code == "RequestData.Traits.PathTrait.filename_is_not_valid":
                            logger.warning(
                                f"File or directory '{filename}' does not exist in scan '{scan_code}' or could not be accessed."
                            )
                            # Return True as this is non-fatal - the file we wanted removed doesn't exist anyway
                            return True

                # Handle other types of errors
                if "Scan not found" in error_msg or "row_not_found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")

                raise ApiError(
                    f"Failed to remove '{filename}' from scan '{scan_code}': {error_msg}",
                    details=response,
                )
        except (ScanNotFoundError, ApiError):
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error removing '{filename}' from scan '{scan_code}': {e}",
                exc_info=True,
            )
            raise ApiError(
                f"Failed to remove '{filename}' from scan '{scan_code}': Unexpected error",
                details={"error": str(e)},
            )

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """
        Triggers archive extraction for a scan.

        Args:
            scan_code: Code of the scan to extract archives for
            recursively_extract_archives: Whether to recursively extract archives
            jar_file_extraction: Whether to extract JAR files

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Extracting Uploaded Archives for Scan '{scan_code}'...")
        # Build the data using the helper
        data = self.build_extract_archives_data(
            scan_code=scan_code,
            recursively_extract_archives=recursively_extract_archives,
            jar_file_extraction=jar_file_extraction,
        )
        # Construct the API payload
        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": data,
        }

        response = self._send_request(payload)
        if response.get("status") == "1":
            logger.debug(
                f"Archive Extraction operation successfully queued/completed for scan '{scan_code}'."
            )
            return True
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Archive extraction failed for scan '{scan_code}': {error_msg}", details=response
            )

    def run_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        autoid_file_licenses: bool,
        autoid_file_copyrights: bool,
        autoid_pending_ids: bool,
        delta_scan: bool,
        id_reuse: bool,
        id_reuse_type: Optional[str] = None,
        id_reuse_source: Optional[str] = None,
        run_dependency_analysis: Optional[bool] = None,
        replace_existing_identifications: bool = False,
        scan_failed_only: bool = False,
        full_file_only: bool = False,
        advanced_match_scoring: bool = True,
        match_filtering_threshold: Optional[int] = None,
    ):
        """
        Run a scan with the specified parameters.

        Args:
            scan_code: The code of the scan to run
            limit: Maximum number of results to consider
            sensitivity: Scan sensitivity level (anything under 6 returns only full file matches)
            autoid_file_licenses: Whether to auto-identify file licenses
            autoid_file_copyrights: Whether to auto-identify file copyrights
            autoid_pending_ids: Whether to auto-identify pending IDs
            delta_scan: Whether to run a delta scan (only newly added/modified files)
            id_reuse: Whether to reuse identifications from other scans
            id_reuse_type: Type of identification reuse. Supported values:
                - "project" or "specific_project": Reuse from specific project
                - "scan" or "specific_scan": Reuse from specific scan
                - "only_me": Only reuse identifications made by current user
                - "any": Use any existing identification (default)
            id_reuse_source: Source to reuse identifications from (required for project/scan types)
            run_dependency_analysis: Whether to run dependency analysis along with the scan
            replace_existing_identifications: Whether to replace existing identifications (default: False)
            scan_failed_only: Whether to only scan files that failed in the previous scan (default: False)
            full_file_only: Whether to return only full file matches regardless of sensitivity (default: False)
            advanced_match_scoring: Whether to use advanced match scoring (default: True)
            match_filtering_threshold: Minimum snippet length in characters for match filtering.
                Set to 0 to disable. If None, uses fossid.conf value or 300 character default.

        Notes:
            For id_reuse parameters, validation should be done prior to calling this method
            using the _validate_reuse_source function from workbench_agent.utilities.scan_target_validators.
            If validation fails, id_reuse should be set to False before calling this method.

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            ValueError: For invalid parameter values
            NetworkError: If there are network issues
        """
        logger.info(f"Starting scan for '{scan_code}'...")
        # Build the data using the helper
        data = self.build_run_scan_data(
            scan_code=scan_code,
            limit=limit,
            sensitivity=sensitivity,
            autoid_file_licenses=autoid_file_licenses,
            autoid_file_copyrights=autoid_file_copyrights,
            autoid_pending_ids=autoid_pending_ids,
            delta_scan=delta_scan,
            id_reuse=id_reuse,
            id_reuse_type=id_reuse_type,
            id_reuse_source=id_reuse_source,
            run_dependency_analysis=run_dependency_analysis,
            replace_existing_identifications=replace_existing_identifications,
            scan_failed_only=scan_failed_only,
            full_file_only=full_file_only,
            advanced_match_scoring=advanced_match_scoring,
            match_filtering_threshold=match_filtering_threshold,
        )
        # Construct the API payload
        payload = {
            "group": "scans",
            "action": "run",
            "data": data,
        }

        # --- Send Request ---
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                print(f"KB Scan initiated for scan '{scan_code}'.")
                return  # Return None or True on success
            else:
                error_msg = response.get("error", "Unknown error")
                if "Scan not found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                raise ApiError(f"Failed to run scan '{scan_code}': {error_msg}", details=response)
        except (ScanNotFoundError, ApiError):
            raise  # Re-raise specific errors
        except Exception as e:
            # Catch other errors like network issues from _send_request
            logger.error(f"Unexpected error trying to run scan '{scan_code}': {e}", exc_info=True)
            raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def start_dependency_analysis(self, scan_code: str, import_only: bool = False):
        """
        Starts or imports dependency analysis for a scan.

        Args:
            scan_code: Code of the scan to start dependency analysis for
            import_only: Whether to only import results without running analysis

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.info(f"Starting dependency analysis for '{scan_code}'...")
        # Build the data using the helper
        data = self.build_dependency_analysis_data(
            scan_code=scan_code,
            import_only=import_only,
        )
        # Construct the API payload
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": data,
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            raise ApiError(
                f"Failed to start dependency analysis for '{scan_code}': {error_msg}",
                details=response,
            )
        logger.info(f"Dependency analysis for '{scan_code}' started successfully.")

    def generate_scan_report(
        self,
        scan_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ):
        """
        Triggers report generation for a scan.
        Can be sync or async depending on the report type.

        Returns:
            Union[int, requests.Response]: Process queue ID for async reports, or raw response for sync reports
        """
        # Build the data using the helper
        data = self.build_scan_report_data(
            scan_code=scan_code,
            report_type=report_type,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
            include_vex=include_vex,
        )

        payload = {"group": "scans", "action": "generate_report", "data": data}

        response_data = self._send_request(payload)

        if "_raw_response" in response_data:
            raw_response = response_data["_raw_response"]
            logger.info(
                f"Synchronous report generation likely completed for scan '{scan_code}'. Returning raw response object."
            )
            return raw_response
        elif (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested successfully (async) for scan '{scan_code}'. Process ID: {process_id}"
            )
            return int(process_id)
        else:
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to request report generation for scan '{scan_code}': {error_msg}",
                details=response_data,
            )

    def import_report(self, scan_code: str):
        """
        Imports an SBOM report into a scan.

        Args:
            scan_code: Code of the scan to import the report into

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.info(f"Starting SBOM report import for '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "import_report",
            "data": {"scan_code": scan_code},
        }
        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to start SBOM report import for '{scan_code}': {error_msg}",
                details=response,
            )
        logger.info(f"SBOM import for '{scan_code}' started successfully.")
