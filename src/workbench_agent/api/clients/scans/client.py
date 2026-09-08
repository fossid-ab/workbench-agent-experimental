"""ScansClient - scan-related Workbench API operations (group: scans)."""

import logging
from typing import Any, Dict, List, Literal, Optional, Union

PolicyWarningType = Literal["identifications", "dependencies", "all"]

import requests

from workbench_agent.api.exceptions import ApiError, ScanNotFoundError
from workbench_agent.api.validation.field_limits import validate_scan_create_data

from . import helpers

logger = logging.getLogger("workbench-agent")


class ScansClient:
    """
    Scans API client (group: scans).

    Request/response fields: ``clients/scans/schema.md``.
    Server quirks: ``clients/scans/quirks.md``.

    Example:
        >>> scans = ScansClient(base_api)
        >>> scan_list = scans.list_scans()
        >>> scans.run({"scan_code": "MY_SCAN", "limit": 10, "sensitivity": 6})
    """

    def __init__(self, base_api):
        """
        Initialize ScansClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("ScansClient initialized")

    # ===== LIST & INFO OPERATIONS =====

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans in Workbench - HEAVY operation.

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans...")
        response = self._api._send_request({"group": "scans", "action": "list_scans", "data": {}})

        if response.get("status") == "1" and "data" in response:
            scan_list = helpers.parse_list_scans_data(response["data"])
            logger.debug("Successfully listed %s scans.", len(scan_list))
            return scan_list
        if response.get("status") == "1":
            logger.warning("API returned success for list_scans but no 'data' key found.")
            return []
        helpers.raise_on_failed_response(response, error_context="Failed to list scans")
        return []

    def get_information(self, scan_code: str) -> Dict[str, Any]:
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
        payload = {
            "group": "scans",
            "action": "get_information",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Failed to get information for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_folder_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves scan file metrics (total, pending, identified, no match).

        Args:
            scan_code: Code of the scan to get metrics for

        Returns:
            Dict[str, Any]: Dictionary containing the metrics counts

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching folder metrics for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_folder_metrics",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if (
            response.get("status") == "1"
            and "data" in response
            and isinstance(response["data"], dict)
        ):
            logger.debug(f"Successfully fetched folder metrics for scan '{scan_code}'.")
            return response["data"]
        elif response.get("status") == "1":
            logger.warning(
                f"Unexpected data format for scan folder metrics: {response.get('data')}"
            )
            raise ApiError(
                f"Unexpected data format received for scan folder metrics: {response.get('data')}",
                details=response,
            )
        else:
            error_msg = response.get("error", "Unknown API error")
            if helpers.is_scan_not_found(error_msg):
                logger.warning(f"Scan '{scan_code}' not found when fetching folder metrics.")
                helpers.raise_scan_not_found(scan_code)
            else:
                logger.error(
                    f"API error fetching folder metrics for scan '{scan_code}': {error_msg}"
                )
                raise ApiError(
                    f"Failed to get scan folder metrics: {error_msg}",
                    details=response,
                )

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
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return list(data.values()) if isinstance(data, dict) else []
        else:
            error_msg = response.get("error", "Unknown error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Error retrieving identified components from scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_identified_licenses(
        self, scan_code: str, unique: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get the list of identified licenses for a scan.

        Args:
            scan_code: Code of the scan to get licenses from
            unique: If True, returns unique licenses (identifier, name).
                   If False, returns all licenses with file paths
                   (identifier, name, local_path). Default: True.

        Returns:
            List[Dict[str, Any]]: List of identified licenses.
                When unique=True: [{"identifier": str, "name": str}, ...]
                When unique=False: [{"identifier": str, "name": str,
                                    "local_path": str}, ...]

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> # Get unique licenses only
            >>> licenses = scans.get_scan_identified_licenses("scan_code")
            >>> # Get all licenses with file paths
            >>> licenses = scans.get_scan_identified_licenses("scan_code",
            ...                                                unique=False)
        """
        logger.debug(
            f"Fetching identified licenses for scan '{scan_code}' " f"(unique={unique})..."
        )

        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1" if unique else "0",
            },
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                result_type = "unique licenses" if unique else "licenses with paths"
                logger.debug(
                    f"Successfully fetched {len(data)} {result_type} " f"for scan '{scan_code}'."
                )
                return data
            else:
                logger.warning(f"Unexpected data type for licenses: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning(
                "API returned success for get_scan_identified_licenses " "but no 'data' key."
            )
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Error getting identified licenses for scan '{scan_code}': " f"{error_msg}",
                details=response,
            )

    def get_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get raw KB scan matches for a scan (``scans.get_results``).

        Returns file-client match rows (``local_path``, ``match_type``,
        ``artifact``, ``version``, etc.). Empty when the scan has not been run
        or has no matches.

        Args:
            scan_code: Code of the scan to get matches from

        Returns:
            List of match records sorted by ``local_path`` then ``id``

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug("Fetching KB scan matches for scan '%s'...", scan_code)
        payload = {
            "group": "scans",
            "action": "get_results",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if data is False:
                logger.info("Scan '%s' has not been run or has no KB matches.", scan_code)
                return []
            if isinstance(data, dict):
                matches = list(data.values())
                matches.sort(
                    key=lambda row: (
                        str(row.get("local_path", "")).lower(),
                        str(row.get("id", "")),
                    )
                )
                logger.debug(
                    "Successfully fetched %d KB matches for scan '%s'.",
                    len(matches),
                    scan_code,
                )
                return matches
            if isinstance(data, list):
                return data
            logger.warning(
                "Unexpected data type for get_results on scan '%s': %s",
                scan_code,
                type(data),
            )
            return []
        if response.get("status") == "1":
            logger.warning(
                "API returned success for get_results but no 'data' key for scan '%s'.",
                scan_code,
            )
            return []

        error_msg = response.get("error", f"Unexpected response: {response}")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            f"Error getting KB scan matches for scan '{scan_code}': {error_msg}",
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
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return data if isinstance(data, list) else []
        elif response.get("status") == "1":
            logger.info(
                f"Dependency Analysis results requested for '{scan_code}', but no 'data' key."
            )
            return []
        else:
            error_msg = response.get("error", "")
            if "Dependency analysis has not been run" in error_msg:
                logger.info(f"Dependency analysis has not been run for '{scan_code}'.")
                return []
            elif helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            else:
                raise ApiError(
                    f"Error getting dependency analysis results for scan '{scan_code}': {error_msg}",
                    details=response,
                )

    def add_dependency_analysis_results(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        package_id: str,
        *,
        projects_and_scopes: Optional[str] = None,
        detailed_dependency_info: Optional[str] = None,
        include_in_report: Optional[Union[bool, int, str]] = None,
    ) -> Dict[str, Any]:
        """
        Add a dependency row to dependency analysis results for a scan.

        Required: ``scan_code``, ``component_name``, ``component_version``,
        ``package_id``. Optional fields match the Workbench API.

        Returns:
            Created dependency record (``scan_id``, ``component_id``,
            ``include_in_report``, ``updated``, …).

        Raises:
            ScanNotFoundError: If the scan does not exist
            ApiError: If the API call fails
        """
        payload_data: Dict[str, Any] = {
            "scan_code": scan_code,
            "component_name": component_name,
            "component_version": component_version,
            "package_id": package_id,
        }
        if projects_and_scopes is not None:
            payload_data["projects_and_scopes"] = projects_and_scopes
        if detailed_dependency_info is not None:
            payload_data["detailed_dependency_info"] = detailed_dependency_info
        if include_in_report is not None:
            payload_data["include_in_report"] = helpers.flag_str(include_in_report)

        response = self._api._send_request(
            {
                "group": "scans",
                "action": "add_dependency_analysis_results",
                "data": payload_data,
            }
        )

        if response.get("status") == "1" and isinstance(response.get("data"), dict):
            return response["data"]

        error_msg = response.get("error", "Unknown error")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            "Failed to add dependency analysis results for "
            f"'{component_name}' {component_version!r} on scan "
            f"'{scan_code}': {error_msg}",
            details=response,
        )

    def update_dependency_analysis_results(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        *,
        package_id: Optional[str] = None,
        projects_and_scopes: Optional[str] = None,
        detailed_dependency_info: Optional[str] = None,
        include_in_report: Optional[Union[bool, int, str]] = None,
    ) -> Dict[str, Any]:
        """
        Update a dependency analysis row for a scan.

        Required: ``scan_code``, ``component_name``, ``component_version``.
        Optional fields match the Workbench API (``include_in_report`` as
        ``"0"`` / ``"1"``, JSON strings for scope/detail blobs).

        Returns:
            Updated dependency record (``scan_id``, ``component_id``,
            ``include_in_report``, ``updated``, …).

        Raises:
            ScanNotFoundError: If the scan does not exist
            ApiError: If the API call fails
        """
        payload_data: Dict[str, Any] = {
            "scan_code": scan_code,
            "component_name": component_name,
            "component_version": component_version,
        }
        if package_id is not None:
            payload_data["package_id"] = package_id
        if projects_and_scopes is not None:
            payload_data["projects_and_scopes"] = projects_and_scopes
        if detailed_dependency_info is not None:
            payload_data["detailed_dependency_info"] = detailed_dependency_info
        if include_in_report is not None:
            payload_data["include_in_report"] = helpers.flag_str(include_in_report)

        response = self._api._send_request(
            {
                "group": "scans",
                "action": "update_dependency_analysis_results",
                "data": payload_data,
            }
        )

        if response.get("status") == "1" and isinstance(response.get("data"), dict):
            return response["data"]

        error_msg = response.get("error", "Unknown error")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            "Failed to update dependency analysis results for "
            f"'{component_name}' {component_version!r} on scan "
            f"'{scan_code}': {error_msg}",
            details=response,
        )

    def remove_dependency_analysis_results(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
    ) -> bool:
        """
        Remove a dependency from dependency analysis results for a scan.

        Args:
            scan_code: Code of the scan
            component_name: Component name to remove
            component_version: Component version to remove

        Returns:
            ``True`` when the API returns ``data: true``.

        Raises:
            ScanNotFoundError: If the scan does not exist
            ApiError: If the API call fails
        """
        response = self._api._send_request(
            {
                "group": "scans",
                "action": "remove_dependency_analysis_results",
                "data": {
                    "scan_code": scan_code,
                    "component_name": component_name,
                    "component_version": component_version,
                },
            }
        )

        if response.get("status") == "1" and response.get("data") is True:
            return True

        error_msg = response.get("error", "Unknown error")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            "Failed to remove dependency analysis results for "
            f"'{component_name}' {component_version!r} on scan "
            f"'{scan_code}': {error_msg}",
            details=response,
        )

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Retrieves pending files for a scan.

        Args:
            scan_code: Code of the scan to check

        Returns:
            Dict[str, str]: Maps scan file id (str) to relative file path (str)

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
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(f"The scan {scan_code} has {len(data)} files pending ID.")
                return data
            elif isinstance(data, list) and not data:
                logger.info(f"Pending files API returned empty list for scan '{scan_code}'.")
                return {}
            else:
                logger.warning(f"Pending files API returned unexpected data type: {type(data)}")
                return {}
        elif response.get("status") == "1":
            logger.info(
                f"Pending files API returned success but no 'data' key for scan '{scan_code}'."
            )
            return {}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {}

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
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Error getting scan policy warnings counter for '{scan_code}': {error_msg}",
                details=response,
            )

    def get_policy_warnings_info(
        self,
        scan_code: str,
        *,
        warning_type: PolicyWarningType = "identifications",
    ) -> Dict[str, Any]:
        """
        Detailed policy rules and finding counts for a scan.

        Args:
            scan_code: Target scan code.
            warning_type: ``identifications``, ``dependencies``, or ``all``.

        Returns:
            Dict with ``policy_warnings_list``: rule rows including ``findings``,
            ``type``, ``license_category``, and optional ``license_info``.

        Raises:
            ScanNotFoundError: If the scan does not exist.
            ApiError: On other API failures.
        """
        logger.debug(
            "Fetching scan policy warnings info for '%s' (type=%s)",
            scan_code,
            warning_type,
        )
        response = self._api._send_request(
            {
                "group": "scans",
                "action": "get_policy_warnings_info",
                "data": {
                    "scan_code": scan_code,
                    "type": warning_type,
                },
            }
        )

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(
                    "Retrieved scan policy warnings info for '%s'",
                    scan_code,
                )
                return data
            raise ApiError(
                f"Unexpected data type for scan policy warnings info: " f"{type(data)}",
                details=response,
            )

        error_msg = response.get("error", "Unknown error")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            f"Error getting scan policy warnings info for " f"'{scan_code}': {error_msg}",
            details=response,
        )

    # ===== SCAN MANAGEMENT OPERATIONS =====

    def create(self, data: Dict[str, Any]) -> int:
        """
        Create a new scan with the provided data.

        Args:
            data: Data payload for the scan creation request. Required fields:
                - scan_code (str): Code of the scan
                - scan_name (str): Name of the scan
                Optional fields:
                - project_code (str): Code of the project to assign scan to
                - description (str): Scan description
                - comment (str): Scan comment
                - target_path (str): Path accessible from server
                - git_repo_url (str): Git repository URL
                - git_branch (str): Git branch, tag, or commit
                - git_depth (str): Git clone depth (integer as string)
                - git_ref_type (str): "branch", "tag", or "commit"
                - jar_file_extraction (str): "always", "never", or "if_no_fullmatch"
                - import_from_report (str): "0" or "1"

        Returns:
            int: The ID of the newly created scan

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
        """
        validate_scan_create_data(data)
        scan_name = data.get("scan_name", "unknown")
        logger.debug(f"Creating scan '{scan_name}' via API")

        payload = {"group": "scans", "action": "create", "data": data}

        response = self._api._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            scan_id = response["data"].get("scan_id")
            if scan_id is None:
                raise ApiError(
                    f"Scan created but no scan_id returned for '{scan_name}'",
                    details=response,
                )
            logger.debug(f"Successfully created scan '{scan_name}' with ID {scan_id}")
            return int(scan_id)
        error_msg = response.get("error", "Unknown error")
        raise ApiError(
            f"Failed to create scan '{scan_name}': {error_msg}",
            details=response,
        )

    def update(
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
            description: Optional new description
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

        # Add only provided parameters
        if scan_name is not None:
            payload_data["scan_name"] = scan_name
        if project_code is not None:
            payload_data["project_code"] = project_code
        if description is not None:
            payload_data["description"] = description
        if target_path is not None:
            payload_data["target_path"] = target_path
        if jar_file_extraction is not None:
            payload_data["jar_file_extraction"] = jar_file_extraction

        # Handle Git parameters
        git_ref_value = None
        git_ref_type = None

        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
        elif git_commit:
            git_ref_value = git_commit
            git_ref_type = "commit"

        if git_repo_url is not None:
            payload_data["git_repo_url"] = git_repo_url

        if git_ref_value:
            payload_data["git_branch"] = git_ref_value
            if git_ref_type:
                payload_data["git_ref_type"] = git_ref_type

        if git_depth is not None:
            payload_data["git_depth"] = str(git_depth)

        payload = {
            "group": "scans",
            "action": "update",
            "data": payload_data,
        }

        try:
            response = self._api._send_request(payload)
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
                    f"Scan '{scan_code}' not found",
                    details=getattr(e, "details", None),
                )
            raise

    def delete(
        self,
        scan_code: str,
        delete_identifications: bool = True,
    ) -> Dict[str, Any]:
        """
        Raw ``scans`` / ``delete`` API call.

        Returns the parsed JSON body on success. On API error (including
        invalid `scan_code`) raises `workbench_agent.api.exceptions.ApiError`

        For orchestration (not-found handling, polling until deleted), use
        workbench_agent.api.services.scan_deletion.ScanDeletionService

        Args:
            scan_code: Code of the scan to delete
            delete_identifications: whether to delete identifications

        Returns:
            Full API response dict (typically includes `data.process_id`)

        Raises:
            ApiError: If the API returns an error response
            NetworkError: If there are network issues
        """
        logger.debug(f"scans/delete request for scan '{scan_code}'")
        payload_data = {
            "scan_code": scan_code,
            "delete_identifications": "1" if delete_identifications else "0",
        }
        payload = {
            "group": "scans",
            "action": "delete",
            "data": payload_data,
        }
        return self._api._send_request(payload)

    # ===== GIT OPERATIONS =====

    def download_content_from_git(self, scan_code: str) -> bool:
        """
        Initiates the Git clone process for a scan.

        Args:
            scan_code: The code of the scan to download Git content for

        Returns:
            True if the Git clone was successfully initiated

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
        """
        logger.debug(f"Initiating Git clone for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "download_content_from_git",
            "data": {"scan_code": scan_code},
        }

        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            raise ApiError(
                f"Failed to initiate download from Git: {error_msg}",
                details=response,
            )

        logger.debug("Successfully started Git Clone.")
        return True

    def check_status_download_content_from_git(self, scan_code: str) -> Dict[str, Any]:
        """
        Check Git clone status for a scan.

        The API wrapper returns {"status": "1", "data": "NOT FINISHED", ...}
        where 'status' is the API success indicator and 'data' contains the
        git clone status string ("NOT STARTED", "NOT FINISHED", or "FINISHED").

        This method normalizes the response to always return a dict:
        - If API returns a string in 'data', wraps it as {"data": <string>}
        - If API returns a dict in 'data', returns it as-is

        Args:
            scan_code: Code of the scan to check

        Returns:
            dict: Git clone status response data, always in dict format.
                For string responses, returns {"data": <status_string>}.
                For dict responses, returns the dict as-is.

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
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return helpers.normalize_git_status_data(response["data"])
        error_msg = response.get("error", f"Unexpected response: {response}")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            f"Failed to retrieve Git clone status for scan '{scan_code}': {error_msg}",
            details=response,
        )

    # ===== SCAN EXECUTION OPERATIONS =====

    def remove_uploaded_content(self, scan_code: str, filename: Optional[str] = None) -> bool:
        """
        Removes uploaded content from a scan.

        Args:
            scan_code: Code of the scan to remove content from
            filename: Relative path of file or directory to remove.
                     If None or empty string, entire scan directory is removed.

        Returns:
            bool: True if the operation was successful

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        if filename:
            logger.debug(f"Removing '{filename}' from scan '{scan_code}'...")
        else:
            logger.debug(f"Removing entire scan directory for scan '{scan_code}'...")

        data = {"scan_code": scan_code}
        if filename:
            data["filename"] = filename

        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": data,
        }

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1":
                if filename:
                    logger.debug(f"Successfully removed '{filename}' from scan '{scan_code}'.")
                else:
                    logger.debug(f"Successfully removed entire directory for scan '{scan_code}'.")
                return True
            else:
                error_msg = response.get("error", "Unknown error")

                if helpers.is_remove_uploaded_filename_not_found(response, filename=filename):
                    logger.warning(f"File '{filename}' does not exist in scan '{scan_code}'.")
                    return True

                # Handle other errors
                if helpers.is_scan_not_found(error_msg):
                    helpers.raise_scan_not_found(scan_code)

                # Build error message based on whether filename was provided
                if filename:
                    error_detail = (
                        f"Failed to remove '{filename}' from scan '{scan_code}': {error_msg}"
                    )
                else:
                    error_detail = f"Failed to remove content from scan '{scan_code}': {error_msg}"

                raise ApiError(error_detail, details=response)
        except ApiError:
            raise
        except Exception as e:
            if filename:
                logger.error(
                    f"Unexpected error removing '{filename}' from scan '{scan_code}': {e}",
                    exc_info=True,
                )
                error_msg = (
                    f"Failed to remove '{filename}' from scan '{scan_code}': Unexpected error"
                )
            else:
                logger.error(
                    f"Unexpected error removing content from scan '{scan_code}': {e}",
                    exc_info=True,
                )
                error_msg = f"Failed to remove content from scan '{scan_code}': Unexpected error"

            raise ApiError(error_msg, details={"error": str(e)})

    def extract_archives(self, payload_data: Dict[str, Any]) -> bool:
        """
        Extract archives using pre-built payload.

        This method wraps the API's extract_archives action.
        For most use cases, use ScanContentService.extract_archives()
        which provides validation and business logic.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - recursively_extract_archives: "1" or "0"
                - jar_file_extraction: "1" or "0"
                - extract_to_directory: Optional "1" or "0"
                - filename: Optional specific file to extract

        Returns:
            True if extraction was triggered successfully

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.debug(f"Extracting archives for scan '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": payload_data,
        }

        response = self._api._send_request(payload)
        if response.get("status") == "1":
            logger.debug(f"Archive extraction operation queued for scan '{scan_code}'.")
            return True
        else:
            error_msg = response.get("error", "Unknown error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Archive extraction failed for scan '{scan_code}': " f"{error_msg}",
                details=response,
            )

    def run(self, payload_data: Dict[str, Any]):
        """
        Run a scan using pre-built payload.

        This method directly wraps the API's run action. For most use cases,
        prefer using ScanOperationsService.start_scan() which provides
        validation, parameter transformation, and version awareness.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - limit: Maximum number of results
                - sensitivity: Scan sensitivity level
                - auto_identification_* fields
                - reuse_identification fields
                - Other scan configuration parameters

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.info(f"Starting scan for '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "run",
            "data": payload_data,
        }

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1":
                logger.info("KB Scan initiated for scan '%s'.", scan_code)
                return
            else:
                error_msg = response.get("error", "Unknown error")
                if helpers.is_scan_not_found(error_msg):
                    helpers.raise_scan_not_found(scan_code)
                raise ApiError(
                    f"Failed to run scan '{scan_code}': {error_msg}",
                    details=response,
                )
        except ApiError:
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error trying to run scan '{scan_code}': {e}",
                exc_info=True,
            )
            raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def run_dependency_analysis(self, payload_data: Dict[str, Any]):
        """
        Run dependency analysis using pre-built payload.

        This method directly wraps the API's run_dependency_analysis action.
        For most use cases, prefer using ScanOperationsService.start_da_only()
        or ScanOperationsService.start_da_import() which provide validation
        and business logic.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - import_only: "0" or "1"

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.info(f"Starting dependency analysis for '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": payload_data,
        }

        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            raise ApiError(
                f"Failed to start dependency analysis for '{scan_code}': " f"{error_msg}",
                details=response,
            )
        logger.info(f"Dependency analysis for '{scan_code}' started successfully.")

    # ===== STATUS & MONITORING =====

    def check_status(
        self,
        scan_code: Optional[str],
        process_type: str,
        process_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Check the status of various scan operations.

        This method directly wraps the API's check_status action.
        Always returns a dict, normalizing any non-dict responses from the API.

        Args:
            scan_code: Code of the scan to check. Use ``None`` to omit (only
                for operations polled by ``process_id``, e.g. ``DELETE_SCAN``).
            process_type: Type of process (SCAN, DEPENDENCY_ANALYSIS,
                EXTRACT_ARCHIVES, REPORT_IMPORT, DELETE_SCAN, etc.)
            process_id: Optional process ID (e.g. async report or delete scan)

        Returns:
            dict: Operation status data, always in dict format

        Raises:
            ScanNotFoundError: If scan doesn't exist
            ApiError: If status check fails
            ValueError: If `scan_code` omitted and `process_id` missing

        Example:
            >>> status = scans.check_status("scan_123", "SCAN")
            >>> status = scans.check_status("scan_123", "DEPENDENCY_ANALYSIS")
            >>> status = scans.check_status(None, "DELETE_SCAN", process_id=42)
        """
        if scan_code is None and process_id is None:
            raise ValueError("check_status requires scan_code or process_id")

        log_target = scan_code if scan_code is not None else f"process_id={process_id}"
        logger.debug(f"Checking {process_type} status for {log_target!r}...")

        # Build payload
        payload_data: Dict[str, Any] = {
            "type": process_type,
        }
        if scan_code is not None:
            payload_data["scan_code"] = scan_code
        if process_id is not None:
            payload_data["process_id"] = str(process_id)

        payload = {
            "group": "scans",
            "action": "check_status",
            "data": payload_data,
        }

        # Make API call
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, bool) and process_type != "DELETE_SCAN":
                logger.warning(
                    f"Unexpected bool data from {process_type} status API " f"({log_target!r})"
                )
            elif isinstance(data, str):
                logger.warning(
                    f"API returned string instead of dict for {process_type} "
                    f"status ({log_target!r})"
                )
            elif not isinstance(data, dict):
                logger.warning(
                    f"Unexpected response type from {process_type} status API: {type(data)}"
                )
            return helpers.normalize_check_status_data(
                data,
                process_type=process_type,
                response=response,
            )
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if helpers.is_scan_not_found(error_msg):
                if scan_code is not None:
                    helpers.raise_scan_not_found(scan_code)
                raise ScanNotFoundError(
                    f"Status check failed ({process_type}, "
                    f"process_id={process_id}): {error_msg}"
                )
            raise ApiError(
                f"Failed to retrieve {process_type} status for " f"{log_target!r}: {error_msg}",
                details=response,
            )

    # ===== REPORT OPERATIONS =====

    def generate_report(self, payload_data: Dict[str, Any]):
        """
        Generate a scan report.

        This method wraps the API's generate_report action.
        For most use cases use ReportService.generate_scan_report() instead.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - report_type: Type of report
                - async: "0" or "1"
                - Other optional parameters

        Returns:
            Union[int, requests.Response]: Process queue ID for async
                reports, or raw response for sync reports

        Raises:
            ScanNotFoundError: If scan doesn't exist
            ApiError: If report generation fails

        Example:
            >>> payload_data = {
            ...     "scan_code": "scan_code",
            ...     "report_type": "xlsx",
            ...     "async": "1"
            ... }
            >>> process_id = scans.generate_report(payload_data)
            >>>
            >>> process_id = client.reports.generate_scan_report(
            ...     "scan_code", "xlsx"
            ... )
        """
        scan_code = payload_data.get("scan_code", "unknown")

        logger.debug(
            f"Generating report for scan '{scan_code}' "
            f"(type={payload_data.get('report_type')})..."
        )

        payload = {
            "group": "scans",
            "action": "generate_report",
            "data": payload_data,
        }
        response_data = self._api._send_request(payload)

        if "_raw_response" in response_data:
            raw_response = response_data["_raw_response"]
            logger.info(f"Synchronous report generation completed for " f"scan '{scan_code}'.")
            return raw_response
        elif (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested (async) for "
                f"scan '{scan_code}'. Process ID: {process_id}"
            )
            return int(process_id)
        else:
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Failed to request report generation for " f"scan '{scan_code}': {error_msg}",
                details=response_data,
            )

    # ===== NOTICE EXTRACT OPERATIONS =====

    def notice_extract_run(
        self,
        scan_code: str,
        extract_type: str = "NOTICE_EXTRACT_FILE",
    ) -> bool:
        """
        Start notice file generation for a scan.

        Wraps ``scans -> notice_extract_run``. Status polling uses
        ``check_status`` with the matching ``NOTICE_EXTRACT_*`` type.

        Args:
            scan_code: Code of the scan
            extract_type: One of NOTICE_EXTRACT_FILE, NOTICE_EXTRACT_COMPONENT,
                NOTICE_EXTRACT_AGGREGATE

        Returns:
            True when the API reports success (data is truthy)

        Raises:
            ScanNotFoundError: If the scan does not exist
            ApiError: If the API returns an error
        """
        logger.debug(f"notice_extract_run for scan '{scan_code}' type={extract_type}")
        payload = {
            "group": "scans",
            "action": "notice_extract_run",
            "data": {
                "scan_code": scan_code,
                "type": extract_type,
            },
        }
        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Failed to start notice extract ({extract_type}) for "
                f"scan '{scan_code}': {error_msg}",
                details=response,
            )
        data = response.get("data")
        if isinstance(data, bool):
            return data
        if data in (1, "1", "true", "True"):
            return True
        return bool(data)

    def notice_extract_download(
        self,
        scan_code: str,
        extract_type: str = "NOTICE_EXTRACT_FILE",
    ) -> Union[requests.Response, str]:
        """
        Download generated notice file text for a scan.

        Wraps ``scans -> notice_extract_download``. The server may return
        raw text (non-JSON) or JSON with string data.

        Returns:
            ``requests.Response`` for streamed content, or a string body
            when the API returns JSON-wrapped text.

        Raises:
            ScanNotFoundError: If the scan does not exist
            ApiError: If the download fails
        """
        logger.debug(f"notice_extract_download for scan '{scan_code}' " f"type={extract_type}")
        payload = {
            "group": "scans",
            "action": "notice_extract_download",
            "data": {
                "scan_code": scan_code,
                "type": extract_type,
            },
        }
        response_data = self._api._send_request(payload)
        if "_raw_response" in response_data:
            return response_data["_raw_response"]
        if response_data.get("status") == "1":
            data = response_data.get("data")
            if isinstance(data, str):
                return data
        error_msg = response_data.get("error", "Unknown API error")
        if helpers.is_scan_not_found(error_msg):
            helpers.raise_scan_not_found(scan_code)
        raise ApiError(
            f"Failed to download notice extract ({extract_type}) for "
            f"scan '{scan_code}': {error_msg}",
            details=response_data,
        )

    def import_report(self, scan_code: str):
        """
        Imports a SBOM into a scan.

        Args:
            scan_code: Code of the scan to import the SBOM into

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.info(f"Starting SBOM import for '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "import_report",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            if helpers.is_scan_not_found(error_msg):
                helpers.raise_scan_not_found(scan_code)
            raise ApiError(
                f"Failed to start SBOM report import for '{scan_code}': {error_msg}",
                details=response,
            )
        logger.info(f"SBOM import for '{scan_code}' started successfully.")
