"""ProjectsClient - project-related Workbench API operations."""

import logging
from typing import Any, Dict, List, Literal, Optional

PolicyWarningType = Literal["identifications", "dependencies", "all"]

from workbench_agent.api.exceptions import ApiError, ValidationError
from workbench_agent.api.validation.field_limits import validate_project_create_fields

from . import helpers

logger = logging.getLogger("workbench-agent")


class ProjectsClient:
    """
    Projects API client (group: projects).

    Request/response fields: ``clients/projects/schema.md``.
    Server quirks: ``clients/projects/quirks.md``.

    Example:
        >>> projects = ProjectsClient(base_api)
        >>> all_projects = projects.list_projects()
        >>> project_code = projects.create("MyProject")
    """

    def __init__(self, base_api):
        """
        Initialize ProjectsClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("ProjectsClient initialized")

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List all projects.

        No request ``data`` fields. See ``schema.md`` for response keys.
        """
        logger.debug("Listing all projects...")

        response = self._api._send_request(
            {"group": "projects", "action": "list_projects", "data": {}}
        )

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} projects.")
                return data
            logger.warning(f"API returned success but 'data' was not a list: " f"{type(data)}")
            return []

        helpers.raise_on_failed_response(response, error_context="Failed to list projects")
        return []

    def get_information(self, project_code: str) -> Dict[str, Any]:
        """
        Get detailed information for a project.

        Required: ``project_code``. Raises ``ProjectNotFoundError`` when missing.
        """
        logger.debug(f"Fetching information for project '{project_code}'...")
        response = self._api._send_request(
            {
                "group": "projects",
                "action": "get_information",
                "data": {"project_code": project_code},
            }
        )

        if response.get("status") == "1" and "data" in response:
            logger.debug(f"Success fetching information for project '{project_code}'.")
            return response["data"]

        error_msg = response.get("error", f"Unexpected response: {response}")
        if helpers.is_project_not_found(error_msg):
            helpers.raise_project_not_found(project_code)
        raise ApiError(
            f"Failed to get project info for '{project_code}': {error_msg}",
            details=response,
        )

    def get_policy_warnings_info(
        self,
        project_code: str,
        *,
        warning_type: PolicyWarningType = "identifications",
    ) -> Dict[str, Any]:
        """
        Policy warnings aggregated across scans in a project.

        Args:
            project_code: Target project code.
            warning_type: ``identifications`` (scan file policy hits),
                ``dependencies`` (dependency analysis), or ``all``.

        Returns:
            Dict with ``scans_with_warnings``, ``warnings_counter``, and
            ``scans_list`` (list of scan dicts or ``null``).

        Raises:
            ProjectNotFoundError: If the project does not exist.
            ApiError: On other API failures.
        """
        logger.debug(
            "Fetching project policy warnings for '%s' (type=%s)",
            project_code,
            warning_type,
        )
        response = self._api._send_request(
            {
                "group": "projects",
                "action": "get_policy_warnings_info",
                "data": {
                    "project_code": project_code,
                    "type": warning_type,
                },
            }
        )

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(
                    "Retrieved project policy warnings for '%s'",
                    project_code,
                )
                return data
            raise ApiError(
                f"Unexpected data type for project policy warnings: " f"{type(data)}",
                details=response,
            )

        error_msg = response.get("error", f"Unexpected response: {response}")
        if helpers.is_project_not_found(error_msg):
            helpers.raise_project_not_found(project_code)
        raise ApiError(
            f"Failed to get policy warnings for project " f"'{project_code}': {error_msg}",
            details=response,
        )

    def get_all_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        List scans in a project.

        Required: ``project_code``. Returns ``[]`` if project code unknown.
        """
        logger.debug(f"Listing scans for the '{project_code}' project...")
        response = self._api._send_request(
            {
                "group": "projects",
                "action": "get_all_scans",
                "data": {"project_code": project_code},
            }
        )

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Found {len(data)} scans in project '{project_code}'.")
                return data
            logger.warning(f"API success but 'data' is not a list: {type(data)}")
            return []
        if response.get("status") == "1":
            logger.warning("API success but no 'data' key found.")
            return []

        error_msg = response.get("error", f"Unexpected response: {response}")
        if helpers.is_project_not_found(error_msg):
            logger.warning(f"Project code '{project_code}' not found.")
            return []
        raise ApiError(
            f"Failed to list scans in project '{project_code}': {error_msg}",
            details=response,
        )

    def create(
        self,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
        project_code: Optional[str] = None,
    ) -> str:
        """
        Create a project.

        Required: ``project_name``. Optional ``project_code`` when the client
        supplies the internal identifier; otherwise Workbench assigns one.
        """
        validate_project_create_fields(
            project_name=project_name,
            project_code=project_code,
            product_code=product_code,
            product_name=product_name,
            jira_project_key=jira_project_key,
        )
        payload_data: Dict[str, Any] = {"project_name": project_name}
        if project_code:
            payload_data["project_code"] = project_code
        if product_code:
            payload_data["product_code"] = product_code
        if product_name:
            payload_data["product_name"] = product_name
        if description:
            payload_data["description"] = description
        if comment:
            payload_data["comment"] = comment
        if limit_date:
            payload_data["limit_date"] = limit_date
        if jira_project_key:
            payload_data["jira_project_key"] = jira_project_key

        response = self._api._send_request(
            {"group": "projects", "action": "create", "data": payload_data}
        )

        if response.get("status") == "1":
            returned_code = response.get("data", {}).get("project_code")
            if project_code:
                return str(project_code)
            if not returned_code:
                raise ApiError(
                    "Project created but no code returned",
                    details=response,
                )
            return str(returned_code)

        helpers.try_raise_create_parsing_request_error(response, project_name=project_name)
        error_msg = response.get("error", "Unknown error")
        raise ApiError(
            f"Failed to create project '{project_name}': {error_msg}",
            details=response,
        )

    def update(
        self,
        project_code: str,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
        new_project_owner: Optional[str] = None,
    ) -> int:
        """
        Update a project.

        Required: ``project_code``, ``project_name``. Optional fields — see
        ``schema.md``.
        """
        logger.debug(f"Updating project '{project_code}'...")

        payload_data: Dict[str, Any] = {
            "project_code": project_code,
            "project_name": project_name,
        }
        if product_code is not None:
            payload_data["product_code"] = product_code
        if product_name is not None:
            payload_data["product_name"] = product_name
        if description is not None:
            payload_data["description"] = description
        if comment is not None:
            payload_data["comment"] = comment
        if limit_date is not None:
            payload_data["limit_date"] = limit_date
        if jira_project_key is not None:
            payload_data["jira_project_key"] = jira_project_key
        if new_project_owner is not None:
            payload_data["new_project_owner"] = new_project_owner

        response = self._api._send_request(
            {"group": "projects", "action": "update", "data": payload_data}
        )

        if response.get("status") == "1":
            project_id = response.get("data", {}).get("project_id")
            if not project_id:
                raise ApiError("Project updated but no ID returned", details=response)
            logger.debug(f"Successfully updated project '{project_code}'.")
            return int(project_id)

        helpers.try_raise_parsing_request_error(
            response,
            context="update",
            project_code=project_code,
        )
        error_msg = response.get("error", "Unknown error")
        if helpers.is_project_not_found(error_msg):
            helpers.raise_project_not_found(project_code)
        raise ApiError(
            f"Failed to update project '{project_code}': {error_msg}",
            details=response,
        )

    def generate_report(self, payload_data: Dict[str, Any]) -> int:
        """
        Generate a project report (prefer ``ReportService`` for building payloads).

        Pass-through ``data`` dict — typically ``project_code``, ``report_type``,
        ``async``, and report options. See ``schema.md``.
        """
        project_code = payload_data.get("project_code", "unknown")

        logger.debug(
            f"Generating report for project '{project_code}' "
            f"(type={payload_data.get('report_type')})..."
        )

        response_data = self._api._send_request(
            {
                "group": "projects",
                "action": "generate_report",
                "data": payload_data,
            }
        )

        if (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested for project "
                f"'{project_code}'. Process ID: {process_id}"
            )
            return int(process_id)

        error_msg = response_data.get("error", f"Unexpected response: {response_data}")
        if helpers.is_project_not_found(error_msg):
            helpers.raise_project_not_found(project_code)
        raise ApiError(
            f"Failed to request report generation for project " f"'{project_code}': {error_msg}",
            details=response_data,
        )

    def check_status(
        self,
        process_id: int,
        process_type: str,
    ) -> Dict[str, Any]:
        """
        Check async project operation status.

        Required: ``process_id``, ``type`` (e.g. ``REPORT_GENERATION``).
        """
        logger.debug(f"Checking {process_type} status for process {process_id}...")

        response = self._api._send_request(
            {
                "group": "projects",
                "action": "check_status",
                "data": {
                    "process_id": str(process_id),
                    "type": process_type,
                },
            }
        )

        if response.get("status") == "1" and "data" in response:
            return response["data"]

        error_msg = response.get("error", f"Unexpected response: {response}")
        raise ApiError(
            f"Failed to check {process_type} status for process " f"{process_id}: {error_msg}",
            details=response,
        )
