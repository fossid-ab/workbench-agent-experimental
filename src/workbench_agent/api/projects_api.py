import logging
from typing import Any, Dict, List, Optional

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.helpers.generate_download_report import ReportHelper
from workbench_agent.exceptions import ApiError, ProjectExistsError, ProjectNotFoundError

logger = logging.getLogger("workbench-agent")


class ProjectsAPI(BaseAPI, ReportHelper):
    """
    Workbench API Project Operations.
    """

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all projects.

        Returns:
            List[Dict[str, Any]]: List of project data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all projects...")
        payload = {"group": "projects", "action": "list_projects", "data": {}}
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} projects.")
                return data
            else:
                logger.warning(
                    f"API returned success for list_projects but 'data' was not a list: {type(data)}"
                )
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list projects: {error_msg}", details=response)

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans within a specific project.

        Args:
            project_code: Code of the project to get scans for

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Listing scans for the '{project_code}' project...")
        payload = {
            "group": "projects",
            "action": "get_all_scans",
            "data": {"project_code": project_code},
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} scans for project '{project_code}'.")
                return data
            else:
                logger.warning(
                    f"API returned success for get_all_scans but 'data' was not a list: {type(data)}"
                )
                return []
        elif response.get("status") == "1":
            logger.warning("API returned success for get_all_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            # Treat project not found as empty list of scans
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                logger.warning(f"Project '{project_code}' not found when trying to list its scans.")
                return []
            else:
                raise ApiError(
                    f"Failed to list scans for project '{project_code}': {error_msg}",
                    details=response,
                )

    def create_project(
        self,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> str:
        """
        Create a new project in Workbench.

        Args:
            project_name: Name of the project to create
            product_name: Optional product name (human-readable application name)
            comment: Optional comment

        Returns:
            The project code of the created project

        Raises:
            ProjectExistsError: If a project with this name already exists
            ApiError: If project creation fails
            NetworkError: If there are network issues
        """
        try:
            # First check if project exists
            projects = self.list_projects()
            for project in projects:
                if project.get("name") == project_name:
                    raise ProjectExistsError(f"Project '{project_name}' already exists")

            # Create the project with additional metadata
            payload_data = {"project_name": project_name}

            # Add optional metadata fields
            if product_code:
                payload_data["product_code"] = product_code
            if product_name:
                payload_data["product_name"] = product_name
            if description:
                payload_data["description"] = description
            if comment:
                payload_data["comment"] = comment

            payload = {"group": "projects", "action": "create", "data": payload_data}
            response = self._send_request(payload)

            if response.get("status") == "1":
                project_code = response.get("data", {}).get("project_code")
                if not project_code:
                    raise ApiError("Project created but no code returned", details=response)
                return project_code
            else:
                error_msg = response.get("error", "Unknown error")
                raise ApiError(
                    f"Failed to create project '{project_name}': {error_msg}", details=response
                )

        except ProjectExistsError:
            raise
        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(f"Failed to create project '{project_name}'", details={"error": str(e)})

    def download_report(self, process_id: int):
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.
        """
        logger.debug(f"Attempting to download project report for process ID '{process_id}'...")
        return self._download_report("projects", process_id)

    def generate_project_report(
        self,
        project_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ) -> int:
        """
        Triggers asynchronous report generation for a project.

        Returns:
            int: Process queue ID for the async report generation.
        """
        logger.info(
            f"Requesting generation of '{report_type}' report for project '{project_code}' (Async)..."
        )
        payload_data = self.build_project_report_data(
            project_code, report_type, selection_type, selection_view, disclaimer, include_vex
        )

        payload = {"group": "projects", "action": "generate_report", "data": payload_data}

        response_data = self._send_request(payload)

        if (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested successfully for project '{project_code}'. Process ID: {process_id}"
            )
            return int(process_id)
        else:
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            raise ApiError(
                f"Failed to request report generation for project '{project_code}': {error_msg}",
                details=response_data,
            )

    def check_project_report_status(self, process_id: int, project_code: str) -> Dict[str, Any]:
        """
        Checks the status of an asynchronous project report generation process.
        """
        logger.debug(
            f"Checking report generation status for process {process_id} (project '{project_code}')..."
        )
        payload = {
            "group": "projects",
            "action": "check_status",
            "data": {
                "process_id": str(process_id),
                "type": "REPORT_GENERATION",
            },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(
                f"Failed to check report status for process {process_id} (project '{project_code}'): {error_msg}",
                details=response,
            )
