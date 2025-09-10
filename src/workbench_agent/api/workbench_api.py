import logging

from workbench_agent.api.helpers.project_scan_resolvers import (
    ResolveWorkbenchProjectScan,
)
from workbench_agent.api.internal_api import InternalAPI
from workbench_agent.api.projects_api import ProjectsAPI
from workbench_agent.api.scans_api import ScansAPI
from workbench_agent.api.upload_api import UploadAPI
from workbench_agent.api.vulnerabilities_api import VulnerabilitiesAPI
from workbench_agent.api.quick_scan_api import QuickScanAPI

logger = logging.getLogger("workbench-agent")


class WorkbenchAPI(
    UploadAPI,
    ResolveWorkbenchProjectScan,
    ProjectsAPI,
    VulnerabilitiesAPI,
    ScansAPI,
    QuickScanAPI,
    InternalAPI,
):
    """
    Workbench API client class for interacting with the FossID Workbench API.
    This class composes all the individual API parts into a single client.
    """

    def get_server_info(self) -> dict:
        """
        Detects Workbench server information for display during startup.
        This provides the foundation for future version-aware API behavior.

        Returns:
            dict: Server information including version, server_name, etc.
                 Returns empty dict if detection fails.

        Note:
            This method is designed to be non-blocking for startup - if
            detection fails, it logs a warning but doesn't raise exceptions.
        """
        try:
            logger.info("Detecting Workbench server information...")
            config_data = self.get_config()

            # Extract version and server information
            server_info = {
                "version": config_data.get("version", "Unknown"),
                "server_name": config_data.get("server_name", "Unknown"),
                "default_language": config_data.get("default_language", "Unknown"),
            }

            # Log additional configuration for debugging
            logger.debug("Server configuration detected:")
            logger.debug(f"  - Version: {server_info['version']}")
            logger.debug(f"  - Server name: {server_info['server_name']}")
            default_lang = server_info["default_language"]
            logger.debug(f"  - Default language: {default_lang}")

            version_detected = server_info["version"]
            logger.info(f"Successfully detected Workbench version: {version_detected}")
            return server_info

        except Exception as e:
            # Non-blocking failure - log warning but continue
            logger.warning(f"Could not detect Workbench server info: {e}")
            logger.debug(f"Server info detection failed with error: {e}", exc_info=True)
            return {}
