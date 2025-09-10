import logging
from typing import Any, Dict

from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class InternalAPI(BaseAPI):
    """
    Workbench Internal API Operations.

    This class handles internal Workbench API operations like configuration
    retrieval. It inherits from APIBase.

    """

    def get_config(self) -> Dict[str, Any]:
        """
        Retrieves the Workbench configuration including version information.

        Returns:
            Dict[str, Any]: Configuration data including version,
                          server settings, and feature flags

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Getting Workbench configuration...")
        payload = {"group": "internal", "action": "getConfig", "data": {}}
        response = self._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug("Successfully retrieved Workbench configuration.")
                return data
            else:
                logger.warning(
                    f"API returned success for getConfig but 'data' was not "
                    f"a dict: {type(data)}"
                )
                return {}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to get configuration: {error_msg}", details=response)
