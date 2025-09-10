import json
import logging

import requests

from workbench_agent.exceptions import ApiError, AuthenticationError, NetworkError

logger = logging.getLogger("workbench-agent")


class BaseAPI:
    """
    Base class for Workbench API interactions.
    Provides only essential API communication functionality.
    """

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initialize the base Workbench API client with authentication details.

        Args:
            api_url: URL to the API endpoint
            api_user: API username
            api_token: API token/key
        """
        # Ensure the API URL ends with api.php
        if not api_url.endswith("/api.php"):
            self.api_url = api_url.rstrip("/") + "/api.php"
            print(f"Warning: API URL adjusted to: {self.api_url}")
        else:
            self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token
        self.session = requests.Session()
        self.session.trust_env = False

    def _send_request(self, payload: dict, timeout: int = 1800) -> dict:
        """
        Sends a POST request to the Workbench API.
        Handles expected non-JSON responses for synchronous operations.

        Args:
            payload: The request payload
            timeout: Request timeout in seconds

        Returns:
            Dict with response data or a special _raw_response key for non-JSON
            responses

        Raises:
            NetworkError: For connection issues, timeouts, etc.
            AuthenticationError: For authentication failures
            ApiError: For API-level errors
        """
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
        }
        payload.setdefault("data", {})
        payload["data"]["username"] = self.api_user
        payload["data"]["key"] = self.api_token

        req_body = json.dumps(payload)
        logger.debug("API URL: %s", self.api_url)
        logger.debug("Request Headers: %s", headers)
        logger.debug("Request Body: %s", req_body)

        try:
            response = self.session.post(
                self.api_url, headers=headers, data=req_body, timeout=timeout
            )
            logger.debug("Response Status Code: %s", response.status_code)
            logger.debug("Response Headers: %s", response.headers)
            # Log first part of text regardless of JSON success/failure
            logger.debug(
                f"Response Text (first 500 chars): "
                f"{response.text[:500] if hasattr(response, 'text') else '(No text)'}"
            )

            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials or expired token")

            response.raise_for_status()

            content_type = response.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                try:
                    parsed_json = response.json()
                    # Check for API-level errors indicated by status='0'
                    if isinstance(parsed_json, dict) and parsed_json.get("status") == "0":
                        error_msg = parsed_json.get("error", "Unknown API error")
                        logger.debug(
                            f"API returned status 0 JSON: {error_msg} | " f"Payload: {payload}"
                        )

                        is_invalid_type_probe = False
                        if (
                            payload.get("action") == "check_status"
                            and error_msg == "RequestData.Base.issues_while_parsing_request"
                            and isinstance(parsed_json.get("data"), list)
                            and len(parsed_json["data"]) > 0
                            and isinstance(parsed_json["data"][0], dict)
                            and parsed_json["data"][0].get("code")
                            == "RequestData.Base.field_not_valid_option"
                            and parsed_json["data"][0]
                            .get("message_parameters", {})
                            .get("fieldname")
                            == "type"
                        ):
                            is_invalid_type_probe = True
                            logger.debug(
                                "Detected 'invalid type option' error during " "check_status probe."
                            )

                        # Determine if this error is expected and non-fatal
                        is_existence_check = payload.get("action") == "get_information"

                        if is_invalid_type_probe or is_existence_check:
                            # Don't raise an exception for these expected cases
                            return parsed_json
                        else:
                            # For other status 0 cases, raise an exception
                            raise ApiError(f"API Error: {error_msg}", details=parsed_json)

                    return parsed_json
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse JSON response: {e}")
                    raise ApiError(f"Invalid JSON response: {e}")
            else:
                # Handle non-JSON responses (like file downloads)
                logger.debug(f"Non-JSON response received (Content-Type: {content_type})")
                return {"_raw_response": response}

        except requests.exceptions.Timeout:
            raise NetworkError(f"Request timeout after {timeout} seconds")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection error: {e}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("Invalid credentials or expired token")
            raise NetworkError(f"HTTP error {e.response.status_code}: {e}")
        except Exception as e:
            if isinstance(e, (ApiError, AuthenticationError, NetworkError)):
                raise
            raise NetworkError(f"Unexpected request error: {e}")
