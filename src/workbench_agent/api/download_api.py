import json
import logging

import requests

from workbench_agent.exceptions import ApiError, NetworkError

logger = logging.getLogger("workbench-agent")


class DownloadAPI:
    """
    Workbench API Download Operations.
    Assumes it will be mixed into a class that has self.api_user, self.api_token,
    self.api_url, and self.session.
    """

    def _download_report(self, report_entity: str, process_id: int):
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.
        """
        logger.debug(
            f"Attempting to download report for process ID '{process_id}' (entity: {report_entity})..."
        )

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "report_entity": report_entity,
                "process_id": str(process_id),
            },
        }
        req_body = json.dumps(payload)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }

        logger.debug("Download API URL: %s", self.api_url)
        logger.debug("Download Request Headers: %s", headers)
        logger.debug("Download Request Body: %s", req_body)

        try:
            logger.debug(f"Initiating download request for process ID: {process_id}")
            r = self.session.post(
                self.api_url, headers=headers, data=req_body, stream=True, timeout=1800
            )
            logger.debug(f"Download Response Status Code: {r.status_code}")
            logger.debug(f"Download Response Headers: {r.headers}")
            r.raise_for_status()

            content_type = r.headers.get("content-type", "").lower()
            content_disposition = r.headers.get("content-disposition")
            logger.info(f"Download Content-Type received: {content_type}")
            if content_disposition:
                logger.info(f"Download Content-Disposition received: {content_disposition}")

            is_likely_file_content = bool(content_disposition) or (
                "application/json" not in content_type
            )

            if not is_likely_file_content:
                logger.warning(
                    f"Received JSON content type without Content-Disposition. Assuming API error message."
                )
                try:
                    error_json = r.json()
                    error_msg = error_json.get("error", "Unknown error")
                    logger.error(f"API error during download: {error_msg} | JSON: {error_json}")
                    raise ApiError(
                        f"Failed to download report (process ID {process_id}): API returned error - {error_msg}",
                        details=error_json,
                    )
                except json.JSONDecodeError:
                    logger.error(
                        f"Failed to decode JSON error response during download: {r.text[:500]}",
                        exc_info=True,
                    )
                    raise ApiError(
                        f"Failed to download report (process ID {process_id}): Could not parse API error response.",
                        details={"response_text": r.text[:500]},
                    )

            logger.debug("Download request successful, returning response object.")
            return r

        except requests.exceptions.RequestException as req_err:
            logger.error(
                f"Failed to initiate report download request for process {process_id}: {req_err}",
                exc_info=True,
            )
            raise NetworkError(f"Failed to download report (process ID {process_id}): {req_err}")
        except Exception as final_dl_err:
            logger.error(
                f"Unexpected error within download_report function for process {process_id}: {final_dl_err}",
                exc_info=True,
            )
            raise ApiError(
                f"Unexpected error during report download (process ID {process_id})",
                details={"error": str(final_dl_err)},
            )
