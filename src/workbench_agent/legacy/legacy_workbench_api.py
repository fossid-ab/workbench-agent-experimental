"""
Legacy Workbench API for backward compatibility.

This module contains the original Workbench class copied from the original-wb-agent.py
to provide complete API isolation for legacy mode. This allows the modern WorkbenchAPI
to evolve independently without affecting legacy functionality.

This module will be removed when legacy support is discontinued.
"""

import base64
import builtins
import io
import json
import logging
import os
import sys
import time
import traceback

import requests

logger = logging.getLogger("workbench-agent")


class Workbench:
    """
    A class to interact with the FossID Workbench API for managing scans and projects.

    This is the original Workbench class preserved for legacy compatibility.

    Attributes:
        api_url (str): The base URL of the Workbench API.
        api_user (str): The username used for API authentication.
        api_token (str): The API token for authentication.
    """

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initializes the Workbench object with API credentials and endpoint.

        Args:
            api_url (str): The base URL of the Workbench API.
            api_user (str): The username used for API authentication.
            api_token (str): The API token for authentication.
        """
        self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token

    def _send_request(self, payload: dict) -> dict:
        """
        Sends a request to the Workbench API.

        Args:
            payload (dict): The payload of the request.

        Returns:
            dict: The JSON response from the API.
        """
        url = self.api_url
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
        }
        req_body = json.dumps(payload)
        logger.debug("url %s", url)
        logger.debug("url %s", headers)
        logger.debug(req_body)
        response = requests.request("POST", url, headers=headers, data=req_body, timeout=1800)
        logger.debug(response.text)
        try:
            # Attempt to parse the JSON
            parsed_json = json.loads(response.text)
            return parsed_json
        except json.JSONDecodeError as e:
            # If an error occurs, catch it and display the message along with the problematic JSON
            print("Failed to decode JSON")
            print(f"Error message: {e.msg}")
            print(f"At position: {e.pos}")
            print("Problematic JSON:")
            print(response.text)

    def _read_in_chunks(self, file_object: io.BufferedReader, chunk_size=5242880):
        """
        Generator to read a file piece by piece.

        Args:
            file_object (io.BufferedReader) : The payload of the request.
            chunk_size (int): Size of the chunk. Default chunk size is 5MB
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _chunked_upload_request(self, scan_code: str, headers: dict, chunk: bytes):
        """
        This function will make sure Content-Length header is not sent by Requests library
        Args:
            scan_code (str): The scan code where the file or files will be uploaded.
            headers (dict) : Headers for HTTP request
            chunk (bytes): Chunk read from large file
        """
        try:
            req = requests.Request(
                "POST",
                self.api_url,
                headers=headers,
                data=chunk,
                auth=(self.api_user, self.api_token),
            )
            s = requests.Session()
            prepped = s.prepare_request(req)
            # Remove the unwanted header  'Content-Length' !!!
            if "Content-Length" in prepped.headers:
                del prepped.headers["Content-Length"]

            # Send HTTP request and retrieve response
            response = s.send(prepped)
            # print(f"Sent headers: {response.request.headers}")
            # print(f"response headers: {response.headers}")
            # Retrieve the HTTP status code
            status_code = response.status_code
            print(f"HTTP Status Code: {status_code}")

            # Check if the request was successful (status code 200)
            if status_code == 200:
                # Parse the JSON response
                try:
                    response.json()
                except:
                    print(f"Failed to decode json {response.text}")
                    print(traceback.print_exc())
                    sys.exit(1)
            else:
                print(f"Request failed with status code {status_code}")
                reason = response.reason
                print(f"Reason: {reason}")
                response_text = response.text
                print(f"Response Text: {response_text}")
                sys.exit(1)
        except IOError:
            # Error opening file
            print(f"Failed to upload files to the scan {scan_code}.")
            print(traceback.print_exc())
            sys.exit(1)

    def upload_files(self, scan_code: str, path: str, chunked_upload: bool = False):
        """
        Uploads files to the Workbench using the API's File Upload endpoint.

        Args:
            scan_code (str): The scan code where the file or files will be uploaded.
            path (str): Path to the file or files to upload.
            chunked_upload (bool): Enable/disable chunk upload.
        """
        file_size = os.path.getsize(path)
        size_limit = (
            8 * 1024 * 1024
        )  # 8MB in bytes. Based on the default value of post_max_size in php.ini
        # Prepare parameters
        filename = os.path.basename(path)
        filename_base64 = base64.b64encode(filename.encode()).decode("utf-8")
        scan_code_base64 = base64.b64encode(scan_code.encode()).decode("utf-8")

        if chunked_upload and (file_size > size_limit):
            print(
                f"Uploading {filename} using 'Transfer-encoding: chunks' due to file size {file_size}."
            )
            # Use chunked upload for files bigger than size_limit
            # First delete possible existing files because chunk uploading works by appending existing file on disk.
            self.remove_uploaded_content(filename, scan_code)
            print("Uploading using Transfer-encoding: chunked...")
            headers = {
                "FOSSID-SCAN-CODE": scan_code_base64,
                "FOSSID-FILE-NAME": filename_base64,
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/octet-stream",
            }
            try:
                with open(path, "rb") as file:
                    for chunk in self._read_in_chunks(file, 5242880):
                        # Upload each chunk
                        self._chunked_upload_request(scan_code, headers, chunk)
            except IOError:
                # Error opening file
                print(f"Failed to upload files to the scan {scan_code}.")
                print(traceback.print_exc())
                sys.exit(1)
            print("Finished uploading.")
        else:
            # Regular upload, no chunk upload
            headers = {"FOSSID-SCAN-CODE": scan_code_base64, "FOSSID-FILE-NAME": filename_base64}
            print("Uploading...")
            try:
                with open(path, "rb") as file:
                    resp = requests.post(
                        self.api_url,
                        headers=headers,
                        data=file,
                        auth=(self.api_user, self.api_token),
                        timeout=1800,
                    )
                    # Retrieve the HTTP status code
                    status_code = resp.status_code
                    print(f"HTTP Status Code: {status_code}")

                    # Check if the request was successful (status code 200)
                    if status_code == 200:
                        # Parse the JSON response
                        try:
                            resp.json()
                        except:
                            print(f"Failed to decode json {resp.text}")
                            print(traceback.print_exc())
                            sys.exit(1)
                    else:
                        print(f"Request failed with status code {status_code}")
                        reason = resp.reason
                        print(f"Reason: {reason}")
                        response_text = resp.text
                        print(f"Response Text: {response_text}")
                        sys.exit(1)
            except IOError:
                # Error opening file
                print(f"Failed to upload files to the scan {scan_code}.")
                print(traceback.print_exc())
                sys.exit(1)
            print("Finished uploading.")

    def _delete_existing_scan(self, scan_code: str):
        """
        Deletes a scan

        Args:
            scan_code (str): The code of the scan to be deleted

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "delete",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "delete_identifications": "true",
            },
        }
        return self._send_request(payload)

    def create_webapp_scan(
        self, scan_code: str, project_code: str = None, target_path: str = None
    ) -> bool:
        """
        Creates a Scan in Workbench. The scan can optionally be created inside a Project.

        Args:
            scan_code (str): The unique identifier for the scan.
            project_code (str, optional): The project code within which to create the scan.
            target_path (str, optional): The target path where scan is stored.

        Returns:
            bool: True if the scan was successfully created, False otherwise.
        """
        payload = {
            "group": "scans",
            "action": "create",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "scan_name": scan_code,
                "project_code": project_code,
                "target_path": target_path,
                "description": "Scan created using the Workbench Agent.",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Failed to create scan {}: {}".format(scan_code, response))
        if "error" in response.keys():
            raise builtins.Exception(
                "Failed to create scan {}: {}".format(scan_code, response["error"])
            )
        return response["data"]["scan_id"]

    def _get_scan_status(self, scan_type: str, scan_code: str):
        """
        Calls API scans -> check_status to determine if the process is finished.

        Args:
            scan_type (str): One of these: SCAN, REPORT_IMPORT, DEPENDENCY_ANALYSIS, REPORT_GENERATION, DELETE_SCAN.
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The data section from the JSON response returned from API.
        """
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "type": scan_type,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception(
                "Failed to retrieve scan status from \
                scan {}: {}".format(
                    scan_code, response["error"]
                )
            )
        return response["data"]

    def start_dependency_analysis(self, scan_code: str):
        """
        Initiate dependency analysis for a scan.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception(
                "Failed to start dependency analysis scan {}: {}".format(
                    scan_code, response["error"]
                )
            )

    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ):
        """
        Check if the scan finished after each 'scan_wait_time' seconds for 'scan_number_of_tries' number of tries.
        If the scan is finished return status data and duration. If the scan is not finished after all tries throw Exception.

        Args:
            scan_type (str): Types: SCAN, REPORT_IMPORT, DEPENDENCY_ANALYSIS, REPORT_GENERATION, DELETE_SCAN
            scan_code (str): Unique scan identifier.
            scan_number_of_tries (int): Number of calls to "check_status" till declaring the scan failed.
            scan_wait_time (int): Time interval between calling "check_status", expressed in seconds

        Returns:
            tuple: (status_data, duration) where status_data is dict and duration is float
        """
        start_time = time.time()

        # pylint: disable-next=unused-variable
        for x in range(scan_number_of_tries):
            scan_status = self._get_scan_status(scan_type, scan_code)
            is_finished = (
                scan_status["is_finished"]
                or scan_status["is_finished"] == "1"
                or scan_status["status"] == "FAILED"
                or scan_status["status"] == "FINISHED"
            )
            if is_finished:
                if (
                    scan_status["percentage_done"] == "100%"
                    or scan_status["percentage_done"] == 100
                    or (
                        scan_type == "DEPENDENCY_ANALYSIS"
                        and (
                            scan_status["percentage_done"] == "0%"
                            or scan_status["percentage_done"] == "0%%"
                        )
                    )
                    or (
                        scan_status["status"] == "FINISHED"
                        and (
                            scan_status["percentage_done"] == "0%"
                            or scan_status["percentage_done"] == "0%%"
                        )
                    )
                ):
                    print(
                        "Scan percentage_done = {}%, scan has finished. Status: {}".format(
                            scan_status["percentage_done"], scan_status["status"]
                        )
                    )
                    duration = time.time() - start_time
                    return scan_status, duration
                raise builtins.Exception(
                    "Scan finished with status: {}  percentage: {} ".format(
                        scan_status["status"], scan_status["percentage_done"]
                    )
                )
            # If scan did not finished, print info about progress
            print(
                "Scan {} is running. Percentage done: {}%  Status: {}".format(
                    scan_code, scan_status["percentage_done"], scan_status["status"]
                )
            )
            # Wait given time
            time.sleep(scan_wait_time)
        # If this code is reached it means the scan didn't finished after  scan_number_of_tries X scan_wait_time
        print("{} timeout: {}".format(scan_type, scan_code))
        raise builtins.Exception("scan timeout")

    def _get_pending_files(self, scan_code: str):
        """
        Call API scans -> get_pending_files.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        # all other situations
        raise builtins.Exception(
            "Error getting pending files \
            result: {}".format(
                response
            )
        )

    def scans_get_policy_warnings_counter(self, scan_code: str):
        """
        Retrieve policy warnings information at scan level.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting project policy warnings information \
            result: {}".format(
                response
            )
        )

    def projects_get_policy_warnings_info(self, project_code: str):
        """
        Retrieve policy warnings information at project level.

        Args:
            project_code (str): The unique identifier for the project.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "projects",
            "action": "get_policy_warnings_info",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting project policy warnings information \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_components(self, scan_code: str):
        """
        Retrieve the list of identified components from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting identified components \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_licenses(self, scan_code: str):
        """
        Retrieve the list of identified licenses from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "unique": "1",
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting identified licenses \
            result: {}".format(
                response
            )
        )

    def get_results(self, scan_code: str):
        """
        Retrieve the list matches from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_results",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "unique": "1",
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting scans ->get_results \
            result: {}".format(
                response
            )
        )

    def _get_dependency_analysis_result(self, scan_code: str):
        """
        Retrieve dependency analysis results.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]

        raise builtins.Exception(
            "Error getting dependency analysis \
            result: {}".format(
                response
            )
        )

    def _cancel_scan(self, scan_code: str):
        """
        Cancel a scan.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "scans",
            "action": "cancel_run",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Error cancelling scan: {}".format(response))

    def _assert_scan_can_start(self, scan_code: str):
        """
        Verify if a new scan can be initiated.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        scan_status = self._get_scan_status("SCAN", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise builtins.Exception(
                "Cannot start scan. Current status of the scan is {}.".format(scan_status["status"])
            )

    def assert_dependency_analysis_can_start(self, scan_code: str):
        """
        Verify if a new dependency analysis scan can be initiated.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        scan_status = self._get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise builtins.Exception(
                "Cannot start dependency analysis. Current status of the scan is {}.".format(
                    scan_status["status"]
                )
            )

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """
        Extract archive

         Args:
             scan_code (str): The unique identifier for the scan.
             recursively_extract_archives (bool): Yes or no
             jar_file_extraction (bool): Yes or no

         Returns:
             bool: true for successful API call
        """
        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "recursively_extract_archives": recursively_extract_archives,
                "jar_file_extraction": jar_file_extraction,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            raise builtins.Exception("Call extract_archives returned error: {}".format(response))
        return True

    def check_if_scan_exists(self, scan_code: str):
        """
        Check if scan exists.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            bool: Yes or no.
        """
        payload = {
            "group": "scans",
            "action": "get_information",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1":
            return True
        else:
            return False

    def check_if_project_exists(self, project_code: str):
        """
        Check if project exists.

        Args:
            project_code (str): The unique identifier for the scan.

        Returns:
            bool: Yes or no.
        """
        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            return False
        # if response["status"] == "0":
        #     raise builtins.Exception("Failed to get project status: {}".format(response))
        return True

    def create_project(self, project_code: str):
        """
        Create new project

        Args:
            project_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
                "project_name": project_code,
                "description": "Automatically created by Workbench Agent script",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Failed to create project: {}".format(response))
        print("Created project {}".format(project_code))

    def run_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        auto_identification_detect_declaration: bool,
        auto_identification_detect_copyright: bool,
        auto_identification_resolve_pending_ids: bool,
        delta_only: bool,
        reuse_identification: bool,
        identification_reuse_type: str = None,
        specific_code: str = None,
        advanced_match_scoring: bool = True,
        match_filtering_threshold: int = -1,
    ):
        """

        Args:
            scan_code (str):                                Unique scan identifier
            limit (int):                                    Limit the number of matches against the KB
            sensitivity (int):                              Result sensitivity
            auto_identification_detect_declaration (bool):  Automatically detect license declaration inside files
            auto_identification_detect_copyright (bool):    Automatically detect copyright statements inside files
            auto_identification_resolve_pending_ids (bool): Automatically resolve pending identifications
            delta_only (bool):                              Scan only new or modified files
            reuse_identification (bool):                    Reuse previous identifications
            identification_reuse_type (str):                Possible values: any,only_me,specific_project,specific_scan
            specific_code (str):                            Fill only when reuse type: specific_project or specific_scan
            advanced_match_scoring (bool):                  If true, scan will run with advanced match scoring.
            match_filtering_threshold (int):                Minimum length (in characters) of snippet to be considered
                                                            valid after applying intelligent match filtering.
        Returns:

        """
        scan_exists = self.check_if_scan_exists(scan_code)
        if not scan_exists:
            raise builtins.Exception(
                "Scan with scan_code: {} doesn't exist when calling 'run' action!".format(scan_code)
            )

        self._assert_scan_can_start(scan_code)
        print("Starting scan {}".format(scan_code))
        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                "auto_identification_detect_declaration": int(
                    auto_identification_detect_declaration
                ),
                "auto_identification_detect_copyright": int(auto_identification_detect_copyright),
                "auto_identification_resolve_pending_ids": int(
                    auto_identification_resolve_pending_ids
                ),
                "delta_only": int(delta_only),
                "advanced_match_scoring": int(advanced_match_scoring),
            },
        }
        if match_filtering_threshold > -1:
            payload["data"]["match_filtering_threshold"] = match_filtering_threshold
        if reuse_identification:
            data = payload["data"]
            data["reuse_identification"] = "1"
            # 'any', 'only_me', 'specific_project', 'specific_scan'
            if identification_reuse_type in {"specific_project", "specific_scan"}:
                data["identification_reuse_type"] = identification_reuse_type
                data["specific_code"] = specific_code
            else:
                data["identification_reuse_type"] = identification_reuse_type

        response = self._send_request(payload)
        if response["status"] != "1":
            logger.error(
                "Failed to start scan {}: {} payload {}".format(scan_code, response, payload)
            )
            raise builtins.Exception(
                "Failed to start scan {}: {}".format(scan_code, response["error"])
            )
        return response

    def remove_uploaded_content(self, filename: str, scan_code: str):
        """
        When using chunked uploading every new chunk is appended to existing file, for this reason we need to make sure
        that initially there is no file (from previous uploading).

        Args:
            filename (str): The file to be deleted
            scan_code (str): The unique identifier for the scan.
        """
        print("Called scans->remove_uploaded_content on file {}".format(filename))
        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "filename": filename,
            },
        }
        resp = self._send_request(payload)
        if resp["status"] != "1":
            print(
                f"Cannot delete file {filename}, maybe is the first time when uploading this file? API response {resp}."
            )
