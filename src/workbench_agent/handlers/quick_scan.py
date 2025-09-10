import argparse
import base64
import logging
import os
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchAPI

logger = logging.getLogger("workbench-agent")


def _format_quick_view_link(api_url: str) -> str:
    base_url = api_url.replace("/api.php", "")
    return base_url + "/?form=main_interface&action=quickview"


def _format_scan_result(result: dict, quick_view_link: str) -> str:
    component = result.get("component")
    match_type = result.get("type")
    if component:
        artifact = component.get("artifact")
        author = component.get("author")
        if match_type == "file":
            msg_a = (
                f"This entire file seems to originate from the {artifact} "
                f"repository by {author}. "
            )
            msg_b = (
                f"Drop this file into the Quick View in Workbench for more "
                f"info: {quick_view_link}"
            )
            return msg_a + msg_b
        if match_type == "partial":
            remote_size = result.get("snippet", {}).get("remote_size")
            part_a = (
                f"This file has {remote_size} lines that resemble content "
            )
            part_b = f"{artifact} by {author}. "
            msg_b = (
                f"Drop this file into the Quick View in Workbench for more "
                f"info: {quick_view_link}"
            )
            return part_a + part_b + msg_b
        return "Unknown match type."
    return "No matches found."


@handler_error_wrapper
def handle_quick_scan(
    workbench: "WorkbenchAPI",
    params: argparse.Namespace,
) -> bool:
    print(f"\n--- Running {params.command.upper()} Command ---")

    if not params.path:
        raise ValueError("A --path to the file to scan is required")
    if not os.path.exists(params.path) or not os.path.isfile(params.path):
        raise ValueError(f"Invalid file path: {params.path}")

    with open(params.path, "rb") as f:
        file_content_b64 = base64.b64encode(f.read()).decode("utf-8")

    print("\nPerforming quick scan...")
    results = workbench.quick_scan_file(
        file_content_b64=file_content_b64,
        limit=params.limit,
        sensitivity=params.sensitivity,
    )

    quick_view_link = _format_quick_view_link(workbench.api_url)
    if getattr(params, "raw", False):
        import json

        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No matches found.")
        else:
            for result in results:
                message = _format_scan_result(result, quick_view_link)
                logger.info(message)
                print(message)

    return True
