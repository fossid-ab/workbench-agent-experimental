"""
Configuration display utilities for the Workbench Agent.

This module provides functions for displaying startup configuration information
in a well-organized format, including agent settings, operation parameters,
result display options, and connection information.
"""

from typing import Any


def print_configuration(params: Any) -> None:
    """
    Print configuration summary for modern commands only.
    Organizes parameters into logical groups: agent configuration,
    user-provided operation parameters, default operation parameters,
    and result display settings.

    Args:
        params: Parsed command line parameters
    """
    print("--- Workbench Agent Configuration ---")
    print(f"Command: {params.command}")

    # Get user-provided arguments (if available)
    user_provided: set = getattr(params, "_user_provided", set())

    # Parameters that will be displayed separately
    connection_params = {"api_url", "api_user", "api_token"}
    agent_config_params = {
        "log",
        "fossid_cli_path",
        "scan_number_of_tries",
        "scan_wait_time",
        "no_wait",
    }
    result_display_params = {
        "show_licenses",
        "show_components",
        "show_dependencies",
        "show_scan_metrics",
        "show_policy_warnings",
        "show_vulnerabilities",
        "show_pending_files",
        "result_save_path",
    }

    # Separate parameters into categories
    agent_config = {}
    result_display = {}
    user_params = {}
    default_params = {}

    for k, v in params.__dict__.items():
        if k in ["command", "_user_provided"] or k in connection_params:
            continue  # Skip these special keys and connection params

        display_val = v

        if k in agent_config_params:
            agent_config[k] = display_val
        elif k in result_display_params:
            result_display[k] = display_val
        elif k in user_provided:
            user_params[k] = display_val
        else:
            default_params[k] = display_val

    # Print agent configuration
    if agent_config:
        print("\n⚙️  Agent Configuration:")
        for k, v in sorted(agent_config.items()):
            print(f"  {k:<30} = {v}")

    # Print user-provided operation parameters
    if user_params:
        print("\n📝 User-Provided Parameters:")
        for k, v in sorted(user_params.items()):
            print(f"  {k:<30} = {v}")

    # Print default operation parameters
    if default_params:
        print("\n⚙️  Default Parameters:")
        for k, v in sorted(default_params.items()):
            print(f"  {k:<30} = {v}")

    # Print result display settings
    if result_display:
        print("\n📊 Result Display:")
        for k, v in sorted(result_display.items()):
            print(f"  {k:<30} = {v}")

    print("------------------------------------")


def print_workbench_connection_info(params: Any, workbench_api: Any) -> None:
    """
    Print Workbench connection information including server details.

    Args:
        params: Command line parameters containing connection details
        workbench_api: WorkbenchAPI instance for getting server info
    """
    print("\n🔗 Workbench Connection Info:")

    # Get debug mode for token masking
    debug_mode = getattr(params, "log", "INFO").upper() == "DEBUG"

    # Display connection parameters
    print(f"  API URL                    : {params.api_url}")
    print(f"  API User                   : {params.api_user}")

    # Mask token unless in debug mode
    token_display = params.api_token if debug_mode else "****"
    print(f"  API Token                  : {token_display}")

    # Get and display server information
    server_info = workbench_api.get_server_info()

    if server_info:
        server_name = server_info.get("server_name", "Unknown")
        print(f"  Server Name                : {server_name}")
        version = server_info.get("version", "Unknown")
        print(f"  Workbench Version          : {version}")
        print("  Status                     : ✓ Connected")
    else:
        print("  Server Name                : Unknown")
        print("  Workbench Version          : Unknown")
        print("  Status                     : ⚠ Could not detect server info")

    print("------------------------------------")
