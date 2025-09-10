"""
Error handling utilities for the Workbench Agent.

This module contains functions for standardized error handling and formatting
across all CLI handlers.
"""

import argparse
import functools
import logging
from typing import Callable

from workbench_agent.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    ConfigurationError,
    FileSystemError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)

logger = logging.getLogger("workbench-agent")


def format_and_print_error(error: Exception, handler_name: str, params: argparse.Namespace):
    """
    Formats and prints a standardized error message for CLI users.

    This centralized function handles consistent error formatting across
    all handlers, eliminating duplicated error handling code.

    Args:
        error: The exception that occurred
        handler_name: Name of the handler where the error occurred
        params: Command line parameters
    """
    command = getattr(params, "command", "unknown")
    error_type = type(error).__name__

    # Get error details if available (for our custom errors)
    error_message = getattr(error, "message", str(error))
    error_code = getattr(error, "code", None)
    error_details = getattr(error, "details", {})

    # Determine if this is a read-only operation
    read_only_commands = {"show-results", "evaluate-gates", "download-reports"}
    is_read_only = command in read_only_commands

    # Add context-specific help based on error type
    if isinstance(error, ProjectNotFoundError):
        if is_read_only:
            print(f"\n❌ Cannot continue: The requested project does not exist")
            print(
                f"   Project '{getattr(params, 'project_name', 'unknown')}' was not found in your Workbench instance."
            )
            print(f"\n💡 Please check:")
            print(f"   • The project name is spelled correctly")
            print(f"   • The project exists in your Workbench instance")
            print(f"   • You have access to the project")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(f"  → Project '{getattr(params, 'project_name', 'unknown')}' was not found")
            print(f"  → Check the project name or use --create-project to create it")

    elif isinstance(error, ScanNotFoundError):
        if is_read_only:
            print(f"\n❌ Cannot continue: The requested scan does not exist")
            scan_name = getattr(params, "scan_name", "unknown")
            project_name = getattr(params, "project_name", None)

            if project_name:
                print(f"   Scan '{scan_name}' was not found in project '{project_name}'.")
            else:
                print(f"   Scan '{scan_name}' was not found in your Workbench instance.")

            print(f"\n💡 Please check:")
            print(f"   • The scan name is spelled correctly")
            if project_name:
                print(f"   • The scan exists in the '{project_name}' project")
            else:
                print(f"   • The scan exists in your Workbench instance")
                print(
                    f"   • Consider specifying --project-name if the scan is in a specific project"
                )
            print(f"   • You have access to the scan")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(f"  → Scan '{getattr(params, 'scan_name', 'unknown')}' was not found")
            if hasattr(params, "project_name"):
                print(
                    f"  → Check the scan name or verify it exists in project '{params.project_name}'"
                )
            else:
                print(
                    f"  → Check the scan name or specify --project-name if it exists in a specific project"
                )

    elif isinstance(error, NetworkError):
        print(f"\n❌ Network connectivity issue")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • The Workbench server is accessible")
        print(f"   • The API URL is correct: {getattr(params, 'api_url', '<not specified>')}")

    elif isinstance(error, ApiError):
        # Check for credential errors first
        if "user_not_found_or_api_key_is_not_correct" in error_message:
            print(f"\n❌ Invalid credentials")
            print(f"   The username or API token provided is incorrect.")
            print(f"\n💡 Please check:")
            print(f"   • Your username: {getattr(params, 'api_user', '<not specified>')}")
            print(f"   • Your API token is correct and not expired")
            print(f"   • Your account has access to the Workbench instance")
            print(f"   • The API URL is correct: {getattr(params, 'api_url', '<not specified>')}")
            return  # Exit early to avoid showing generic API error details

        print(f"\n❌ Workbench API error")
        print(f"   {error_message}")

        if error_code:
            print(f"   Error code: {error_code}")

            # Special handling for Git repository access errors
            if error_code == "git_repository_access_error":
                print(f"\n💡 Git repository access issue:")
                print(
                    f"   • Check that the Git URL is correct and accessible from the Workbench server"
                )
                print(f"   • Ensure any required authentication is properly configured")
            else:
                print(f"\n💡 The Workbench API reported an issue with your request")

    elif isinstance(error, ProcessTimeoutError):
        print(f"\n❌ Operation timed out")
        print(f"   {error_message}")
        print(f"\n💡 Consider increasing the timeout values:")
        print(
            f"   • --scan-number-of-tries (current: {getattr(params, 'scan_number_of_tries', 'default')})"
        )
        print(f"   • --scan-wait-time (current: {getattr(params, 'scan_wait_time', 'default')})")

    elif isinstance(error, ProcessError):
        print(f"\n❌ Workbench process error")
        print(f"   {error_message}")
        print(f"\n💡 A Workbench process failed to complete successfully")

    elif isinstance(error, FileSystemError):
        print(f"\n❌ File system error")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • File permissions are correct")
        print(f"   • All specified paths exist")
        if hasattr(params, "path"):
            print(f"   • Path specified: {params.path}")

    elif isinstance(error, ValidationError):
        print(f"\n❌ Invalid input or configuration")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments and input files")

    elif isinstance(error, ConfigurationError):
        print(f"\n❌ Configuration error")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments and configuration")

    elif isinstance(error, CompatibilityError):
        print(f"\n❌ Compatibility issue")
        print(f"   {error_message}")
        print(f"\n💡 The requested operation is not compatible with the scan's current state")

    elif isinstance(error, AuthenticationError):
        print(f"\n❌ Authentication failed")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • Your API credentials are correct")
        print(f"   • You have the necessary permissions")

    else:
        # Generic error formatting for unexpected errors
        print(f"\n❌ Error executing '{command}' command: {error_message}")

    # Show error code if available (and not already shown)
    if error_code and not isinstance(error, (ApiError, ProcessTimeoutError)):
        print(f"\nError code: {error_code}")

    # Show details in verbose mode
    if getattr(params, "verbose", False) and error_details:
        print("\nDetailed error information:")
        for key, value in error_details.items():
            print(f"  • {key}: {value}")

    # Add help text only for non-read-only operations or when in verbose mode
    if not is_read_only or getattr(params, "verbose", False):
        print(f"\nFor more details, run with --log DEBUG for verbose output")


def handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    A decorator that wraps handler functions with standardized error handling.

    This wrapper ensures consistent error handling across all handlers, reducing
    code duplication and ensuring all exceptions are properly logged and handled.
    The wrapper catches exceptions, formats user-friendly error messages, and
    re-raises the exceptions for proper exit code handling in the main CLI.

    Args:
        handler_func: The handler function to wrap

    Returns:
        The wrapped handler function with error handling

    Example:
        @handler_error_wrapper
        def handle_scan(workbench, params):
            # Implementation without try/except blocks
            ...
    """

    @functools.wraps(handler_func)
    def wrapper(workbench, params):
        try:
            # Get the handler name for better error messages
            handler_name = handler_func.__name__
            command_name = params.command if hasattr(params, "command") else "unknown"
            logger.debug(f"Starting {handler_name} for command '{command_name}'")

            # Call the actual handler function
            return handler_func(workbench, params)

        except (
            ProjectNotFoundError,
            ScanNotFoundError,
            FileSystemError,
            ApiError,
            NetworkError,
            ProcessError,
            ProcessTimeoutError,
            ValidationError,
            CompatibilityError,
            ConfigurationError,
            AuthenticationError,
        ) as e:
            # These exceptions are expected and properly formatted already
            # Format and display error message in standardized format
            logger.debug(
                f"Expected error in {handler_func.__name__}: {type(e).__name__}: {getattr(e, 'message', str(e))}"
            )
            format_and_print_error(e, handler_func.__name__, params)
            # Re-raise the exception for proper exit code handling
            raise

        except Exception as e:
            # Unexpected errors get wrapped in a WorkbenchAgentError
            logger.error(f"Unexpected error in {handler_func.__name__}: {e}", exc_info=True)

            # Create a WorkbenchAgentError with detailed info
            agent_error = WorkbenchAgentError(
                f"Failed to execute {params.command if hasattr(params, 'command') else 'command'}: {str(e)}",
                details={"error": str(e), "handler": handler_func.__name__},
            )

            # Format and display the error message
            format_and_print_error(agent_error, handler_func.__name__, params)

            # Raise the wrapped error for proper exit code handling
            raise agent_error

    return wrapper
