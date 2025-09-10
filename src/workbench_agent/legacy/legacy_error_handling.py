"""
Legacy error handling utilities for the Workbench Agent.

This module provides legacy error handling and formatting isolated from modern
implementations to allow independent evolution of modern error handling patterns.
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
    ProjectExistsError,
    ProjectNotFoundError,
    ScanExistsError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchAgentError,
)

# Exception categorization based on inspiration patterns (legacy frozen version)
USER_SETUP_ERRORS = (AuthenticationError, ConfigurationError, ValidationError, CompatibilityError)
RUNTIME_ERRORS = (ApiError, NetworkError, ProcessError, ProcessTimeoutError, FileSystemError)
RESOURCE_ERRORS = (ProjectNotFoundError, ScanNotFoundError, ProjectExistsError, ScanExistsError)

logger = logging.getLogger("workbench-agent")


def agent_error_wrapper(parse_args_func: Callable):
    """
    Legacy decorator for main function that provides error handling.

    Args:
        parse_args_func: Function to parse command line arguments

    Returns:
        Decorator function that wraps main with comprehensive error handling
    """

    def decorator(main_func: Callable):
        @functools.wraps(main_func)
        def wrapper():
            import time

            start_time = time.monotonic()

            try:
                return main_func()

            except USER_SETUP_ERRORS as e:
                # Errors typically due to user input/setup
                print(f"\nDetailed Error Information:")
                print(f"Configuration Error: {getattr(e, 'message', str(e))}")
                if logger:
                    logger.error(
                        "%s: %s", type(e).__name__, getattr(e, "message", str(e)), exc_info=False
                    )
                return 1

            except RUNTIME_ERRORS as e:
                # Runtime interaction errors
                print(f"\nDetailed Error Information:")
                print(f"Runtime Error: {getattr(e, 'message', str(e))}")
                if logger:
                    logger.error(
                        "%s: %s", type(e).__name__, getattr(e, "message", str(e)), exc_info=True
                    )
                return 1

            except RESOURCE_ERRORS as e:
                # Resource errors
                print(f"\nDetailed Error Information:")
                print(f"Resource Error: {getattr(e, 'message', str(e))}")
                if logger:
                    logger.error(
                        "%s: %s", type(e).__name__, getattr(e, "message", str(e)), exc_info=True
                    )
                return 1

            except WorkbenchAgentError as e:
                # Catch any other specific agent errors
                print(f"\nDetailed Error Information:")
                print(f"Workbench Agent Error: {getattr(e, 'message', str(e))}")
                if logger:
                    logger.error(
                        "Unhandled WorkbenchAgentError: %s",
                        getattr(e, "message", str(e)),
                        exc_info=True,
                    )
                return 1

            except KeyboardInterrupt:
                print(f"\nOperation interrupted by user")
                if logger:
                    logger.warning("Operation interrupted by user")
                return 130

            except Exception as e:
                # Catch truly unexpected errors with full debugging
                print(f"\nDetailed Error Information:")
                print(f"Unexpected Error: {e}")
                import traceback

                tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
                print("".join(tb_lines).rstrip())
                if logger:
                    logger.critical("Unexpected error occurred", exc_info=True)
                return 1

            finally:
                # Always show duration using legacy format_duration
                from .legacy_utils import format_duration

                end_time = time.monotonic()
                duration_seconds = end_time - start_time
                duration_str = format_duration(duration_seconds)
                print(f"\nTotal Execution Time: {duration_str}")
                if logger:
                    logger.info("Total execution time: %s", duration_str)

        return wrapper

    return decorator


def handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    Legacy decorator that wraps handler functions with standardized error handling.

    Args:
        handler_func: The handler function to wrap

    Returns:
        The wrapped handler function with error handling
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
            logger.debug(
                f"Expected error in {handler_func.__name__}: {type(e).__name__}: {getattr(e, 'message', str(e))}"
            )
            format_and_print_error(e, params)
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
            format_and_print_error(agent_error, params)

            # Raise the wrapped error for proper exit code handling
            raise agent_error

    return wrapper


def format_and_print_error(error: Exception, params: argparse.Namespace):
    """
    Legacy function that formats and prints standardized error messages.

    Args:
        error: The exception that occurred
        params: Command line parameters
    """
    error_type = type(error).__name__

    # Get error details if available (for our custom errors)
    error_message = getattr(error, "message", str(error))
    error_code = getattr(error, "code", None)
    error_details = getattr(error, "details", {})

    # Add context-specific help based on error type
    if isinstance(error, ProjectNotFoundError):
        print(f"\n❌ Project not found")
        project_ref = getattr(params, "project_code", getattr(params, "project_name", "Unknown"))
        print(f"   Project '{project_ref}' does not exist in your Workbench instance.")
        print(f"\n💡 Possible solutions:")
        print(f"   • Check that the project name is spelled correctly")
        print(
            f"   • Verify the project exists in Workbench: {getattr(params, 'api_url', 'Unknown')}"
        )
        print(f"   • Ensure your account has access to this project")
        print(f"   • The project will be created automatically if it doesn't exist")

    elif isinstance(error, ScanNotFoundError):
        print(f"\n❌ Scan not found")
        project_ref = getattr(params, "project_code", getattr(params, "project_name", "Unknown"))
        scan_ref = getattr(params, "scan_code", getattr(params, "scan_name", "Unknown"))
        print(f"   Scan '{scan_ref}' does not exist in project '{project_ref}'.")
        print(f"\n💡 Possible solutions:")
        print(f"   • Check that the scan name is spelled correctly")
        print(f"   • Verify the scan exists in the specified project")
        print(f"   • The scan will be created automatically if it doesn't exist")

    elif isinstance(error, NetworkError):
        print(f"\n❌ Network connectivity issue")
        print(f"   Unable to connect to the Workbench server.")
        print(f"   Details: {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • The Workbench server is accessible from your CI/CD environment")
        print(f"   • The API URL is correct: {getattr(params, 'api_url', 'Unknown')}")
        print(f"   • Network firewalls allow outbound HTTPS connections")
        print(f"   • The server is not experiencing downtime")

    elif isinstance(error, ApiError):
        # Check for credential errors first
        if "user_not_found_or_api_key_is_not_correct" in error_message:
            print(f"\n❌ Invalid Workbench credentials")
            print(f"   The username or API token provided is incorrect.")
            print(f"\n💡 Please verify:")
            print(f"   • Username: {getattr(params, 'api_user', 'Unknown')}")
            print(f"   • API token is correct and not expired")
            print(f"   • Account has access to the Workbench instance")
            print(f"   • API URL is correct: {getattr(params, 'api_url', 'Unknown')}")
            print(f"\n🔧 In CI/CD pipelines:")
            print(f"   • Store credentials as secure environment variables")
            print(f"   • Ensure API tokens have sufficient permissions")
            return  # Exit early to avoid showing generic API error details

        print(f"\n❌ Workbench API error")
        print(f"   {error_message}")

        if error_code:
            print(f"   Error code: {error_code}")
        print(f"\n💡 The Workbench API reported an issue with your request")

    elif isinstance(error, ProcessTimeoutError):
        print(f"\n❌ Operation timed out")
        print(f"   {error_message}")
        print(f"\n💡 For CI/CD environments, consider:")
        print(f"   • Increasing timeout values:")
        print(
            f"     --scan-number-of-tries (current: {getattr(params, 'scan_number_of_tries', 'Unknown')})"
        )
        print(f"     --scan-wait-time (current: {getattr(params, 'scan_wait_time', 'Unknown')})")
        print(f"   • Large codebases may require longer scan times")
        print(f"   • Check Workbench server performance and load")

    elif isinstance(error, ProcessError):
        print(f"\n❌ Workbench process failed")
        print(f"   {error_message}")
        print(f"\n💡 Common causes:")
        print(f"   • Scan conflicts with existing operations")
        print(f"   • Server resource limitations")
        print(f"   • Invalid scan configuration")

    elif isinstance(error, FileSystemError):
        print(f"\n❌ File system error")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • File and directory permissions are correct")
        print(f"   • Specified paths exist and are accessible")
        if hasattr(params, "path"):
            print(f"   • Source path: {params.path}")
        if hasattr(params, "path_result"):
            print(f"   • Output path: {params.path_result}")
        print(f"\n🔧 In CI/CD pipelines:")
        print(f"   • Ensure the agent has read access to source files")
        print(f"   • Verify write permissions for output directories")

    elif isinstance(error, ValidationError):
        print(f"\n❌ Invalid configuration")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments:")
        print(f"   • All required parameters are provided")
        print(f"   • Parameter values are in the correct format")
        print(f"   • File paths are valid and accessible")

    elif isinstance(error, AuthenticationError):
        print(f"\n❌ Authentication failed")
        print(f"   {error_message}")
        print(f"\n💡 Authentication checklist:")
        print(f"   • API credentials are correct")
        print(f"   • Account has necessary permissions")
        print(f"   • API token is not expired")
        print(f"   • Account is not locked or disabled")

    elif isinstance(error, (ConfigurationError, CompatibilityError)):
        # These are usually handled gracefully, but just in case
        print(f"\n⚠️  Resource already exists")
        print(f"   {error_message}")
        print(f"   This is typically handled automatically - continuing with existing resource.")

    else:
        # Generic error formatting for unexpected errors
        print(f"\n❌ Unexpected error occurred")
        print(f"   {error_message}")
        print(f"   Error type: {error_type}")

    # Show error code if available (and not already shown)
    if error_code and not isinstance(error, (ApiError,)):
        print(f"\nError code: {error_code}")

    # Show details in verbose mode
    if getattr(params, "log", "ERROR") == "DEBUG" and error_details:
        print("\n🔍 Detailed error information:")
        for key, value in error_details.items():
            print(f"   • {key}: {value}")

    # Add help text for debugging
    if getattr(params, "log", "ERROR") != "DEBUG":
        print(f"\n🔧 For more detailed logs, run with --log DEBUG")
