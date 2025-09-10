import logging
import sys

# Package imports
from workbench_agent.api import WorkbenchAPI
from workbench_agent.cli import parse_cmdline_args
from workbench_agent.utilities.config_display import (
    print_configuration,
    print_workbench_connection_info,
)
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
)

# Import all handlers from the handlers package
from workbench_agent.handlers import (
    handle_blind_scan,
    handle_download_reports,
    handle_evaluate_gates,
    handle_import_da,
    handle_import_sbom,
    handle_scan,
    handle_scan_git,
    handle_show_results,
    handle_quick_scan,
)


def setup_logging(log_level: str) -> logging.Logger:
    """
    Set up enhanced logging configuration with both file and console handlers.

    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    # Parse log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear any existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure file handler with detailed format
    file_handler = logging.FileHandler(
        "workbench-agent-log.txt", mode="w", encoding="utf-8"
    )
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - "
        "%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(numeric_level)
    root_logger.addHandler(file_handler)

    # Configure console handler with simpler format
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)

    # Configure workbench-agent logger (don't propagate to avoid duplication)
    app_logger = logging.getLogger("workbench-agent")
    app_logger.setLevel(numeric_level)

    return app_logger


def uses_legacy_interface(args_list: list) -> bool:
    """
    Detect if the command line arguments use the legacy underscore interface.

    Args:
        args_list: List of command line arguments (sys.argv[1:])

    Returns:
        bool: True if legacy interface is detected
    """
    from .cli.common import uses_legacy_interface as cli_common_uses_legacy

    return cli_common_uses_legacy(args_list)


def handle_legacy_request() -> int:
    """
    Handle legacy requests using the refactored legacy module.

    Returns:
        int: Exit code from the legacy handler
    """
    from .legacy import handle_legacy_main

    return handle_legacy_main()


def main() -> int:
    """
    Main entry point for the Workbench Agent.

    Detects whether legacy or modern interface is being used:
    - Legacy: Delegates directly to original-wb-agent.py
    - Modern: Uses new command-based handlers

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        # Quick check for legacy interface before any parsing
        args_list = sys.argv[1:] if len(sys.argv) > 1 else []

        if uses_legacy_interface(args_list):
            # Delegate directly to original script for full compatibility
            return handle_legacy_request()

        # Modern interface - proceed with new implementation
        args = parse_cmdline_args()

        # Setup logging for modern commands
        logger = setup_logging(args.log)

        # Print configuration for verification
        print_configuration(args)

        logger.info("FossID Workbench Agent starting...")
        logger.debug(f"Command line arguments: {vars(args)}")

        # Initialize Workbench API client
        logger.info("Initializing Workbench API client...")
        workbench = WorkbenchAPI(
            api_url=args.api_url,
            api_user=args.api_user,
            api_token=args.api_token,
        )
        logger.info("Workbench API client initialized.")

        # Display Workbench connection information
        print_workbench_connection_info(args, workbench)

        # Command dispatch for modern commands
        COMMAND_HANDLERS = {
            "scan": handle_scan,
            "blind-scan": handle_blind_scan,
            "scan-git": handle_scan_git,
            "show-results": handle_show_results,
            "import-da": handle_import_da,
            "evaluate-gates": handle_evaluate_gates,
            "import-sbom": handle_import_sbom,
            "download-reports": handle_download_reports,
            "quick-scan": handle_quick_scan,
        }

        command_key = args.command
        handler = COMMAND_HANDLERS.get(command_key)

        if handler:
            # Execute the command handler
            logger.info(f"Executing {command_key} command...")
            # Handlers raise exceptions on failure
            result = handler(workbench, args)

            # Determine exit code based on command and result
            if command_key == "evaluate-gates":
                # evaluate-gates returns True for PASS, False for FAIL
                exit_code = 0 if result else 1
                if exit_code == 0:
                    print(
                        "\nWorkbench Agent finished successfully "
                        "(Gates Passed)."
                    )
                else:
                    # Don't print 'Error' here, just the status
                    print("\nWorkbench Agent finished (Gates FAILED).")
                return exit_code
            else:
                # For other commands, success is assumed if no exception
                # was raised
                if result:
                    print("\nWorkbench Agent finished successfully.")
                    return 0
                else:
                    logger.error("Handler reported failure")
                    print("\nWorkbench Agent finished with errors.")
                    return 1
        else:
            # This case should ideally be caught by argparse,
            # but handle defensively
            print(f"Error: Unknown command '{command_key}'.")
            logger.error(
                f"Unknown command '{command_key}' encountered in main "
                f"dispatch."
            )
            raise ValidationError(f"Unknown command/scan type: {command_key}")

    except (ValidationError, ConfigurationError, AuthenticationError) as e:
        # Configuration/validation errors - user fixable
        try:
            logger.error(f"Configuration error: {e}")
        except NameError:
            # logger not yet initialized
            pass
        print(f"Error: {e}")
        return 2

    except (
        ApiError,
        NetworkError,
        ProcessError,
        ProcessTimeoutError,
        FileSystemError,
        CompatibilityError,
        ProjectNotFoundError,
        ScanNotFoundError,
    ) as e:
        # Runtime errors during execution
        try:
            logger.error(f"Runtime error: {e}")
        except NameError:
            # logger not yet initialized
            pass
        print(f"Error: {e}")
        return 1

    except Exception as e:
        # Unexpected errors
        try:
            logger.error(f"Unexpected error: {e}")
        except NameError:
            # logger not yet initialized
            pass
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
