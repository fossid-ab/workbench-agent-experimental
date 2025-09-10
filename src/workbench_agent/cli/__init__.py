# workbench_agent/cli/__init__.py

"""
CLI module for workbench-agent.

This module provides command-line argument parsing and validation functionality.
"""

from .common import (
    KNOWN_SUBCOMMANDS,
    LEGACY_INDICATORS,
    uses_legacy_interface,
    uses_modern_interface,
)
from .parser import parse_cmdline_args, show_argument_usage
from .validators import validate_parsed_args

__all__ = [
    "parse_cmdline_args",
    "show_argument_usage",
    "validate_parsed_args",
    "uses_modern_interface",
    "uses_legacy_interface",
    "KNOWN_SUBCOMMANDS",
    "LEGACY_INDICATORS",
]
