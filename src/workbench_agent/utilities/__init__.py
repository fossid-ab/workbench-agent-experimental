"""
Utility modules for the Workbench Agent.
"""

# Re-export commonly used exceptions and utilities for backward compatibility
from workbench_agent.exceptions import ValidationError, WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
