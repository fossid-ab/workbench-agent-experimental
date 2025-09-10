#!/usr/bin/env python3

"""
Module entry point for workbench-agent.

This allows the package to be executed as:
    python -m workbench_agent scan --project-name "Project" --scan-name "Scan" --path ./src
"""

import sys

from workbench_agent.main import main

if __name__ == "__main__":
    sys.exit(main())
