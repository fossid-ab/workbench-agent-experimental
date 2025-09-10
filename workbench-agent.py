#!/usr/bin/env python3

# Copyright: FossID AB 2022

import sys

# Keep backward compatibility by creating an alias
from workbench_agent.api import WorkbenchAPI
from workbench_agent.main import main  # Import the main function from the package

Workbench = WorkbenchAPI


if __name__ == "__main__":
    sys.exit(main())  # Call the main function and exit with its code
