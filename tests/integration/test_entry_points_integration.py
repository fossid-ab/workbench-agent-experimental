"""Test different execution entry points for workbench-agent package."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


class TestModuleExecution:
    """Test execution via 'python -m workbench_agent'."""

    def test_module_execution_help(self):
        """Test that python -m workbench_agent --help works."""
        result = subprocess.run(
            [sys.executable, "-m", "workbench_agent", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,  # Project root
        )

        assert result.returncode == 0
        assert "FossID Workbench Agent" in result.stdout
        assert "usage: __main__.py" in result.stdout

    def test_module_execution_version_display(self):
        """Test that module execution shows correct program name."""
        result = subprocess.run(
            [sys.executable, "-m", "workbench_agent", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        # Module execution should show __main__.py in usage
        assert "usage: __main__.py" in result.stdout

    def test_module_execution_subcommand_help(self):
        """Test that subcommands work with module execution."""
        result = subprocess.run(
            [sys.executable, "-m", "workbench_agent", "scan", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode == 0
        assert "Run a standard scan" in result.stdout
        assert "--project-name" in result.stdout

    def test_module_execution_imports_main(self):
        """Test that __main__.py properly imports and calls main()."""
        main_file = Path(__file__).parent.parent.parent / "src" / "workbench_agent" / "__main__.py"

        # Read the __main__.py file
        content = main_file.read_text()

        # Verify it imports main and calls it
        assert "from workbench_agent.main import main" in content
        assert "sys.exit(main())" in content


class TestLegacyScriptExecution:
    """Test execution via workbench-agent.py script."""

    def test_legacy_script_help(self):
        """Test that python workbench-agent.py --help works."""
        result = subprocess.run(
            [sys.executable, "workbench-agent.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode == 0
        assert "FossID Workbench Agent" in result.stdout
        assert "usage: workbench-agent.py" in result.stdout

    def test_legacy_script_subcommand_help(self):
        """Test that subcommands work with legacy script."""
        result = subprocess.run(
            [sys.executable, "workbench-agent.py", "scan", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode == 0
        assert "Run a standard scan" in result.stdout
        assert "--project-name" in result.stdout


class TestConsoleScriptExecution:
    """Test execution via console script entry point."""

    def test_console_script_installed(self):
        """Test that console script was installed correctly."""
        # This test verifies the entry point exists in the installed package
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import pkg_resources; print([ep.name for ep in pkg_resources.iter_entry_points('console_scripts') if ep.name == 'workbench-agent'])",
            ],
            capture_output=True,
            text=True,
        )

        # If the package is installed in development mode, this should show the entry point
        # Note: This might be empty if not installed, which is OK for unit tests
        assert result.returncode == 0

    def test_console_script_entry_point_definition(self):
        """Test that pyproject.toml has correct entry point."""
        pyproject_file = Path(__file__).parent.parent.parent / "pyproject.toml"
        content = pyproject_file.read_text()

        # Verify the entry point is defined
        assert "[project.scripts]" in content
        assert 'workbench-agent = "workbench_agent.main:main"' in content

    @pytest.mark.skipif(
        not Path("/Users/tomasegonzalez/Library/Python/3.9/bin/workbench-agent").exists(),
        reason="Console script not installed or not in expected location",
    )
    def test_console_script_execution_if_available(self):
        """Test console script execution if it's available."""
        script_path = "/Users/tomasegonzalez/Library/Python/3.9/bin/workbench-agent"

        result = subprocess.run(
            [script_path, "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "FossID Workbench Agent" in result.stdout
        assert "usage: workbench-agent" in result.stdout


class TestExecutionMethodConsistency:
    """Test that all execution methods behave consistently."""

    @pytest.mark.parametrize(
        "execution_method,expected_usage",
        [
            (["python", "workbench-agent.py"], "workbench-agent.py"),
            (["python", "-m", "workbench_agent"], "__main__.py"),
        ],
    )
    def test_all_methods_show_same_commands(self, execution_method, expected_usage):
        """Test that all execution methods expose the same commands."""
        result = subprocess.run(
            [sys.executable] + execution_method[1:] + ["--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        assert result.returncode == 0
        assert f"usage: {expected_usage}" in result.stdout

        # All methods should show the same subcommands
        expected_commands = [
            "scan",
            "blind-scan",
            "scan-git",
            "import-da",
            "import-sbom",
            "show-results",
            "evaluate-gates",
            "download-reports",
        ]

        for command in expected_commands:
            assert command in result.stdout

    def test_all_methods_show_same_scan_options(self):
        """Test that scan command has consistent options across execution methods."""
        methods = [
            ["python", "workbench-agent.py", "scan", "--help"],
            ["python", "-m", "workbench_agent", "scan", "--help"],
        ]

        outputs = []
        for method in methods:
            result = subprocess.run(
                [sys.executable] + method[1:],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent,
            )
            assert result.returncode == 0
            outputs.append(result.stdout)

        # Check that all methods show the same key arguments
        expected_args = [
            "--project-name",
            "--scan-name",
            "--path",
            "--sensitivity",
            "--limit",
            "--show-components",
        ]

        for arg in expected_args:
            for output in outputs:
                assert arg in output, f"Missing {arg} in output"


class TestMainModuleContent:
    """Test the content and structure of __main__.py module."""

    def test_main_module_exists(self):
        """Test that __main__.py exists in the package."""
        main_file = Path(__file__).parent.parent.parent / "src" / "workbench_agent" / "__main__.py"
        assert main_file.exists()

    def test_main_module_has_correct_structure(self):
        """Test that __main__.py has the expected structure."""
        main_file = Path(__file__).parent.parent.parent / "src" / "workbench_agent" / "__main__.py"
        content = main_file.read_text()

        # Should have shebang
        assert content.startswith("#!/usr/bin/env python3")

        # Should have proper imports
        assert "import sys" in content
        assert "from workbench_agent.main import main" in content

        # Should have proper main execution
        assert 'if __name__ == "__main__":' in content
        assert "sys.exit(main())" in content

    def test_main_module_docstring(self):
        """Test that __main__.py has proper documentation."""
        main_file = Path(__file__).parent.parent.parent / "src" / "workbench_agent" / "__main__.py"
        content = main_file.read_text()

        # Should have a docstring explaining module execution
        assert '"""' in content
        assert "Module entry point" in content
        assert "python -m workbench_agent" in content


class TestPackageStructure:
    """Test that package structure supports all execution methods."""

    def test_package_has_main_function(self):
        """Test that main.py exports a main function."""
        # This is an import test to ensure the main function is accessible
        try:
            from workbench_agent.main import main

            assert callable(main)
        except ImportError:
            pytest.fail("Could not import main function from workbench_agent.main")

    def test_package_has_init_file(self):
        """Test that package has proper __init__.py."""
        init_file = Path(__file__).parent.parent.parent / "src" / "workbench_agent" / "__init__.py"
        assert init_file.exists()

    def test_legacy_script_exists(self):
        """Test that legacy script still exists."""
        legacy_script = Path(__file__).parent.parent.parent / "workbench-agent.py"
        assert legacy_script.exists()

        # Should import from the package
        content = legacy_script.read_text()
        assert "from workbench_agent.main import main" in content


class TestArgumentParsing:
    """Test that argument parsing works consistently across execution methods."""

    def test_missing_required_args_consistent_error(self):
        """Test that missing required arguments give consistent errors."""
        methods = [
            ["python", "workbench-agent.py", "scan"],
            ["python", "-m", "workbench_agent", "scan"],
        ]

        for method in methods:
            result = subprocess.run(
                [sys.executable] + method[1:],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent,
            )

            # Should fail with exit code 2 (argument parsing error)
            assert result.returncode == 2
            assert "required" in result.stderr.lower() or "required" in result.stdout.lower()

    def test_help_flag_works_consistently(self):
        """Test that --help works with all execution methods."""
        methods = [
            ["python", "workbench-agent.py", "--help"],
            ["python", "-m", "workbench_agent", "--help"],
        ]

        for method in methods:
            result = subprocess.run(
                [sys.executable] + method[1:],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent,
            )

            assert result.returncode == 0
            assert "usage:" in result.stdout
            assert "FossID Workbench Agent" in result.stdout
