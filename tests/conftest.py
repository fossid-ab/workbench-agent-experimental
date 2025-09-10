import argparse
from unittest.mock import MagicMock, Mock, call, mock_open, patch

import pytest
import requests

# Import dependencies needed for fixtures
from workbench_agent.api import WorkbenchAPI

# Add a fallback mocker fixture for environments where pytest-mock is not installed
try:
    import pytest_mock
except ImportError:

    @pytest.fixture
    def mocker():
        """Provides a simple mock factory when pytest-mock is not available."""

        class SimpleMocker:
            def MagicMock(self, *args, **kwargs):
                return MagicMock(*args, **kwargs)

            def Mock(self, *args, **kwargs):
                return Mock(*args, **kwargs)

            def patch(self, *args, **kwargs):
                return patch(*args, **kwargs)

            def spy(self, obj, name):
                original = getattr(obj, name)
                mock = MagicMock(wraps=original)
                setattr(obj, name, mock)
                return mock

            def patch_object(self, target, attribute, *args, **kwargs):
                return patch.object(target, attribute, *args, **kwargs)

            def patch_multiple(self, target, **kwargs):
                return patch.multiple(target, **kwargs)

            def call(self, *args, **kwargs):
                return call(*args, **kwargs)

            def ANY(self):
                from unittest.mock import ANY

                return ANY

            def mock_open(self, *args, **kwargs):
                return mock_open(*args, **kwargs)

        return SimpleMocker()


@pytest.fixture
def mock_session(mocker):
    """
    Create a mock requests.Session that can be used in place of the real session.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.text = '{"status": "1", "data": {}}'
    mock_response.json.return_value = {"status": "1", "data": {}}
    mock_session.post.return_value = mock_response

    # Mock the raise_for_status method
    mock_response.raise_for_status.return_value = None

    return mock_session


@pytest.fixture
def workbench_inst(mock_session):
    """
    Create a WorkbenchAPI instance with a mock session for testing.
    """
    # Create a new instance
    wb = WorkbenchAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    # Replace the session with our mock
    wb.session = mock_session
    return wb


@pytest.fixture
def mock_workbench(mocker):
    """
    Create a completely mocked WorkbenchAPI instance for testing (no methods are real).
    This mock does not use a spec to avoid issues with mocking methods that
    are dynamically added or don't exist on the real class.
    """
    mock_wb = mocker.MagicMock()

    # Manually add all methods that the handlers will call.
    mock_wb.assert_process_can_start = mocker.MagicMock()
    mock_wb.ensure_scan_compatibility = mocker.MagicMock()

    # Setup common returns
    mock_wb._send_request.return_value = {"status": "1", "data": {}}
    return mock_wb


# Fixture for mock params object (parsed arguments)
@pytest.fixture
def mock_params(mocker):
    """Provides a mocked argparse.Namespace object for handler tests."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Set common attributes needed by handlers
    params.api_url = "http://dummy.com/api.php"
    params.scan_number_of_tries = 10
    params.scan_wait_time = 1
    # Set defaults for flags often checked
    params.show_licenses = False
    params.show_components = False
    params.show_policy_warnings = False
    params.result_save_path = None
    params.policy_check = False
    params.show_files = False
    # Set default command-specific attributes (can be overridden in tests)
    params.command = None  # Set specifically in tests needing it
    params.project_name = "test_project"
    params.scan_name = "test_scan"
    params.path = "/path/to/files"
    # Add other common params defaults
    params.report_scope = "scan"
    params.report_type = "ALL"
    params.report_save_path = "."
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.recursively_extract_archives = False
    params.jar_file_extraction = False
    return params
