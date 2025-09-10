# tests/unit/api/helpers/test_upload_helpers.py

import io
import os
import tempfile
import time
from unittest.mock import MagicMock, call, mock_open, patch

import pytest
import requests

from workbench_agent.api.helpers.upload_helpers import UploadHelper
from workbench_agent.exceptions import NetworkError


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def upload_helper_inst(mock_session):
    """Create an UploadHelper instance with a properly mocked session."""

    # Create a concrete instance for testing
    class TestUploadHelper(UploadHelper):
        def __init__(self, api_url, api_user, api_token):
            self.api_url = api_url
            self.api_user = api_user
            self.api_token = api_token
            self.session = mock_session

    helper = TestUploadHelper(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )
    return helper


# --- Test _read_in_chunks ---
def test_read_in_chunks(upload_helper_inst):
    """Test reading file in chunks."""
    test_data = b"0123456789ABCDEF" * 1024  # 16KB of data (16 * 1024 = 16384 bytes)
    file_obj = io.BytesIO(test_data)

    chunks = list(upload_helper_inst._read_in_chunks(file_obj, chunk_size=1024))

    # Should have 16 chunks of 1KB each (16384 ÷ 1024 = 16)
    assert len(chunks) == 16
    for chunk in chunks:
        assert len(chunk) == 1024

    # Verify all data is preserved
    reconstructed = b"".join(chunks)
    assert reconstructed == test_data


def test_read_in_chunks_partial(upload_helper_inst):
    """Test reading file that doesn't divide evenly into chunks."""
    test_data = b"HELLO WORLD"
    file_obj = io.BytesIO(test_data)

    chunks = list(upload_helper_inst._read_in_chunks(file_obj, chunk_size=5))

    assert len(chunks) == 3
    assert chunks[0] == b"HELLO"
    assert chunks[1] == b" WORL"
    assert chunks[2] == b"D"


# --- Test _upload_single_chunk ---
def test_upload_single_chunk_success(upload_helper_inst, mocker):
    """Test successful single chunk upload."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "1"}

    mock_session = MagicMock()
    mock_session.send.return_value = mock_response

    with patch("requests.Session", return_value=mock_session):
        with patch("requests.Request") as mock_request:
            upload_helper_inst._upload_single_chunk(
                b"test_chunk", 1, {"Content-Type": "application/octet-stream"}
            )

    # Verify request was created and sent
    mock_request.assert_called_once()
    mock_session.send.assert_called_once()


def test_upload_single_chunk_retry_success(upload_helper_inst, mocker):
    """Test chunk upload success after retry."""
    mock_response_fail = MagicMock()
    mock_response_fail.status_code = 500
    mock_response_fail.text = "Server Error"

    mock_response_success = MagicMock()
    mock_response_success.status_code = 200
    mock_response_success.json.return_value = {"status": "1"}

    mock_session = MagicMock()
    mock_session.send.side_effect = [
        requests.exceptions.ConnectionError("Network error"),
        mock_response_success,
    ]

    with patch("requests.Session", return_value=mock_session):
        with patch("requests.Request"):
            with patch("time.sleep"):  # Mock sleep to speed up test
                upload_helper_inst._upload_single_chunk(
                    b"test_chunk", 1, {"Content-Type": "application/octet-stream"}
                )

    # Should have been called twice (initial failure + retry success)
    assert mock_session.send.call_count == 2


def test_upload_single_chunk_max_retries_exceeded(upload_helper_inst, mocker):
    """Test chunk upload failing after max retries."""
    mock_session = MagicMock()
    mock_session.send.side_effect = requests.exceptions.ConnectionError("Network error")

    with patch("requests.Session", return_value=mock_session):
        with patch("requests.Request"):
            with patch("time.sleep"):  # Mock sleep to speed up test
                with pytest.raises(
                    NetworkError, match="Network error for chunk 1 after 4 attempts"
                ):
                    upload_helper_inst._upload_single_chunk(
                        b"test_chunk", 1, {"Content-Type": "application/octet-stream"}
                    )

    # Should have been called MAX_CHUNK_RETRIES + 1 times
    assert mock_session.send.call_count == upload_helper_inst.MAX_CHUNK_RETRIES + 1


# --- Test _validate_chunk_response ---
def test_validate_chunk_response_success(upload_helper_inst):
    """Test successful chunk response validation."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "1"}

    # Should not raise any exception
    upload_helper_inst._validate_chunk_response(mock_response, 1, 0)


def test_validate_chunk_response_http_error(upload_helper_inst):
    """Test chunk response validation with HTTP error."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")

    with pytest.raises(requests.exceptions.HTTPError):
        upload_helper_inst._validate_chunk_response(
            mock_response, 1, upload_helper_inst.MAX_CHUNK_RETRIES
        )


def test_validate_chunk_response_json_error(upload_helper_inst):
    """Test chunk response validation with JSON decode error."""
    import json

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "response", 0)
    mock_response.text = "Invalid JSON response"

    # The _validate_chunk_response method catches JSON decode errors and retries
    # Let's test the retry logic by making it fail on the max retry
    with pytest.raises(NetworkError, match="Invalid JSON response from server for chunk 1"):
        upload_helper_inst._validate_chunk_response(
            mock_response, 1, upload_helper_inst.MAX_CHUNK_RETRIES
        )


# --- Test progress display methods ---
def test_should_show_progress_interval(upload_helper_inst):
    """Test progress display interval logic."""
    # Should show progress at intervals
    assert upload_helper_inst._should_show_progress(20, 0, 1, 10) is True  # First interval
    assert upload_helper_inst._should_show_progress(40, 20, 2, 10) is True  # Second interval
    assert upload_helper_inst._should_show_progress(35, 20, 2, 10) is False  # Not at interval

    # Should always show for small files
    assert upload_helper_inst._should_show_progress(10, 0, 1, 3) is True  # Small file

    # Should always show for last chunk
    assert upload_helper_inst._should_show_progress(50, 20, 10, 10) is True  # Last chunk


def test_format_progress_display(upload_helper_inst):
    """Test progress display formatting."""
    upload_helper_inst._total_file_size = 100 * 1024 * 1024  # 100MB

    progress_str = upload_helper_inst._format_progress_display(
        progress_percent=50,
        chunk_number=5,
        total_chunks=10,
        bytes_uploaded=50 * 1024 * 1024,  # 50MB
        elapsed_time=10.0,
    )

    assert "50%" in progress_str
    assert "(5/10 chunks)" in progress_str
    assert "5.0MB/s" in progress_str
    assert "ETA" in progress_str


# --- Test _perform_upload ---
def test_perform_upload_small_file(upload_helper_inst, mock_session):
    """Test upload of small file (below chunked threshold)."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        test_data = b"Small file content"
        temp_file.write(test_data)
        temp_file_path = temp_file.name

    try:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_session.post.return_value = mock_response

        headers = {"Content-Type": "application/octet-stream"}

        upload_helper_inst._perform_upload(temp_file_path, headers)

        # Verify standard upload was used
        mock_session.post.assert_called_once()

    finally:
        os.unlink(temp_file_path)


def test_perform_upload_large_file_chunked(upload_helper_inst, mocker):
    """Test upload of large file using chunked upload."""
    # Create a large temporary file (larger than CHUNKED_UPLOAD_THRESHOLD)
    large_size = upload_helper_inst.CHUNKED_UPLOAD_THRESHOLD + 1024

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Write data in chunks to avoid memory issues
        chunk_data = b"A" * 1024
        for _ in range(large_size // 1024 + 1):
            temp_file.write(chunk_data)
        temp_file_path = temp_file.name

    try:
        # Mock the chunked upload methods
        upload_helper_inst._read_in_chunks = mocker.MagicMock(return_value=[b"chunk1", b"chunk2"])
        upload_helper_inst._upload_single_chunk = mocker.MagicMock()
        upload_helper_inst._should_show_progress = mocker.MagicMock(return_value=False)

        headers = {"Content-Type": "application/octet-stream"}

        with patch("time.time", return_value=10.0):  # Mock time for performance calculation
            upload_helper_inst._perform_upload(temp_file_path, headers)

        # Verify chunked upload was used
        upload_helper_inst._read_in_chunks.assert_called_once()
        assert upload_helper_inst._upload_single_chunk.call_count == 2  # Two chunks

    finally:
        os.unlink(temp_file_path)


def test_perform_upload_network_error(upload_helper_inst, mock_session):
    """Test upload with network error."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        test_data = b"Small file content"
        temp_file.write(test_data)
        temp_file_path = temp_file.name

    try:
        mock_session.post.side_effect = requests.exceptions.ConnectionError("Network failed")

        headers = {"Content-Type": "application/octet-stream"}

        with pytest.raises(NetworkError, match="Network error during file upload"):
            upload_helper_inst._perform_upload(temp_file_path, headers)

    finally:
        os.unlink(temp_file_path)
