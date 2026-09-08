"""
Workbench field length limits for project and scan targets.

Limits mirror FossID Workbench ``RequestData`` validation and database
``varchar`` columns (see ``CreateRequestData.php`` for projects/scans).

When no customer code is supplied, Workbench auto-generates one as
``{name_with_underscores}_{autoincrement_id}``.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from workbench_agent.api.exceptions import ValidationError

PROJECT_NAME_MAX_LENGTH = 250
PROJECT_CODE_MAX_LENGTH = 250
PRODUCT_CODE_MAX_LENGTH = 250
PRODUCT_NAME_MAX_LENGTH = 250
JIRA_PROJECT_KEY_MAX_LENGTH = 250
SCAN_NAME_MAX_LENGTH = 255
SCAN_CODE_MAX_LENGTH = 255
PROJECT_CODE_ON_SCAN_MAX_LENGTH = 250

AUTO_CODE_SUFFIX_RESERVED = 7
PROJECT_NAME_SAFE_MAX_LENGTH = PROJECT_CODE_MAX_LENGTH - AUTO_CODE_SUFFIX_RESERVED
SCAN_NAME_SAFE_MAX_LENGTH = SCAN_CODE_MAX_LENGTH - AUTO_CODE_SUFFIX_RESERVED


def validate_string_length(value: str, field: str, max_length: int) -> None:
    """Raise ``ValidationError`` when ``value`` exceeds ``max_length``."""
    if len(value) > max_length:
        raise ValidationError(
            f"{field} exceeds maximum length of {max_length} characters "
            f"(got {len(value)})"
        )


def validate_optional_string(
    value: Optional[str],
    field: str,
    max_length: int,
) -> None:
    """Validate a non-empty optional string field."""
    if value is not None and value != "":
        validate_string_length(value, field, max_length)


def _effective_name_limit(
    *,
    absolute_max: int,
    safe_max: int,
    customer_code: Optional[str],
) -> int:
    if customer_code:
        return absolute_max
    return safe_max


def validate_project_create_fields(
    *,
    project_name: str,
    project_code: Optional[str] = None,
    product_code: Optional[str] = None,
    product_name: Optional[str] = None,
    jira_project_key: Optional[str] = None,
) -> None:
    """Validate project create parameters before an API call."""
    name_limit = _effective_name_limit(
        absolute_max=PROJECT_NAME_MAX_LENGTH,
        safe_max=PROJECT_NAME_SAFE_MAX_LENGTH,
        customer_code=project_code,
    )
    validate_string_length(project_name, "project_name", name_limit)
    validate_optional_string(
        project_code, "project_code", PROJECT_CODE_MAX_LENGTH
    )
    validate_optional_string(
        product_code, "product_code", PRODUCT_CODE_MAX_LENGTH
    )
    validate_optional_string(
        product_name, "product_name", PRODUCT_NAME_MAX_LENGTH
    )
    validate_optional_string(
        jira_project_key,
        "jira_project_key",
        JIRA_PROJECT_KEY_MAX_LENGTH,
    )


def validate_project_scan_target_fields(
    *,
    project_name: Optional[str] = None,
    project_code: Optional[str] = None,
    scan_name: Optional[str] = None,
    scan_code: Optional[str] = None,
    scan_required: bool = True,
) -> None:
    """Validate CLI/MCP-style project and scan identifier lengths."""
    if project_name:
        project_name_limit = _effective_name_limit(
            absolute_max=PROJECT_NAME_MAX_LENGTH,
            safe_max=PROJECT_NAME_SAFE_MAX_LENGTH,
            customer_code=project_code,
        )
        validate_string_length(
            project_name, "project_name", project_name_limit
        )
    validate_optional_string(
        project_code, "project_code", PROJECT_CODE_MAX_LENGTH
    )
    if scan_required:
        if scan_name:
            scan_name_limit = _effective_name_limit(
                absolute_max=SCAN_NAME_MAX_LENGTH,
                safe_max=SCAN_NAME_SAFE_MAX_LENGTH,
                customer_code=scan_code,
            )
            validate_string_length(scan_name, "scan_name", scan_name_limit)
        validate_optional_string(
            scan_code, "scan_code", SCAN_CODE_MAX_LENGTH
        )


def validate_scan_create_data(data: Mapping[str, Any]) -> None:
    """Validate scan create payload before an API call."""
    scan_name = data.get("scan_name")
    if scan_name is None:
        raise ValidationError("scan_name is required")

    scan_code = _optional_str(data.get("scan_code"))
    name_limit = _effective_name_limit(
        absolute_max=SCAN_NAME_MAX_LENGTH,
        safe_max=SCAN_NAME_SAFE_MAX_LENGTH,
        customer_code=scan_code,
    )
    validate_string_length(str(scan_name), "scan_name", name_limit)
    validate_optional_string(scan_code, "scan_code", SCAN_CODE_MAX_LENGTH)
    validate_optional_string(
        _optional_str(data.get("project_code")),
        "project_code",
        PROJECT_CODE_ON_SCAN_MAX_LENGTH,
    )


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
