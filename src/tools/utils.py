# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

from semver import Version


def is_tool_compatible(current_version: Version, tool_info: dict = {}):
    """Check if a tool is compatible with the current OpenSearch version.

    Args:
        current_version (Version): The current OpenSearch version
        tool_info (dict): Tool information containing min_version and max_version

    Returns:
        bool: True if the tool is compatible, False otherwise
    """
    min_tool_version = Version.parse(
        tool_info.get('min_version', '0.0.0'), optional_minor_and_patch=True
    )
    max_tool_version = Version.parse(
        tool_info.get('max_version', '99.99.99'), optional_minor_and_patch=True
    )
    return min_tool_version <= current_version <= max_tool_version
