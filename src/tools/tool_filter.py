# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import logging
from .tool_params import baseToolArgs
from .tools import TOOL_REGISTRY
from .utils import is_tool_compatible
from opensearch.helper import get_opensearch_version
import os


def get_tools(mode: str = 'single') -> dict:
    """Filter and return available tools based on server mode and OpenSearch version.

    In 'multi' mode, returns all tools without filtering. In 'single' mode, filters tools
    based on OpenSearch version compatibility and removes base tool arguments from schemas.

    Args:
        mode (str): Server mode - 'single' for version-filtered tools, 'multi' for all tools

    Returns:
        dict: Dictionary of enabled tools with their configurations
    """
    # In multi mode, return all tools without any filtering
    if mode == 'multi':
        return TOOL_REGISTRY

    enabled = {}

    # Get OpenSearch version for compatibility checking (only in single mode)
    version = get_opensearch_version(baseToolArgs())
    logging.info(f'Connected OpenSearch version: {version}')

    # Check if running in OpenSearch Serverless mode
    is_serverless = os.getenv('AWS_OPENSEARCH_SERVERLESS', '').lower() == 'true'

    for name, info in TOOL_REGISTRY.items():
        # Create a copy to avoid modifying the original tool info
        tool_info = info.copy()

        # Skip version compatibility check for serverless mode
        # In serverless, all tools are available regardless of version
        if not is_serverless and not is_tool_compatible(version, info):
            continue

        # Remove baseToolArgs fields from input schema for single mode
        # This simplifies the schema since base args are handled internally
        schema = tool_info['input_schema'].copy()
        if 'properties' in schema:
            base_fields = baseToolArgs.model_fields.keys()
            for field in base_fields:
                schema['properties'].pop(field, None)
        tool_info['input_schema'] = schema

        enabled[name] = tool_info

    return enabled
