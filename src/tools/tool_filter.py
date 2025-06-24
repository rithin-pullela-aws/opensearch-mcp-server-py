# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import logging
from .tool_params import baseToolArgs
from .tools import TOOL_REGISTRY
from .utils import is_tool_compatible
from opensearch.helper import get_opensearch_version


def get_tools(mode: str = 'single') -> dict:
    enabled = {}
    for name, info in TOOL_REGISTRY.items():
        # Create a copy of the tool info
        tool_info = info.copy()

        if mode == 'single':
            version = get_opensearch_version()
            logging.info(f'Connected OpenSearch version: {version}')
            # In single mode, we do version filtering and remove baseToolArgs
            if not is_tool_compatible(version, info):
                continue

            # Remove baseToolArgs from schema
            schema = tool_info['input_schema'].copy()
            if 'properties' in schema:
                # Remove baseToolArgs fields
                base_fields = baseToolArgs.model_fields.keys()
                for field in base_fields:
                    schema['properties'].pop(field, None)
            tool_info['input_schema'] = schema

        enabled[name] = tool_info
    return enabled
