from .tools import TOOL_REGISTRY
from semver import Version
from opensearch.helper import get_opensearch_version
import logging

def is_tool_compatible(current_version: Version, tool_info: dict = {}):
    min_tool_version = Version.parse(
        tool_info.get("min_version", "0.0.0"), optional_minor_and_patch=True
    )
    max_tool_version = Version.parse(
        tool_info.get("max_version", "99.99.99"), optional_minor_and_patch=True
    )
    return min_tool_version <= current_version <= max_tool_version


def get_tools(mode: str = "single") -> dict:
    enabled = {}
    for name, info in TOOL_REGISTRY.items():
        # Create a copy of the tool info
        tool_info = info.copy()
        
        if mode == "single":
            version = get_opensearch_version()
            logging.info(f"Connected OpenSearch version: {version}")
            # In single mode, we do version filtering and remove baseToolArgs
            if not is_tool_compatible(version, info):
                continue
                
            # Remove baseToolArgs from schema
            schema = tool_info["input_schema"].copy()
            if "properties" in schema:
                # Remove baseToolArgs fields
                for field in ["opensearch_url", "iam_arn", "aws_region", 
                            "opensearch_username", "opensearch_password"]:
                    schema["properties"].pop(field, None)
            tool_info["input_schema"] = schema
        
        enabled[name] = tool_info
    return enabled
