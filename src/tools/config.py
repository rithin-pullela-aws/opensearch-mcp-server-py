# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import copy
import logging
import re
import yaml
from typing import Dict, Any, Optional, List, Tuple
from tools.tools import TOOL_REGISTRY as default_tool_registry

# Field aliases mapping: actual field name -> list of accepted aliases
FIELD_ALIASES = {
    'display_name': ['name', 'displayName', 'display_name', 'customName'],
    'description': ['description', 'desc', 'customDescription'],
}

# Constants for field names
DISPLAY_NAME_STRING = 'display_name'
DESCRIPTION_STRING = 'description'

# Regex pattern for tool display name validation
DISPLAY_NAME_PATTERN = r'^[a-zA-Z0-9_-]+$'


def _find_actual_field(field_alias: str) -> Optional[str]:
    """
    Find the actual field name for a given alias.

    :param field_alias: The alias to look up
    :return: The actual field name or None if not found
    """
    for actual_field, aliases in FIELD_ALIASES.items():
        if field_alias in aliases:
            return actual_field
    return None


def _get_all_aliases() -> Tuple[List[str], List[str]]:
    """
    Get all aliases for display name and description fields.

    :return: Tuple of (display_name_aliases, description_aliases)
    """
    all_display_name_aliases = []
    all_description_aliases = []
    for actual_field, aliases in FIELD_ALIASES.items():
        if actual_field == DISPLAY_NAME_STRING:
            all_display_name_aliases.extend(aliases)
        elif actual_field == DESCRIPTION_STRING:
            all_description_aliases.extend(aliases)
    return all_display_name_aliases, all_description_aliases


def is_valid_display_name_pattern(name: str) -> bool:
    """
    Check if a display name follows the required pattern.

    :param name: The name to validate
    :return: True if valid, False otherwise
    """
    return re.match(DISPLAY_NAME_PATTERN, name) is not None


def _load_config_from_file(config_from_file: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """
    Load configurations from YAML file data.

    Creates a dict mapping original tool names to their custom configurations.
    Example: {'ListIndexTool': {'display_name': 'CustomLister', 'description': 'Custom desc'}}

    :param config_from_file: Configuration data from YAML file
    :return: Dictionary of tool names and their custom configurations
    """
    file_configs = {}
    for original_tool_name, custom_config in config_from_file.items():
        if original_tool_name not in file_configs:
            file_configs[original_tool_name] = {}

        # Track which actual fields have been set to detect duplicates
        set_fields = set()

        for config_key, config_value in custom_config.items():
            actual_field = _find_actual_field(config_key)
            if actual_field == DISPLAY_NAME_STRING:
                if DISPLAY_NAME_STRING in set_fields:
                    raise ValueError(
                        f"Duplicate display name field for tool '{original_tool_name}' in config file. "
                        f'Found multiple aliases: {[k for k, v in custom_config.items() if _find_actual_field(k) == DISPLAY_NAME_STRING]}'
                    )
                file_configs[original_tool_name][DISPLAY_NAME_STRING] = config_value
                set_fields.add(DISPLAY_NAME_STRING)
            elif actual_field == DESCRIPTION_STRING:
                if DESCRIPTION_STRING in set_fields:
                    raise ValueError(
                        f"Duplicate description field for tool '{original_tool_name}' in config file. "
                        f'Found multiple aliases: {[k for k, v in custom_config.items() if _find_actual_field(k) == DESCRIPTION_STRING]}'
                    )
                file_configs[original_tool_name][DESCRIPTION_STRING] = config_value
                set_fields.add(DESCRIPTION_STRING)
            else:
                logging.warning(
                    f"Invalid field '{config_key}' for tool '{original_tool_name}' in config file will be ignored. "
                    f'Only display_name and description are supported.'
                )
    return file_configs


def _check_cli_duplicate_field_aliases(cli_tool_overrides: Dict[str, str], display_name_pattern: str, description_pattern: str) -> None:
    """
    Check for duplicate field aliases in CLI arguments and raise ValueError if found.
    
    :param cli_tool_overrides: Command line tool overrides
    :param display_name_pattern: Regex pattern for display name arguments
    :param description_pattern: Regex pattern for description arguments
    :raises ValueError: If duplicate field aliases are found for the same tool
    """
    # Collect all arguments by tool and field type to detect duplicates
    tool_display_name_args = {}  # tool_name -> list of (arg, value)
    tool_description_args = {}   # tool_name -> list of (arg, value)

    for arg, value in cli_tool_overrides.items():
        display_name_match = re.match(display_name_pattern, arg)
        description_match = re.match(description_pattern, arg)

        if display_name_match:
            original_tool_name = display_name_match.group(1)
            if original_tool_name not in tool_display_name_args:
                tool_display_name_args[original_tool_name] = []
            tool_display_name_args[original_tool_name].append((arg, value))
        elif description_match:
            original_tool_name = description_match.group(1)
            if original_tool_name not in tool_description_args:
                tool_description_args[original_tool_name] = []
            tool_description_args[original_tool_name].append((arg, value))
        else:
            logging.warning(
                f"Invalid argument '{arg}' will be ignored. Expected format: tool.<ToolName>.<field>=<value>"
            )

    # Check for duplicate display name fields
    for tool_name, args_list in tool_display_name_args.items():
        if len(args_list) > 1:
            duplicate_args = [arg for arg, value in args_list]
            raise ValueError(
                f"Duplicate display name field for tool '{tool_name}' in CLI arguments. "
                f'Found multiple aliases: {duplicate_args}'
            )

    # Check for duplicate description fields
    for tool_name, args_list in tool_description_args.items():
        if len(args_list) > 1:
            duplicate_args = [arg for arg, value in args_list]
            raise ValueError(
                f"Duplicate description field for tool '{tool_name}' in CLI arguments. "
                f'Found multiple aliases: {duplicate_args}'
            )


def _load_config_from_cli(cli_tool_overrides: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """
    Load configurations from CLI arguments.

    Creates a dict mapping original tool names to their custom configurations.
    Example: {'ListIndexTool': {'display_name': 'CustomLister', 'description': 'Custom desc'}}

    :param cli_tool_overrides: Command line tool overrides
    :return: Dictionary of tool names and their custom configurations
    """
    cli_configs = {}
    if not cli_tool_overrides:
        return cli_configs

    # Generate regex patterns for display name and description aliases (once)
    all_display_name_aliases, all_description_aliases = _get_all_aliases()
    display_name_alias_pattern = '|'.join(re.escape(alias) for alias in all_display_name_aliases)
    description_alias_pattern = '|'.join(re.escape(alias) for alias in all_description_aliases)
    display_name_pattern = rf'tool\.(\w+)\.({display_name_alias_pattern})'
    description_pattern = rf'tool\.(\w+)\.({description_alias_pattern})'

    # Check for duplicate field aliases first
    _check_cli_duplicate_field_aliases(cli_tool_overrides, display_name_pattern, description_pattern)

    # Apply the configurations
    for arg, value in cli_tool_overrides.items():
        display_name_match = re.match(display_name_pattern, arg)
        description_match = re.match(description_pattern, arg)

        if display_name_match:
            # Argument format: tool.ListIndexTool.display_name=MyCustomIndexLister
            original_tool_name = display_name_match.group(1)
            if original_tool_name not in cli_configs:
                cli_configs[original_tool_name] = {}
            cli_configs[original_tool_name][DISPLAY_NAME_STRING] = value

        elif description_match:
            # Argument format: tool.ListIndexTool.description=MyCustomDescription
            original_tool_name = description_match.group(1)
            if original_tool_name not in cli_configs:
                cli_configs[original_tool_name] = {}
            cli_configs[original_tool_name][DESCRIPTION_STRING] = value

    return cli_configs


def _validate_config(config: Dict[str, Dict[str, str]]) -> None:
    """
    Validate the configuration.

    Checks:
    1. All tool names exist in the default registry
    2. No duplicate display names will be created
    3. All display names follow the required pattern

    :param config: The configuration to validate
    """
    # Track available tool names (original names minus configured ones)
    available_tool_names = set(default_tool_registry.keys())

    # Validate that all configured tools exist
    for original_name in config.keys():
        if original_name not in available_tool_names:
            raise ValueError(f"Tool '{original_name}' is not a valid tool name.")
        available_tool_names.remove(original_name)

    # Check for duplicate display names
    for original_name, custom_config in config.items():
        custom_display_name = custom_config.get(DISPLAY_NAME_STRING)
        if custom_display_name:
            if custom_display_name in available_tool_names:
                raise ValueError(
                    f"Display name '{custom_display_name}' conflicts with another tool."
                )
            available_tool_names.add(custom_display_name)

    # Validate display name patterns
    for original_name, custom_config in config.items():
        custom_display_name = custom_config.get(DISPLAY_NAME_STRING)
        if custom_display_name and not is_valid_display_name_pattern(custom_display_name):
            raise ValueError(
                f"Display name '{custom_display_name}' for tool '{original_name}' "
                f"does not follow the required pattern '{DISPLAY_NAME_PATTERN}'."
            )


def _apply_validated_configs(
    custom_registry: Dict[str, Any], configs: Dict[str, Dict[str, str]]
) -> None:
    """
    Apply validated configurations to the registry.

    :param custom_registry: The registry to modify
    :param configs: Dictionary of tool names and their custom configurations
    """
    for original_tool_name, custom_config in configs.items():
        if original_tool_name not in custom_registry:
            continue

        for field_name, field_value in custom_config.items():
            custom_registry[original_tool_name][field_name] = field_value


def apply_custom_tool_config(
    tool_registry: Dict[str, Any],
    config_file_path: str,
    cli_tool_overrides: Dict[str, str],
) -> Dict[str, Any]:
    """
    Apply custom configurations to the tool registry from YAML file and command-line arguments.

    Priority order:
    1. Config file settings (if config file is provided, CLI is completely ignored)
    2. CLI argument settings (only used if no config file is provided)

    :param tool_registry: The original tool registry
    :param config_file_path: Path to the YAML configuration file
    :param cli_tool_overrides: Dictionary of tool overrides from command line
    :return: A new tool registry with custom configurations applied
    """
    custom_registry = copy.deepcopy(tool_registry)

    # Load configuration from file
    config_from_file = {}
    if config_file_path:
        try:
            with open(config_file_path, 'r') as f:
                config = yaml.safe_load(f)
                if config and 'tools' in config:
                    config_from_file = config['tools']
        except Exception as e:
            logging.error(f'Error loading tool config file: {e}')

    # Load configurations from appropriate source
    if config_from_file:
        # Use config file and completely ignore CLI
        file_configs = _load_config_from_file(config_from_file)
        if file_configs:
            _validate_config(file_configs)
            _apply_validated_configs(custom_registry, file_configs)
    else:
        # Use CLI arguments only if no config file
        cli_configs = _load_config_from_cli(cli_tool_overrides)
        if cli_configs:
            _validate_config(cli_configs)
            _apply_validated_configs(custom_registry, cli_configs)

    # Update the default registry
    default_tool_registry.update(custom_registry)

    return custom_registry
