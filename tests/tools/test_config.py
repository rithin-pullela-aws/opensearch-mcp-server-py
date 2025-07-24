# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import copy
import os
import yaml
from tools.config import apply_custom_tool_config

MOCK_TOOL_REGISTRY = {
    'ListIndexTool': {
        'display_name': 'ListIndexTool',
        'description': 'Original description for ListIndexTool',
        'other_field': 'some_value',
    },
    'SearchIndexTool': {
        'display_name': 'SearchIndexTool',
        'description': 'Original description for SearchIndexTool',
    },
}


def test_apply_config_from_yaml_file():
    """Test that tool names and descriptions are updated from a YAML file."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'YAML_Custom_Name',
                'description': 'YAML custom description.',
            },
            'SearchIndexTool': {'display_name': 'YAML_Searcher'},
        }
    }
    config_path = 'test_temp_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    assert custom_registry['ListIndexTool']['display_name'] == 'YAML_Custom_Name'
    assert custom_registry['ListIndexTool']['description'] == 'YAML custom description.'
    assert custom_registry['SearchIndexTool']['display_name'] == 'YAML_Searcher'
    # Ensure other fields are untouched
    assert custom_registry['ListIndexTool']['other_field'] == 'some_value'
    # Ensure original is untouched
    assert registry['ListIndexTool']['display_name'] == 'ListIndexTool'

    os.remove(config_path)


def test_apply_config_from_cli_args():
    """Test that tool names and descriptions are updated from CLI arguments."""
    cli_overrides = {
        'tool.ListIndexTool.displayName': 'CLI_Custom_Name',
        'tool.SearchIndexTool.description': 'CLI custom description.',
    }
    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, '', cli_overrides)

    assert custom_registry['ListIndexTool']['display_name'] == 'CLI_Custom_Name'
    assert custom_registry['SearchIndexTool']['description'] == 'CLI custom description.'


def test_cli_overrides_yaml():
    """Test that config file takes priority over CLI arguments when both are provided."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'YAML_Custom_Name',
                'description': 'YAML description.',
            }
        }
    }
    config_path = 'test_temp_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    cli_overrides = {
        'tool.ListIndexTool.name': 'CLI_Final_Name',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, cli_overrides)

    # Config file should take priority over CLI
    assert custom_registry['ListIndexTool']['display_name'] == 'YAML_Custom_Name'
    assert custom_registry['ListIndexTool']['description'] == 'YAML description.'

    os.remove(config_path)


def test_cli_name_alias():
    """Test that 'name' alias works for 'display_name' in CLI arguments."""
    cli_overrides = {'tool.ListIndexTool.name': 'CLI_Name_Alias'}
    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, '', cli_overrides)

    assert custom_registry['ListIndexTool']['display_name'] == 'CLI_Name_Alias'


def test_yaml_field_aliases():
    """Test that various field aliases work correctly in YAML configuration."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'name': 'YAML_Name_Alias',  # Should map to display_name
                'desc': 'YAML Desc Alias',  # Should map to description
            },
            'SearchIndexTool': {
                'displayName': 'YAML_DisplayName_Alias',  # Should map to display_name
                'description': 'Regular Description',  # Direct mapping
            },
        }
    }
    config_path = 'test_temp_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    assert custom_registry['ListIndexTool']['display_name'] == 'YAML_Name_Alias'
    assert custom_registry['ListIndexTool']['description'] == 'YAML Desc Alias'
    assert custom_registry['SearchIndexTool']['display_name'] == 'YAML_DisplayName_Alias'
    assert custom_registry['SearchIndexTool']['description'] == 'Regular Description'

    os.remove(config_path)


def test_cli_field_aliases():
    """Test that various field aliases work correctly in CLI arguments."""
    cli_overrides = {
        'tool.ListIndexTool.name': 'CLI_Name_Alias',
        'tool.ListIndexTool.desc': 'CLI Desc Alias',
        'tool.SearchIndexTool.displayName': 'CLI_DisplayName_Alias',
        'tool.SearchIndexTool.description': 'CLI Regular Description',
    }
    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, '', cli_overrides)

    assert custom_registry['ListIndexTool']['display_name'] == 'CLI_Name_Alias'
    assert custom_registry['ListIndexTool']['description'] == 'CLI Desc Alias'
    assert custom_registry['SearchIndexTool']['display_name'] == 'CLI_DisplayName_Alias'
    assert custom_registry['SearchIndexTool']['description'] == 'CLI Regular Description'


def test_yaml_unsupported_fields_ignored():
    """Test that unsupported field names are ignored in YAML configuration."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'name': 'Valid_Name',
                'unsupported_field': 'Should be ignored',
                'another_invalid': 'Also ignored',
            },
        }
    }
    config_path = 'test_temp_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    # Valid changes should be applied
    assert custom_registry['ListIndexTool']['display_name'] == 'Valid_Name'

    # Invalid fields should not be added to the registry
    assert 'unsupported_field' not in custom_registry['ListIndexTool']
    assert 'another_invalid' not in custom_registry['ListIndexTool']

    # Other fields should remain unchanged
    assert custom_registry['ListIndexTool']['other_field'] == 'some_value'

    os.remove(config_path)


def test_cli_unsupported_fields_ignored():
    """Test that unsupported field names are ignored in CLI arguments."""
    cli_overrides = {
        'tool.ListIndexTool.name': 'Valid_Name',
        'tool.ListIndexTool.invalid_field': 'Should be ignored by regex',
        'tool.SearchIndexTool.bad_field': 'Also ignored by regex',
        'invalid.format': 'Wrong format entirely',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, '', cli_overrides)

    # Only valid field should be applied
    assert custom_registry['ListIndexTool']['display_name'] == 'Valid_Name'

    # Invalid fields should not be added
    assert 'invalid_field' not in custom_registry['ListIndexTool']
    assert 'bad_field' not in custom_registry['SearchIndexTool']


def test_yaml_unsupported_field_warning(caplog):
    """Test that warnings are logged for unsupported fields in YAML configuration."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'name': 'Valid_Name',
                'invalid_field': 'Should trigger warning',
                'another_bad_field': 'Also triggers warning',
            },
        }
    }
    config_path = 'test_temp_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    # Valid field should be applied
    assert custom_registry['ListIndexTool']['display_name'] == 'Valid_Name'

    # Check that warnings were logged
    assert len(caplog.records) == 2
    warning_messages = [record.message for record in caplog.records]

    assert any("Invalid field 'invalid_field'" in msg for msg in warning_messages)
    assert any("Invalid field 'another_bad_field'" in msg for msg in warning_messages)

    os.remove(config_path)


def test_cli_unsupported_field_ignored():
    """Test that CLI arguments with unsupported fields are ignored by regex pattern."""
    cli_overrides = {
        'tool.ListIndexTool.name': 'Valid_Name',
        'tool.ListIndexTool.invalid_field': 'Should be ignored by regex',
        'tool.SearchIndexTool.bad_field': 'Also ignored by regex',
        'invalid.format': 'Wrong format entirely',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, '', cli_overrides)

    # Only valid field should be applied
    assert custom_registry['ListIndexTool']['display_name'] == 'Valid_Name'

    # Invalid fields should not be added
    assert 'invalid_field' not in custom_registry['ListIndexTool']
    assert 'bad_field' not in custom_registry['SearchIndexTool']


def test_field_aliases_structure():
    """Test that the FIELD_ALIASES structure and utility functions work correctly."""
    from tools.config import FIELD_ALIASES, _find_actual_field, _get_all_aliases

    # Test the structure
    assert 'display_name' in FIELD_ALIASES
    assert 'description' in FIELD_ALIASES
    assert isinstance(FIELD_ALIASES['display_name'], list)
    assert isinstance(FIELD_ALIASES['description'], list)

    # Test _find_actual_field function
    assert _find_actual_field('name') == 'display_name'
    assert _find_actual_field('displayName') == 'display_name'
    assert _find_actual_field('display_name') == 'display_name'
    assert _find_actual_field('customName') == 'display_name'
    assert _find_actual_field('description') == 'description'
    assert _find_actual_field('desc') == 'description'
    assert _find_actual_field('customDescription') == 'description'
    assert _find_actual_field('invalid_field') is None

    # Test _get_all_aliases function
    display_name_aliases, description_aliases = _get_all_aliases()
    expected_display_aliases = ['name', 'displayName', 'display_name', 'customName']
    expected_description_aliases = ['description', 'desc', 'customDescription']

    for alias in expected_display_aliases:
        assert alias in display_name_aliases
    for alias in expected_description_aliases:
        assert alias in description_aliases


def test_load_config_from_file():
    """Test the _load_config_from_file function directly."""
    from tools.config import _load_config_from_file

    config_data = {
        'tool1': {
            'name': 'Tool_One',
            'description': 'First tool',
        },
        'tool2': {
            'displayName': 'Tool_Two',
        },
    }

    configs = _load_config_from_file(config_data)

    # Should return dictionary mapping tool names to their configs
    assert len(configs) == 2
    assert 'tool1' in configs
    assert 'tool2' in configs
    assert configs['tool1']['display_name'] == 'Tool_One'
    assert configs['tool1']['description'] == 'First tool'
    assert configs['tool2']['display_name'] == 'Tool_Two'


def test_load_config_from_cli():
    """Test the _load_config_from_cli function directly."""
    from tools.config import _load_config_from_cli

    cli_overrides = {
        'tool.tool1.name': 'CLI_Tool_One',
        'tool.tool2.description': 'CLI Tool Two Description',
        'invalid.format': 'Should be ignored',
        'tool.tool3.invalid_field': 'Should be ignored by regex',
    }

    configs = _load_config_from_cli(cli_overrides)

    # Should return dictionary mapping tool names to their configs
    assert len(configs) == 2
    assert 'tool1' in configs
    assert 'tool2' in configs
    assert configs['tool1']['display_name'] == 'CLI_Tool_One'
    assert configs['tool2']['description'] == 'CLI Tool Two Description'


def test_apply_validated_configs():
    """Test the _apply_validated_configs function directly."""
    from tools.config import _apply_validated_configs

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    configs = {
        'ListIndexTool': {
            'display_name': 'New_Name',
            'description': 'New Description',
        },
        'NonExistentTool': {
            'display_name': 'Should be ignored',
        },
    }

    _apply_validated_configs(registry, configs)

    # Valid changes should be applied
    assert registry['ListIndexTool']['display_name'] == 'New_Name'
    assert registry['ListIndexTool']['description'] == 'New Description'

    # Non-existent tool should not be added
    assert 'NonExistentTool' not in registry


def test_config_file_priority_over_cli():
    """Test that config file completely overrides CLI arguments when both are provided."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'YAML_Priority_Name',
                'description': 'YAML_Priority_Description',
            }
        }
    }
    config_path = 'test_priority_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    cli_overrides = {
        'tool.ListIndexTool.name': 'CLI_Ignored_Name',
        'tool.ListIndexTool.description': 'CLI_Ignored_Description',
        'tool.SearchIndexTool.display_name': 'CLI_Also_Ignored',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, cli_overrides)

    # Config file should take priority
    assert custom_registry['ListIndexTool']['display_name'] == 'YAML_Priority_Name'
    assert custom_registry['ListIndexTool']['description'] == 'YAML_Priority_Description'

    # CLI arguments should be completely ignored
    assert custom_registry['SearchIndexTool']['display_name'] == 'SearchIndexTool'

    os.remove(config_path)


def test_yaml_duplicate_field_aliases_error():
    """Test that duplicate field aliases in YAML configuration raise an error."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'name': 'First Alias',
                'displayName': 'Second Alias',
                'customName': 'Third Alias',
            }
        }
    }
    config_path = 'test_duplicate_aliases.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, config_path, {})
        assert False, 'Expected ValueError for duplicate field aliases'
    except ValueError as e:
        error_msg = str(e)
        assert 'Duplicate display name field' in error_msg
        assert 'Found multiple aliases' in error_msg
        assert 'name' in error_msg
        assert 'displayName' in error_msg
        assert 'customName' in error_msg

    os.remove(config_path)


def test_cli_duplicate_field_aliases_error():
    """Test that duplicate field aliases in CLI arguments raise an error."""
    cli_overrides = {
        'tool.ListIndexTool.name': 'First CLI Alias',
        'tool.ListIndexTool.displayName': 'Second CLI Alias',
        'tool.ListIndexTool.customName': 'Third CLI Alias',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, '', cli_overrides)
        assert False, 'Expected ValueError for duplicate CLI field aliases'
    except ValueError as e:
        error_msg = str(e)
        assert 'Duplicate display name field' in error_msg
        assert 'CLI arguments' in error_msg
        assert 'tool.ListIndexTool.name' in error_msg
        assert 'tool.ListIndexTool.displayName' in error_msg
        assert 'tool.ListIndexTool.customName' in error_msg


def test_display_name_pattern_validation():
    """Test that display names must follow the required pattern."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'Valid_Name_123',
                'description': 'Valid description',
            },
            'SearchIndexTool': {
                'display_name': 'Invalid_Name!',  # Contains space and exclamation
            },
        }
    }
    config_path = 'test_pattern_validation.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, config_path, {})
        assert False, 'Expected ValueError for invalid display name pattern'
    except ValueError as e:
        error_msg = str(e)
        assert 'does not follow the required pattern' in error_msg
        assert 'Invalid_Name!' in error_msg

    os.remove(config_path)


def test_duplicate_display_name_detection():
    """Test that duplicate display names across different tools raise an error."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'Shared_Name',
            },
            'SearchIndexTool': {
                'display_name': 'Shared_Name',  # Same as ListIndexTool
            },
        }
    }
    config_path = 'test_duplicate_display_names.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, config_path, {})
        assert False, 'Expected ValueError for duplicate display names'
    except ValueError as e:
        error_msg = str(e)
        assert 'conflicts with another tool' in error_msg
        assert 'Shared_Name' in error_msg

    os.remove(config_path)


def test_empty_config_file():
    """Test that empty config files are handled gracefully."""
    config_content = {}
    config_path = 'test_empty_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    # No tools should be renamed
    assert custom_registry['ListIndexTool']['display_name'] == 'ListIndexTool'
    assert custom_registry['SearchIndexTool']['display_name'] == 'SearchIndexTool'

    os.remove(config_path)


def test_non_existent_tool_validation():
    """Test that references to non-existent tools raise an error."""
    config_content = {
        'tools': {
            'NonExistentTool': {
                'display_name': 'Custom Name',
            }
        }
    }
    config_path = 'test_nonexistent_tool.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, config_path, {})
        assert False, 'Expected ValueError for non-existent tool'
    except ValueError as e:
        error_msg = str(e)
        assert 'is not a valid tool name' in error_msg
        assert 'NonExistentTool' in error_msg

    os.remove(config_path)


def test_cli_non_existent_tool_validation():
    """Test that CLI references to non-existent tools raise an error."""
    cli_overrides = {
        'tool.NonExistentTool.display_name': 'Custom Name',
    }

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)

    try:
        apply_custom_tool_config(registry, '', cli_overrides)
        assert False, 'Expected ValueError for non-existent tool in CLI'
    except ValueError as e:
        error_msg = str(e)
        assert 'is not a valid tool name' in error_msg
        assert 'NonExistentTool' in error_msg


def test_mixed_valid_invalid_configurations():
    """Test that configurations with both valid and invalid fields work correctly."""
    config_content = {
        'tools': {
            'ListIndexTool': {
                'display_name': 'Valid_Name',
                'invalid_field': 'Should be ignored',
                'description': 'Valid description',
                'another_invalid': 'Also ignored',
            },
            'SearchIndexTool': {'display_name': 'Valid_Name_2'},
        }
    }
    config_path = 'test_mixed_config.yml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    registry = copy.deepcopy(MOCK_TOOL_REGISTRY)
    custom_registry = apply_custom_tool_config(registry, config_path, {})

    # Valid configurations should be applied
    assert custom_registry['ListIndexTool']['display_name'] == 'Valid_Name'
    assert custom_registry['ListIndexTool']['description'] == 'Valid description'
    assert custom_registry['SearchIndexTool']['display_name'] == 'Valid_Name_2'

    # Invalid fields should not be added
    assert 'invalid_field' not in custom_registry['ListIndexTool']
    assert 'another_invalid' not in custom_registry['ListIndexTool']

    os.remove(config_path)
