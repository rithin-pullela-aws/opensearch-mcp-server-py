# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
from unittest.mock import Mock, patch


class TestTools:
    def setup_method(self):
        """Setup that runs before each test method."""
        # Create a properly configured mock client
        self.mock_client = Mock()

        # Configure mock client methods to return proper data structures
        # These will be overridden in individual tests as needed
        self.mock_client.cat.indices.return_value = []
        self.mock_client.indices.get_mapping.return_value = {}
        self.mock_client.search.return_value = {}
        self.mock_client.cat.shards.return_value = []
        self.mock_client.info.return_value = {'version': {'number': '2.11.1'}}

        # Patch initialize_client to always return our mock client
        self.init_client_patcher = patch(
            'opensearch.client.initialize_client', return_value=self.mock_client
        )
        self.init_client_patcher.start()

        # Import after patching
        from tools.tools import (
            TOOL_REGISTRY,
            GetIndexMappingArgs,
            GetShardsArgs,
            ListIndicesArgs,
            SearchIndexArgs,
            get_index_mapping_tool,
            get_shards_tool,
            list_indices_tool,
            search_index_tool,
        )

        self.ListIndicesArgs = ListIndicesArgs
        self.GetIndexMappingArgs = GetIndexMappingArgs
        self.SearchIndexArgs = SearchIndexArgs
        self.GetShardsArgs = GetShardsArgs
        self.TOOL_REGISTRY = TOOL_REGISTRY
        self._list_indices_tool = list_indices_tool
        self._get_index_mapping_tool = get_index_mapping_tool
        self._search_index_tool = search_index_tool
        self._get_shards_tool = get_shards_tool

        self.test_url = 'https://test-opensearch-domain.com'

    def teardown_method(self):
        self.init_client_patcher.stop()

    @pytest.mark.asyncio
    async def test_list_indices_tool(self):
        """Test list_indices_tool successful."""
        # Setup
        self.mock_client.cat.indices.return_value = [{'index': 'index1'}, {'index': 'index2'}]
        # Execute
        result = await self._list_indices_tool(self.ListIndicesArgs(opensearch_url=self.test_url))
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'index1\nindex2' in result[0]['text']
        self.mock_client.cat.indices.assert_called_once_with(format='json')

    @pytest.mark.asyncio
    async def test_list_indices_tool_error(self):
        """Test list_indices_tool exception handling."""
        # Setup
        self.mock_client.cat.indices.side_effect = Exception('Test error')
        # Execute
        result = await self._list_indices_tool(self.ListIndicesArgs(opensearch_url=self.test_url))
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Error listing indices: Test error' in result[0]['text']
        self.mock_client.cat.indices.assert_called_once_with(format='json')

    @pytest.mark.asyncio
    async def test_get_index_mapping_tool(self):
        """Test get_index_mapping_tool successful."""
        # Setup
        mock_mapping = {'mappings': {'properties': {'field1': {'type': 'text'}}}}
        self.mock_client.indices.get_mapping.return_value = mock_mapping
        # Execute
        args = self.GetIndexMappingArgs(opensearch_url=self.test_url, index='test-index')
        result = await self._get_index_mapping_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Mapping for test-index' in result[0]['text']
        assert json.loads(result[0]['text'].split('\n', 1)[1]) == mock_mapping
        self.mock_client.indices.get_mapping.assert_called_once_with(index='test-index')

    @pytest.mark.asyncio
    async def test_get_index_mapping_tool_error(self):
        """Test get_index_mapping_tool exception handling."""
        # Setup
        self.mock_client.indices.get_mapping.side_effect = Exception('Test error')
        # Execute
        args = self.GetIndexMappingArgs(opensearch_url=self.test_url, index='test-index')
        result = await self._get_index_mapping_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Error getting mapping: Test error' in result[0]['text']
        self.mock_client.indices.get_mapping.assert_called_once_with(index='test-index')

    @pytest.mark.asyncio
    async def test_search_index_tool(self):
        """Test search_index_tool successful."""
        # Setup
        mock_results = {'hits': {'total': {'value': 1}, 'hits': [{'_source': {'field': 'value'}}]}}
        self.mock_client.search.return_value = mock_results
        # Execute
        args = self.SearchIndexArgs(
            opensearch_url=self.test_url, index='test-index', query={'match_all': {}}
        )
        result = await self._search_index_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Search results from test-index' in result[0]['text']
        assert json.loads(result[0]['text'].split('\n', 1)[1]) == mock_results
        self.mock_client.search.assert_called_once_with(index='test-index', body={'match_all': {}})

    @pytest.mark.asyncio
    async def test_search_index_tool_error(self):
        """Test search_index_tool exception handling."""
        # Setup
        self.mock_client.search.side_effect = Exception('Test error')
        # Execute
        args = self.SearchIndexArgs(
            opensearch_url=self.test_url, index='test-index', query={'match_all': {}}
        )
        result = await self._search_index_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Error searching index: Test error' in result[0]['text']
        self.mock_client.search.assert_called_once_with(index='test-index', body={'match_all': {}})

    @pytest.mark.asyncio
    async def test_get_shards_tool(self):
        """Test get_shards_tool successful."""
        # Setup
        mock_shards = [
            {
                'index': 'test-index',
                'shard': '0',
                'prirep': 'p',
                'state': 'STARTED',
                'docs': '1000',
                'store': '1mb',
                'ip': '127.0.0.1',
                'node': 'node1',
            }
        ]
        self.mock_client.cat.shards.return_value = mock_shards
        # Execute
        args = self.GetShardsArgs(opensearch_url=self.test_url, index='test-index')
        result = await self._get_shards_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'index | shard | prirep | state | docs | store | ip | node' in result[0]['text']
        assert 'test-index | 0 | p | STARTED | 1000 | 1mb | 127.0.0.1 | node1' in result[0]['text']
        self.mock_client.cat.shards.assert_called_once_with(index='test-index', format='json')

    @pytest.mark.asyncio
    async def test_get_shards_tool_error(self):
        """Test get_shards_tool exception handling."""
        # Setup
        self.mock_client.cat.shards.side_effect = Exception('Test error')
        # Execute
        args = self.GetShardsArgs(opensearch_url=self.test_url, index='test-index')
        result = await self._get_shards_tool(args)
        # Assert
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert 'Error getting shards information: Test error' in result[0]['text']
        self.mock_client.cat.shards.assert_called_once_with(index='test-index', format='json')

    def test_tool_registry(self):
        assert 'ListIndexTool' in self.TOOL_REGISTRY
        assert 'IndexMappingTool' in self.TOOL_REGISTRY
        assert 'SearchIndexTool' in self.TOOL_REGISTRY
        assert 'GetShardsTool' in self.TOOL_REGISTRY

    def test_input_models(self):
        # Just check that the input models can be instantiated
        self.ListIndicesArgs(opensearch_url=self.test_url)
        self.GetIndexMappingArgs(opensearch_url=self.test_url, index='foo')
        self.SearchIndexArgs(opensearch_url=self.test_url, index='foo', query={})
        self.GetShardsArgs(opensearch_url=self.test_url, index='foo')
