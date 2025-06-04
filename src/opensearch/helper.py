# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

from .client import initialize_client
import json
from typing import Any

# List all the helper functions, these functions perform a single rest call to opensearch
# these functions will be used in tools folder to eventually write more complex tools
def list_indices(opensearch_url: str) -> json:
    client = initialize_client(opensearch_url)
    response = client.cat.indices(format="json")
    return response

def get_index_mapping(opensearch_url: str, index: str) -> json:
    client = initialize_client(opensearch_url)
    response = client.indices.get_mapping(index=index)
    return response

def search_index(opensearch_url: str, index: str, query: Any) -> json:
    client = initialize_client(opensearch_url)
    response = client.search(index=index, body=query)
    return response

def get_shards(opensearch_url: str, index: str) -> json:
    client = initialize_client(opensearch_url)
    response = client.cat.shards(index=index, format="json")
    return response