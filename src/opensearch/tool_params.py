# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

from pydantic import BaseModel, Field
from typing import Any

class baseToolArgs(BaseModel):
    """
    Base class for all tool arguments that contains common OpenSearch connection parameters.
    """
    opensearch_url: str = Field(
        default="",
        description="The URL of the OpenSearch cluster endpoint (e.g., https://search-domain.region.es.amazonaws.com)"
    )
    iam_arn: str = Field(
        default="",
        description="The ARN of the IAM role to assume for authentication. If not provided, will try basic auth or default AWS credentials"
    )
    aws_region: str = Field(
        default="",
        description="The AWS region where the OpenSearch domain is located (e.g., us-west-2)"
    )
    opensearch_username: str = Field(
        default="",
        description="Username for basic authentication. If not provided, will try IAM authentication"
    )
    opensearch_password: str = Field(
        default="",
        description="Password for basic authentication. If not provided, will try IAM authentication"
    )

class ListIndicesArgs(baseToolArgs):
    pass

class GetIndexMappingArgs(baseToolArgs):
    index: str = Field(
        description="The name of the index to get mapping information for"
    )

class SearchIndexArgs(baseToolArgs):
    index: str = Field(
        description="The name of the index to search in"
    )
    query: Any = Field(
        description="The search query in OpenSearch query DSL format"
    )

class GetShardsArgs(baseToolArgs):
    index: str = Field(
        description="The name of the index to get shard information for"
    ) 