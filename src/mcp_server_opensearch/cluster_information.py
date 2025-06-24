# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import yaml
from pydantic import BaseModel
from typing import Dict, Optional


class ClusterInfo(BaseModel):
    """Model representing OpenSearch cluster configuration."""

    opensearch_url: str
    iam_arn: Optional[str] = None
    aws_region: Optional[str] = None
    opensearch_username: Optional[str] = None
    opensearch_password: Optional[str] = None
    profile: Optional[str] = None


# Global dictionary to store cluster information
# Key: string name (cluster identifier)
# Value: ClusterInfo object containing cluster configuration
cluster_registry: Dict[str, ClusterInfo] = {}


def add_cluster(name: str, cluster_info: ClusterInfo) -> None:
    """Add a cluster configuration to the global registry.

    Args:
        name: String identifier for the cluster
        cluster_info: ClusterInfo object containing cluster configuration
    """
    cluster_registry[name] = cluster_info


def get_cluster(name: str) -> Optional[ClusterInfo]:
    """Retrieve cluster configuration by name.

    Args:
        name: String identifier for the cluster

    Returns:
        ClusterInfo: Cluster configuration or None if not found
    """
    return cluster_registry.get(name)


def list_clusters() -> list[str]:
    """Get list of all registered cluster names.

    Returns:
        list[str]: List of cluster names
    """
    return list(cluster_registry.keys())


def get_all_clusters() -> Dict[str, ClusterInfo]:
    """Get all cluster configurations.

    Returns:
        Dict[str, ClusterInfo]: Dictionary of cluster configurations
    """
    return cluster_registry


def load_clusters_from_yaml(file_path: str) -> None:
    """Load cluster configurations from a YAML file and populate the global registry.

    Args:
        file_path: Path to the YAML configuration file

    Raises:
        FileNotFoundError: If the YAML file doesn't exist
        yaml.YAMLError: If the YAML file is malformed
    """
    if not file_path:
        return
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'YAML file not found: {file_path}')

    result = {'loaded_clusters': [], 'errors': [], 'total_clusters': 0}

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)

        # Validate version
        version = config.get('version', '1.0')
        if version != '1.0':
            result['errors'].append(f'Unsupported version: {version}. Expected: 1.0')
            return result

        # Process clusters
        clusters = config.get('clusters', {})
        result['total_clusters'] = len(clusters)
        logging.info(f'total cluster found in config file: {result["total_clusters"]}')

        for cluster_name, cluster_config in clusters.items():
            try:
                # Validate required fields
                if 'opensearch_url' not in cluster_config:
                    result['errors'].append(f'Missing opensearch_url for cluster: {cluster_name}')
                    continue
                cluster_info = ClusterInfo(
                    opensearch_url=cluster_config['opensearch_url'],
                    iam_arn=cluster_config.get('iam_arn', None),
                    aws_region=cluster_config.get('aws_region', None),
                    opensearch_username=cluster_config.get('opensearch_username', None),
                    opensearch_password=cluster_config.get('opensearch_password', None),
                    profile=cluster_config.get('profile', None),
                )
                # Check if possible to connect to the cluster
                is_connected, error_message = check_cluster_connection(cluster_info)
                if not is_connected:
                    result['errors'].append(
                        f"Error connecting to cluster '{cluster_name}': {error_message}"
                    )
                    continue
                else:
                    # Add cluster to registry
                    add_cluster(name=cluster_name, cluster_info=cluster_info)

                result['loaded_clusters'].append(cluster_name)

            except Exception as e:
                result['errors'].append(f"Error processing cluster '{cluster_name}': {str(e)}")

        result['loaded_clusters'] = list(cluster_registry.keys())
        if result['errors']:
            logging.error(f'Loading errors: {result["errors"]}')

        logging.info(f'Loaded clusters: {result["loaded_clusters"]}')
        return

    except yaml.YAMLError as e:
        raise yaml.YAMLError(f'Invalid YAML format in {file_path}: {str(e)}')


def check_cluster_connection(cluster_info: ClusterInfo) -> tuple[bool, str]:
    """Check if the cluster is reachable by attempting to connect.

    Args:
        cluster_info: ClusterInfo object containing cluster configuration

    Returns:
        tuple[bool, str]: (True, "") if connection successful, (False, error_message) otherwise
    """
    try:
        # Lazy import to avoid circular dependency
        from opensearch.client import initialize_client_with_cluster

        client = initialize_client_with_cluster(cluster_info)
        client.info()
        return True, ''
    except Exception as e:
        return False, str(e)
