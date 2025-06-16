# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

from opensearchpy import OpenSearch, RequestsHttpConnection
from urllib.parse import urlparse
from requests_aws4auth import AWS4Auth
import os
import boto3
import logging
from typing import Dict, Any
from .tool_params import baseToolArgs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
OPENSEARCH_SERVICE = "es"
OPENSEARCH_SERVERLESS_SERVICE = "aoss"

# This file should expose the OpenSearch py client
def initialize_client(args: baseToolArgs) -> OpenSearch:
    """
    Initialize and return an OpenSearch client with appropriate authentication.
    
    The function attempts to authenticate in the following order:
    1. Basic authentication using OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD
    2. AWS IAM authentication using boto3 credentials
       - Uses 'aoss' service name if OPENSEARCH_SERVERLESS=true
       - Uses 'es' service name otherwise

    Args:
        args (baseToolArgs): The arguments object containing authentication and connection details
    
    Returns:
        OpenSearch: An initialized OpenSearch client instance.
    
    Raises:
        ValueError: If opensearch_url is empty or invalid
        RuntimeError: If no valid authentication method is available
    """
    args.opensearch_url = args.opensearch_url or os.getenv("OPENSEARCH_URL", "")
    if not args.opensearch_url:
        raise ValueError("OpenSearch URL must be provided either via command line argument or OPENSEARCH_URL environment variable")

    
    args.opensearch_username = args.opensearch_username or os.getenv("OPENSEARCH_USERNAME", "")
    args.opensearch_password = args.opensearch_password or os.getenv("OPENSEARCH_PASSWORD", "")
    
    # Check if using OpenSearch Serverless
    is_serverless = os.getenv("AWS_OPENSEARCH_SERVERLESS", "").lower() == "true"
    service_name = OPENSEARCH_SERVERLESS_SERVICE if is_serverless else OPENSEARCH_SERVICE
    
    if is_serverless:
        logger.info("Using OpenSearch Serverless with service name: aoss")

    # Parse the OpenSearch domain URL
    parsed_url = urlparse(args.opensearch_url)

    # Common client configuration
    client_kwargs: Dict[str, Any] = {
        'hosts': [args.opensearch_url],
        'use_ssl': (parsed_url.scheme == "https"),
        'verify_certs': True,
        'connection_class': RequestsHttpConnection,
    }

    session = boto3.Session()
    if not args.aws_region:
        args.aws_region = os.getenv("AWS_REGION") or session.region_name

    # 1. Try IAM auth
    if args.iam_arn:
        try:
            if not args.aws_region:
                raise RuntimeError("AWS region not found, please specify region using `aws configure`")
            
            sts_client = boto3.client('sts', region_name=args.aws_region)
            assumed_role = sts_client.assume_role(
                RoleArn=args.iam_arn,
                RoleSessionName='OpenSearchClientSession'
            )
            credentials = assumed_role['Credentials']
            
            aws_auth = AWS4Auth(
                credentials['AccessKeyId'],
                credentials['SecretAccessKey'],
                args.aws_region,
                service_name,
                session_token=credentials['SessionToken']
            )
            client_kwargs['http_auth'] = aws_auth
            logger.info(f"Successfully assumed IAM role: {args.iam_arn}")
            return OpenSearch(**client_kwargs)
        except Exception as e:
            logger.error(f"Failed to assume IAM role {args.iam_arn}: {str(e)}")

    # 1. Try basic auth
    if args.opensearch_username and args.opensearch_password:
        client_kwargs['http_auth'] = (args.opensearch_username, args.opensearch_password)
        return OpenSearch(**client_kwargs)

    # 2. Try to get credentials (boto3 session)
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        if not args.aws_region:
            raise RuntimeError("AWS region not found, please specify region using `aws configure`")
        if credentials:
            aws_auth = AWS4Auth(
                refreshable_credentials=credentials,
                service=service_name,
                region=args.aws_region,
            )
            client_kwargs['http_auth'] = aws_auth
            return OpenSearch(**client_kwargs)
    except (boto3.exceptions.Boto3Error, Exception) as e:
        logger.error(f"Failed to get AWS credentials: {str(e)}")

    raise RuntimeError("No valid AWS or basic authentication provided for OpenSearch")
