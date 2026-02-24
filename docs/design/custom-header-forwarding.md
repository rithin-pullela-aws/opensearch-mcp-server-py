# Design: Configurable Custom Header Forwarding

**Status**: Proposed
**Authors**: Rithin Pullela
**Created**: 2026-02-21

---

## 1. Problem Statement

The OpenSearch MCP server has no mechanism for users to send custom HTTP headers to the OpenSearch cluster (or whatever sits at the `opensearch_url` -- could be a proxy, API gateway, load balancer, etc.). opensearch-py is just an HTTP client; it doesn't care what's on the other end as long as it responds with the expected JSON shape.

This blocks real-world use cases:

- **OpenSearch Security Plugin**: `securitytenant` header for tenant isolation.
- **Proxies / API gateways**: `X-Forwarded-For`, `X-Api-Key`, custom auth tokens.
- **Observability**: `X-Request-ID`, `traceparent` for distributed tracing through the chain.
- **Audit logging**: OpenSearch can log request headers; custom headers enable request correlation.

## 2. Goals

1. Allow **static headers** (fixed key-value pairs) sent on every request to OpenSearch.
2. Allow **forwarded headers** (extracted per-request from incoming MCP HTTP requests) sent to OpenSearch, with regex pattern support.
3. Work in both **single mode** and **multi mode** as first-class citizens.
4. Support **YAML config**, **environment variables**, and **CLI arguments**.
5. Full **backward compatibility**. `opensearch_header_auth` is untouched -- it's an auth concern, not a header forwarding concern.

## 3. Non-Goals

- Modifying the existing `opensearch_header_auth` / `_get_auth_from_headers()` mechanism.
- Forwarding all incoming headers by default.

---

## 4. How opensearch-py Handles Headers

```
AsyncOpenSearch(headers={"X-Custom": "value"}, ...)
    └─> Transport.__init__()
        └─> Connection.__init__()
            └─> self.headers = {"X-Custom": "value"}
```

On every request to OpenSearch:

```python
# connection.py:110-112
req_headers = self.headers.copy()      # picks up custom headers
if headers:
    req_headers.update(headers)        # merges per-request headers

# connection.py:136
response = await self.session.request(
    method, url,
    headers=req_headers,               # sent as HTTP headers to opensearch_url
)
```

**Injection point**: `client_kwargs['headers']` passed to `AsyncOpenSearch()`. These become `self.headers` on every `BufferedAsyncHttpConnection` instance and are sent on every HTTP request.

This is orthogonal to `client_kwargs['http_auth']` which handles authentication (SigV4 signing, basic auth). They don't conflict.

---

## 5. Design

### 5.1 Two Concepts

| Concept | What | Transport | Config |
|---------|------|-----------|--------|
| **Static** | Fixed key-value pairs sent on every OpenSearch request | Both stdio and HTTP | `headers.static` |
| **Forward** | Header names/regex patterns extracted per-request from incoming MCP HTTP request | HTTP only (no-op on stdio) | `headers.forward` |

### 5.2 Configuration by Mode

#### Single Mode

**Env vars (simplest, no YAML):**

```bash
export OPENSEARCH_URL="https://opensearch.example.com"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="password"

# Static headers: comma-separated key=value pairs
export OPENSEARCH_HEADERS_STATIC="securitytenant=admin_tenant,X-Api-Key=abc123"

# Forward headers: comma-separated names or regex patterns
export OPENSEARCH_HEADERS_FORWARD="X-Request-ID,^X-Forwarded-.*"

opensearch-mcp-server-py --transport stream
```

**YAML config (recommended for non-trivial setups):**

Single mode already supports `--config` for tool customization. The top-level `headers:` works here too:

```yaml
headers:
  static:
    securitytenant: "admin_tenant"
    X-Api-Key: "abc123"
  forward:
    - "X-Request-ID"
    - "^X-Forwarded-.*"

tools:
  SearchIndexTool:
    display_name: "Search"
```

```bash
export OPENSEARCH_URL="https://opensearch.example.com"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="password"
opensearch-mcp-server-py --transport stream --config config.yml
```

**CLI args:**

```bash
opensearch-mcp-server-py --transport stream \
  --headers-static "securitytenant=admin_tenant,X-Api-Key=abc123" \
  --headers-forward "X-Request-ID,^X-Forwarded-.*"
```

#### Multi Mode

Supports **global** `headers:` (shared defaults) and **per-cluster** overrides:

```yaml
# Global: applied to all clusters
headers:
  forward:
    - "X-Request-ID"
    - "X-Correlation-ID"

clusters:
  # Inherits global headers
  cluster-a:
    opensearch_url: "https://cluster-a.example.com"
    opensearch_username: "admin"
    opensearch_password: "password"

  # Overrides global headers entirely
  cluster-b:
    opensearch_url: "https://cluster-b.example.com"
    opensearch_username: "admin"
    opensearch_password: "password"
    headers:
      static:
        securitytenant: "special_tenant"
      forward:
        - "X-Request-ID"
        - "^X-Custom-.*"
```

Per-cluster `headers:` **fully replaces** global (no deep merge).

### 5.3 Config Source Precedence

Follows the existing tool filtering pattern (`tool_filter.py:340-348`):

- **YAML config provided**: env vars and CLI args for headers are ignored (warning logged if both set).
- **No YAML config**: env vars and CLI args are used. CLI overrides env var.
- **Within YAML (multi mode)**: per-cluster `headers` fully replaces global `headers`. No `headers` key = inherit global.

### 5.4 Regex Behavior in `forward`

| Entry | Behavior |
|-------|----------|
| Starts with `^` | Compiled as Python regex, matched case-insensitively against all incoming header names |
| Otherwise | Exact match, case-insensitive |

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `X-Request-ID` | `X-Request-ID`, `x-request-id` | `X-Request-Trace` |
| `^X-Forwarded-.*` | `X-Forwarded-For`, `X-Forwarded-Proto` | `My-X-Forwarded` |
| `^X-(Request\|Correlation)-ID$` | `X-Request-ID`, `X-Correlation-ID` | `X-Request-IDx` |

Invalid regex: logged as warning, skipped (server doesn't crash).

### 5.5 Security

**Blocked headers** (never forwarded, even if matched):
```
host, content-length, content-type, transfer-encoding,
connection, user-agent, accept-encoding
```

**Catch-all rejected**: `.*` or `^.*$` raises a config error.

**Auth-overlap warning**: if a forward pattern matches `authorization`, `aws-access-key-id`, etc., a warning is logged.

**Logging**: header names at INFO, values only at DEBUG.

### 5.6 Transport Behavior

| Feature | stdio (default) | stream (HTTP) |
|---------|:-:|:-:|
| `headers.static` | Works | Works |
| `headers.forward` | No-op | Works |

If `headers.forward` is configured with stdio transport, a warning is logged at startup.

### 5.7 Relationship to `opensearch_header_auth`

These are separate concerns:

| Feature | What it does | Config location |
|---------|-------------|-----------------|
| `opensearch_header_auth` | Extracts auth credentials from incoming MCP request → configures `http_auth` (SigV4 / basic auth) | `opensearch_header_auth: true` on cluster, or `OPENSEARCH_HEADER_AUTH=true` env var |
| `headers.static` / `headers.forward` | Sends raw HTTP headers to OpenSearch | `headers:` section |

They're orthogonal. A typical deployment combining both:

```yaml
clusters:
  my-cluster:
    opensearch_url: "https://opensearch.internal:9200"
    opensearch_header_auth: true          # Auth from incoming MCP request
    headers:
      static:
        securitytenant: "admin_tenant"    # Always send to OpenSearch
      forward:
        - "X-Request-ID"                 # Forward from MCP request to OpenSearch
```

---

## 6. Implementation Details

### 6.1 Files Changed

| File | Change |
|------|--------|
| `src/mcp_server_opensearch/clusters_information.py` | Add `HeadersConfig` model, add `headers` field to `ClusterInfo`, update YAML loading |
| `src/opensearch/client.py` | Add `_parse_headers_static_env()`, `_collect_custom_headers()`, update `_create_opensearch_client()`, `_initialize_client_single_mode()`, `_initialize_client_multi_mode()` |
| `src/mcp_server_opensearch/__init__.py` | Add `--headers-static` and `--headers-forward` CLI args |
| `example_config.yml` | Add example cluster with headers config |
| `tests/opensearch/test_client.py` | Add `TestCustomHeaders` test class |
| `tests/mcp_server_opensearch/test_clusters_information.py` | Add tests for new fields |

### 6.2 Data Model Changes

**File: `src/mcp_server_opensearch/clusters_information.py`**

```python
from typing import Dict, List, Optional
from pydantic import BaseModel

class HeadersConfig(BaseModel):
    """Configuration for custom headers sent to OpenSearch."""
    static: Optional[Dict[str, str]] = None
    forward: Optional[List[str]] = None

class ClusterInfo(BaseModel):
    """Model representing OpenSearch cluster configuration."""
    opensearch_url: str
    iam_arn: Optional[str] = None
    aws_region: Optional[str] = None
    opensearch_username: Optional[str] = None
    opensearch_password: Optional[str] = None
    profile: Optional[str] = None
    is_serverless: Optional[bool] = None
    timeout: Optional[int] = None
    opensearch_no_auth: Optional[bool] = None
    ssl_verify: Optional[bool] = None
    opensearch_header_auth: Optional[bool] = None    # unchanged, BWC
    max_response_size: Optional[int] = None
    headers: Optional[HeadersConfig] = None           # NEW
```

Update `load_clusters_from_yaml()` to:
1. Parse the global `headers:` section from config root.
2. For each cluster, parse per-cluster `headers:` if present, otherwise inherit global.

```python
async def load_clusters_from_yaml(file_path: str) -> None:
    # ... existing loading code ...
    config = yaml.safe_load(file)

    # NEW: Parse global headers
    global_headers_raw = config.get('headers', None)
    global_headers = None
    if global_headers_raw and isinstance(global_headers_raw, dict):
        global_headers = HeadersConfig(
            static=global_headers_raw.get('static', None),
            forward=global_headers_raw.get('forward', None),
        )

    clusters = config.get('clusters', {})
    for cluster_name, cluster_config in clusters.items():
        # ... existing field parsing ...

        # NEW: Parse per-cluster headers, fallback to global
        cluster_headers_raw = cluster_config.get('headers', None)
        if cluster_headers_raw and isinstance(cluster_headers_raw, dict):
            cluster_headers = HeadersConfig(
                static=cluster_headers_raw.get('static', None),
                forward=cluster_headers_raw.get('forward', None),
            )
        else:
            cluster_headers = global_headers  # inherit global

        cluster_info = ClusterInfo(
            # ... existing fields ...
            headers=cluster_headers,
        )
```

### 6.3 New Functions in `client.py`

**Constants:**

```python
import re

# Headers that must never be forwarded (HTTP protocol headers)
BLOCKED_FORWARD_HEADERS = frozenset({
    'host', 'content-length', 'content-type', 'transfer-encoding',
    'connection', 'user-agent', 'accept-encoding',
})

# Auth headers that trigger a warning if forwarded
AUTH_SENSITIVE_HEADERS = frozenset({
    'authorization', 'aws-access-key-id', 'aws-secret-access-key',
    'aws-session-token', 'aws-region', 'aws-service-name',
    'opensearch-url',
})

# Catch-all patterns that are rejected
REJECTED_PATTERNS = frozenset({'.*', '^.*$', '^.*', '.*$'})
```

**`_parse_headers_static_env()`:**

```python
def _parse_headers_static_env(env_value: str) -> Optional[Dict[str, str]]:
    """Parse OPENSEARCH_HEADERS_STATIC env var.

    Format: "Header-Name=value,Another-Header=value"
    Splits on first '=' per entry. Values may contain '='.
    """
    if not env_value:
        return None
    headers = {}
    for entry in env_value.split(','):
        entry = entry.strip()
        if not entry:
            continue
        if '=' not in entry:
            logger.warning(f'Ignoring malformed header entry (no "="): {entry}')
            continue
        key, value = entry.split('=', 1)
        key, value = key.strip(), value.strip()
        if key:
            headers[key] = value
    return headers if headers else None
```

**`_parse_headers_forward_env()`:**

```python
def _parse_headers_forward_env(env_value: str) -> Optional[List[str]]:
    """Parse OPENSEARCH_HEADERS_FORWARD env var.

    Format: "Header-Name,^regex-pattern,Another-Header"
    """
    if not env_value:
        return None
    patterns = [p.strip() for p in env_value.split(',') if p.strip()]
    return patterns if patterns else None
```

**`_validate_forward_patterns()`:**

```python
def _validate_forward_patterns(patterns: List[str]) -> List[str]:
    """Validate forward patterns. Returns list of valid patterns, logs warnings for invalid ones."""
    valid = []
    for pattern in patterns:
        # Reject catch-all patterns
        if pattern in REJECTED_PATTERNS:
            logger.error(f'Rejected catch-all forward pattern: "{pattern}". '
                        f'Forwarding all headers is not allowed.')
            continue

        # Validate regex patterns (start with ^)
        if pattern.startswith('^'):
            try:
                re.compile(pattern)
            except re.error as e:
                logger.warning(f'Invalid regex forward pattern "{pattern}": {e}. Skipping.')
                continue

        # Warn about auth-sensitive patterns
        if not pattern.startswith('^') and pattern.lower() in AUTH_SENSITIVE_HEADERS:
            logger.warning(f'Forward pattern "{pattern}" matches a built-in auth header. '
                          f'This may conflict with opensearch_header_auth.')

        valid.append(pattern)
    return valid
```

**`_collect_custom_headers()`:**

This is the core function. It merges static headers with forwarded headers extracted from the incoming MCP request.

```python
def _collect_custom_headers(
    static_headers: Optional[Dict[str, str]] = None,
    forward_patterns: Optional[List[str]] = None,
) -> Optional[Dict[str, str]]:
    """Collect custom headers to send to OpenSearch.

    Merges static headers with headers forwarded from the incoming MCP
    HTTP request. Forwarded headers take precedence over static headers
    when the same header name appears in both.

    Args:
        static_headers: Fixed key-value pairs.
        forward_patterns: Header names or regex patterns to extract
                         from the incoming MCP request.

    Returns:
        Combined headers dict, or None if empty.
    """
    result: Dict[str, str] = {}

    # 1. Add static headers
    if static_headers:
        for key, value in static_headers.items():
            if key.lower() in BLOCKED_FORWARD_HEADERS:
                logger.warning(f'Skipping blocked static header: {key}')
                continue
            result[key] = value

    # 2. Extract forwarded headers from incoming MCP HTTP request
    if forward_patterns:
        incoming_headers = _get_incoming_request_headers()
        if incoming_headers:
            for pattern in forward_patterns:
                if pattern.startswith('^'):
                    # Regex match against all incoming headers
                    compiled = re.compile(pattern, re.IGNORECASE)
                    for header_name, header_value in incoming_headers.items():
                        if compiled.match(header_name):
                            if header_name.lower() not in BLOCKED_FORWARD_HEADERS:
                                result[header_name] = header_value
                            else:
                                logger.debug(f'Blocked forwarding of {header_name}')
                else:
                    # Exact match (case-insensitive)
                    pattern_lower = pattern.lower()
                    if pattern_lower in BLOCKED_FORWARD_HEADERS:
                        logger.debug(f'Blocked forwarding of {pattern}')
                        continue
                    for header_name, header_value in incoming_headers.items():
                        if header_name.lower() == pattern_lower:
                            result[header_name] = header_value
                            break

    if result:
        logger.info(f'Custom headers configured: {list(result.keys())}')
        logger.debug(f'Custom header values: {result}')

    return result if result else None
```

**`_get_incoming_request_headers()`:**

```python
def _get_incoming_request_headers() -> Optional[Dict[str, str]]:
    """Extract all headers from the incoming MCP HTTP request.

    Returns:
        Dict of header name -> value, or None if not available
        (e.g., stdio transport).
    """
    try:
        request_context = request_ctx.get()
        if request_context and hasattr(request_context, 'request'):
            request = request_context.request
            if request and isinstance(request, Request):
                return dict(request.headers)
    except Exception as e:
        logger.debug(f'Could not read headers from request context: {e}')
    return None
```

### 6.4 Modify `_create_opensearch_client()`

**File: `src/opensearch/client.py`**

Add `custom_headers` parameter and inject into `client_kwargs`:

```python
def _create_opensearch_client(
    opensearch_url: str,
    opensearch_username: str = '',
    opensearch_password: str = '',
    opensearch_no_auth: bool = False,
    iam_arn: str = '',
    profile: str = '',
    is_serverless_mode: bool = False,
    opensearch_timeout: Optional[int] = None,
    aws_region: Optional[str] = None,
    ssl_verify: bool = True,
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    max_response_size: Optional[int] = None,
    custom_headers: Optional[Dict[str, str]] = None,  # NEW
) -> AsyncOpenSearch:
```

In the `client_kwargs` construction (after line 450):

```python
    client_kwargs: Dict[str, Any] = {
        'hosts': [opensearch_url],
        'use_ssl': (parsed_url.scheme == 'https'),
        'verify_certs': ssl_verify,
        'connection_class': BufferedAsyncHttpConnection,
        'timeout': timeout,
        'max_response_size': response_size_limit,
    }

    # NEW: Add custom headers
    if custom_headers:
        client_kwargs['headers'] = custom_headers
        logger.info(f'OpenSearch client configured with custom headers: {list(custom_headers.keys())}')
```

### 6.5 Modify `_initialize_client_single_mode()`

**File: `src/opensearch/client.py`**

After the existing env var parsing block (~line 190), before the call to `_create_opensearch_client()`:

```python
    # NEW: Parse headers config
    # Check for YAML config first (via global state), then fall back to env vars
    headers_config = _get_headers_config_single_mode()
    static_headers = headers_config.static if headers_config else None
    forward_patterns = headers_config.forward if headers_config else None

    # Validate forward patterns
    if forward_patterns:
        forward_patterns = _validate_forward_patterns(forward_patterns)

    # Collect custom headers (static + forwarded)
    custom_headers = _collect_custom_headers(
        static_headers=static_headers,
        forward_patterns=forward_patterns,
    )

    # ... existing URL validation ...

    return _create_opensearch_client(
        # ... existing args ...
        max_response_size=max_response_size,
        custom_headers=custom_headers,          # NEW
    )
```

Helper to resolve headers config for single mode:

```python
def _get_headers_config_single_mode() -> Optional[HeadersConfig]:
    """Get headers config for single mode.

    Priority: YAML config > env vars.
    """
    # Try YAML config first
    config_path = get_config_file_path()
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                headers_raw = config.get('headers', None) if config else None
                if headers_raw and isinstance(headers_raw, dict):
                    if os.getenv('OPENSEARCH_HEADERS_STATIC') or os.getenv('OPENSEARCH_HEADERS_FORWARD'):
                        logger.warning('Both YAML config and env vars set for headers. Using YAML config.')
                    return HeadersConfig(
                        static=headers_raw.get('static', None),
                        forward=headers_raw.get('forward', None),
                    )
        except Exception as e:
            logger.debug(f'Could not load headers from config file: {e}')

    # Fall back to env vars
    static = _parse_headers_static_env(os.getenv('OPENSEARCH_HEADERS_STATIC', '').strip())
    forward = _parse_headers_forward_env(os.getenv('OPENSEARCH_HEADERS_FORWARD', '').strip())
    if static or forward:
        return HeadersConfig(static=static, forward=forward)
    return None
```

### 6.6 Modify `_initialize_client_multi_mode()`

**File: `src/opensearch/client.py`**

After extracting existing cluster params (~line 310), before calling `_create_opensearch_client()`:

```python
    # NEW: Get headers config from cluster info
    headers_config = cluster_info.headers
    static_headers = headers_config.static if headers_config else None
    forward_patterns = headers_config.forward if headers_config else None

    if forward_patterns:
        forward_patterns = _validate_forward_patterns(forward_patterns)

    custom_headers = _collect_custom_headers(
        static_headers=static_headers,
        forward_patterns=forward_patterns,
    )

    return _create_opensearch_client(
        # ... existing args ...
        max_response_size=max_response_size,
        custom_headers=custom_headers,          # NEW
    )
```

### 6.7 CLI Arguments

**File: `src/mcp_server_opensearch/__init__.py`**

```python
    parser.add_argument(
        '--headers-static',
        default='',
        help='Static headers to send to OpenSearch (format: "Key1=Val1,Key2=Val2")',
    )
    parser.add_argument(
        '--headers-forward',
        default='',
        help='Header names/patterns to forward from MCP requests to OpenSearch (comma-separated)',
    )
```

After argument parsing:

```python
    # CLI args set env vars (env vars are read by client.py)
    if args.headers_static:
        os.environ['OPENSEARCH_HEADERS_STATIC'] = args.headers_static
    if args.headers_forward:
        os.environ['OPENSEARCH_HEADERS_FORWARD'] = args.headers_forward
```

### 6.8 YAML Config Loading for Global Headers

**File: `src/mcp_server_opensearch/clusters_information.py`**

In `load_clusters_from_yaml()`, parse the global `headers:` section and propagate to clusters that don't define their own:

```python
    # Parse global headers config
    global_headers_raw = config.get('headers', None)
    global_headers = None
    if global_headers_raw and isinstance(global_headers_raw, dict):
        global_headers = HeadersConfig(
            static=global_headers_raw.get('static', None),
            forward=global_headers_raw.get('forward', None),
        )
        logging.info(f'Loaded global headers config: '
                    f'static={list((global_headers.static or {}).keys())}, '
                    f'forward={global_headers.forward or []}')

    clusters = config.get('clusters', {})
    for cluster_name, cluster_config in clusters.items():
        # ... existing field parsing ...

        # Per-cluster headers override global entirely
        cluster_headers_raw = cluster_config.get('headers', None)
        if cluster_headers_raw and isinstance(cluster_headers_raw, dict):
            headers = HeadersConfig(
                static=cluster_headers_raw.get('static', None),
                forward=cluster_headers_raw.get('forward', None),
            )
        else:
            headers = global_headers  # inherit global

        cluster_info = ClusterInfo(
            # ... existing fields ...
            headers=headers,
        )
```

---

## 7. Example Configurations

### Static headers only (stdio, simplest)

```bash
export OPENSEARCH_URL="https://opensearch.example.com"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="password"
export OPENSEARCH_HEADERS_STATIC="securitytenant=admin_tenant"
opensearch-mcp-server-py
```

### Header auth + forwarding (streaming)

```bash
export OPENSEARCH_URL="https://opensearch.example.com"
export OPENSEARCH_HEADER_AUTH=true
export OPENSEARCH_HEADERS_FORWARD="X-Request-ID,^X-Forwarded-.*"
opensearch-mcp-server-py --transport stream
```

### Single mode YAML

```yaml
headers:
  static:
    securitytenant: "admin_tenant"
  forward:
    - "X-Request-ID"
    - "^X-Forwarded-.*"
```

### Multi mode with global + per-cluster

```yaml
headers:
  forward:
    - "X-Request-ID"
    - "X-Correlation-ID"

clusters:
  cluster-a:
    opensearch_url: "https://cluster-a.example.com"
    opensearch_username: "admin"
    opensearch_password: "password"
    # inherits global headers

  cluster-b:
    opensearch_url: "https://cluster-b.example.com"
    opensearch_header_auth: true
    headers:
      static:
        securitytenant: "special_tenant"
      forward:
        - "X-Request-ID"
        - "^X-Custom-.*"
```

### API gateway with custom auth

```yaml
clusters:
  gateway-cluster:
    opensearch_url: "https://api-gateway.example.com/opensearch"
    opensearch_no_auth: true
    headers:
      static:
        X-Api-Key: "your-api-key"
        X-Gateway-Auth: "bearer-token"
```

---

## 8. Testing Plan

### Unit Tests (`tests/opensearch/test_client.py`)

| Test | What it verifies |
|------|-----------------|
| `test_static_headers_in_client_kwargs` | `headers.static` → `client_kwargs['headers']` |
| `test_forward_headers_from_request_context` | Mock `request_ctx`, verify matched headers appear in `client_kwargs['headers']` |
| `test_forward_regex_matching` | `^X-Forwarded-.*` matches `X-Forwarded-For` but not `My-X-Forwarded` |
| `test_forward_exact_case_insensitive` | `X-Request-ID` matches `x-request-id` |
| `test_forward_absent_headers_skipped` | Listed header not in request → silently skipped |
| `test_forward_stdio_noop` | `request_ctx.get()` returns None → forward produces nothing |
| `test_blocked_headers_not_forwarded` | `host`, `content-length`, etc. are skipped |
| `test_catchall_pattern_rejected` | `.*` and `^.*$` raise config error |
| `test_invalid_regex_skipped` | `^[invalid` logs warning, skipped |
| `test_auth_sensitive_warning` | `authorization` in forward triggers warning |
| `test_forward_precedence_over_static` | Same header in both → forward wins |
| `test_no_headers_default_behavior` | No config → `client_kwargs` has no `headers` key (BWC) |
| `test_parse_headers_static_env` | `K1=V1,K2=V2` parsing, edge cases (`=` in values, spaces) |
| `test_parse_headers_forward_env` | `H1,^regex,H2` parsing |
| `test_multi_mode_headers_from_cluster_info` | `ClusterInfo.headers` flows through to `client_kwargs` |
| `test_global_headers_inherited` | Cluster without `headers:` gets global |
| `test_per_cluster_headers_override_global` | Cluster with `headers:` replaces global entirely |

### Model Tests (`tests/mcp_server_opensearch/test_clusters_information.py`)

| Test | What it verifies |
|------|-----------------|
| `test_cluster_info_with_headers` | `HeadersConfig` accepted by `ClusterInfo` |
| `test_cluster_info_without_headers` | `headers` defaults to None (BWC) |
| `test_load_yaml_with_global_headers` | Global `headers:` parsed and inherited |
| `test_load_yaml_per_cluster_override` | Per-cluster `headers:` replaces global |

---

## 9. Design Decisions

1. **`opensearch_header_auth` stays separate.** It's an auth concern (configures `http_auth`), not a header forwarding concern (configures `headers`). No unnecessary BWC shims.

2. **Config file vs env var precedence.** YAML wins, env vars ignored when YAML present. Matches existing tool filtering pattern.

3. **Global headers section.** Top-level `headers:` in YAML serves as single mode config AND multi mode global defaults. Per-cluster fully replaces global (no merge).

4. **Single mode is first-class.** Supports env vars, CLI args, and YAML equally. No mode is an afterthought.

5. **Transport-aware warnings.** `headers.forward` with stdio logs a warning at startup instead of silently doing nothing.

6. **Regex opt-in via `^` prefix.** Simple heuristic: starts with `^` = regex, otherwise exact match. No ambiguity.

7. **Blocked headers.** Protocol-sensitive headers (`host`, `content-length`, etc.) are never forwarded regardless of config. Safety net.
