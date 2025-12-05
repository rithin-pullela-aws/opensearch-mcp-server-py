# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Pytest configuration file for test discovery and path setup."""

import sys
from pathlib import Path

# Add the src directory to sys.path to ensure tests use the local development version
# This is important when a different version of the package is installed in site-packages
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

