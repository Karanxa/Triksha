"""
API Endpoints Package
"""

import logging as _logging

__all__ = []

try:
    from .dataset import router as dataset_router  # type: ignore
    __all__.append("dataset_router")
except Exception as e:
    _logging.getLogger(__name__).debug("dataset router unavailable: %s", e)

try:
    from .mcp_tool_scan import router as mcp_tool_scan_router  # type: ignore
    __all__.append("mcp_tool_scan_router")
except Exception as e:
    _logging.getLogger(__name__).debug("mcp_tool_scan router unavailable: %s", e)
