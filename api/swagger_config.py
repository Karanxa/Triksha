"""
Swagger/OpenAPI Configuration for Triksha API

Provides comprehensive API documentation for:
- Contextual GenAI Red Teaming
- Dataset Poisoning Detection
- MCP Security Scanning
- Inventory Management
"""

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse
from typing import Dict, Any


# Custom OpenAPI schema tags with descriptions
API_TAGS = [
    {
        "name": "S2S Agent Scan",
        "description": (
            "**Service-to-service API for triggering AI agent security scans programmatically.**\n\n"
            "Services call `POST /triksha/agent-scan` with the raw curl they use to talk to their agent. "
            "Triksha parses the curl, runs a full ADK-based security scan (tool discovery + adversarial attacks), "
            "and returns results via polling or SSE.\n\n"
            "**Required:** Place `__PROMPT__` in the curl body where the adversarial prompt should be injected.\n\n"
            "**Flow:** POST → get `scan_id` → poll `GET /triksha/agent-scan/{scan_id}` or stream "
            "`GET /agents/scan/{scan_id}/events`"
        ),
    },
    {
        "name": "Red Teaming",
        "description": "Adversarial security testing for AI models with contextual attack generation"
    },
    {
        "name": "MCP Security",
        "description": "Security scanning for Model Context Protocol (MCP) servers"
    },
    {
        "name": "Datasets",
        "description": "Dataset poisoning detection using ML-based anomaly detection"
    },
    {
        "name": "Inventory",
        "description": "Manage AI models, datasets, and MCP server registry"
    },
]


def get_custom_openapi_schema(app: FastAPI) -> Dict[str, Any]:
    """
    Generate custom OpenAPI schema with comprehensive documentation
    """
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Triksha API",
        version="2.0.0",
        description="Triksha AI Security Platform - Red teaming, MCP security scanning, and dataset poisoning detection.",
        routes=app.routes,
        tags=API_TAGS,
    )
    
    # Add server information
    openapi_schema["servers"] = [
        {"url": "/", "description": "Current Server"},
        {"url": "http://localhost:8000", "description": "Local Development"},
        {"url": "https://your-triksha-host.example.com", "description": "Production"},
    ]
    
    # Add security schemes
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token from authentication service"
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "API Key in format: Bearer <api_key>"
        }
    }
    
    # Apply security globally
    openapi_schema["security"] = [{"BearerAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


def get_swagger_ui_page() -> HTMLResponse:
    """
    Return Swagger UI HTML with Triksha theme
    """
    return HTMLResponse(content=f"""
<!DOCTYPE html>
<html>
<head>
    <title>Triksha API</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
    <style>
        .swagger-ui .topbar {{ background: #2874F0; }}
        .swagger-ui .info .title {{ color: #2874F0; }}
        .swagger-ui .btn.execute {{ background: #2874F0; border-color: #2874F0; }}
        .swagger-ui .btn.authorize {{ background: #2874F0; border-color: #2874F0; color: #fff; }}
        .swagger-ui .opblock.opblock-post .opblock-summary-method {{ background: #2874F0; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            window.ui = SwaggerUIBundle({{
                url: "/swagger/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                docExpansion: "list",
                filter: true,
                tryItOutEnabled: true,
                persistAuthorization: true,
            }});
        }};
    </script>
</body>
</html>
    """)


def setup_swagger_routes(app: FastAPI):
    """
    Setup custom swagger routes at /swagger
    """
    
    @app.get("/swagger", include_in_schema=False)
    async def swagger_ui():
        """Serve custom Swagger UI"""
        return get_swagger_ui_page()
    
    @app.get("/swagger/openapi.json", include_in_schema=False)
    async def swagger_openapi():
        """Return the OpenAPI schema"""
        return get_custom_openapi_schema(app)
    
    # Override the default openapi function
    app.openapi = lambda: get_custom_openapi_schema(app)

