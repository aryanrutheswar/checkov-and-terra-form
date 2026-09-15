from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from backend.config import get_security_config
from backend.scanner import (
    execute_checkov_scan,
    get_latest_results,
    get_system_health
)

app = FastAPI(
    title="CyberSentinel IaC Security Gate API",
    description="Real-time Terraform and Checkov AST Static Security Scanner & Gate Enforcement API",
    version="3.3.11"
)

# Enable CORS for local React/Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: Optional[str] = Field(
        default="terraform/vulnerable",
        description="Target Terraform directory (terraform/vulnerable or terraform/remediated)"
    )
    custom_code: Optional[str] = Field(
        default=None,
        description="Optional raw Terraform HCL code snippet to scan directly"
    )


@app.get("/api/health")
def health_endpoint() -> Dict[str, Any]:
    """Returns real operational status of all platform components."""
    try:
        return get_system_health()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check error: {str(e)}"
        )


@app.get("/api/config")
def config_endpoint() -> Dict[str, Any]:
    """Returns current security gate configuration thresholds."""
    try:
        return get_security_config()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read security configuration: {str(e)}"
        )


@app.post("/api/scan")
def scan_endpoint(payload: ScanRequest = ScanRequest()) -> Dict[str, Any]:
    """
    Executes a real Checkov AST static analysis scan against the configured Terraform directory
    or against a custom raw HCL code snippet if provided.
    Enforces security gate thresholds and returns normalized findings.
    """
    target = payload.target or "terraform/vulnerable"
    try:
        results = execute_checkov_scan(
            target=target,
            custom_code=payload.custom_code.strip() if payload.custom_code and payload.custom_code.strip() else None
        )
        return results
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except FileNotFoundError as fe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(fe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution error: {str(e)}"
        )


@app.get("/api/results")
def results_endpoint() -> Dict[str, Any]:
    """Returns the most recent scan result or loads a baseline scan."""
    try:
        return get_latest_results()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan results: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
