"""
Dataset Management API Endpoints

Mirrors CLI dataset functionality including download, format, view, export, and delete operations.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File, Header, Form
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime
import os
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import json
import io
import tempfile
import requests
import time

try:
    from services.dataset_service import DatasetService
except Exception:
    DatasetService = None  # Optional service; endpoints must guard usage
try:
    from models.dataset_models import (  # type: ignore
        DatasetDownloadRequest, DatasetFormatRequest, DatasetViewRequest,
        DatasetExportRequest, DatasetDeleteRequest, DatasetResponse,
        DatasetListResponse, DatasetFormatResponse
    )
except Exception:
    # Fallback lightweight models so the router can load even if models package is absent
    class DatasetDownloadRequest(BaseModel):
        dataset_id: str
        subset: Optional[str] = None
        format: Optional[str] = None

    class DatasetFormatRequest(BaseModel):
        input_dataset_id: str
        format_type: str
        output_format: Optional[str] = None
        options: Optional[Dict[str, Any]] = None

    class DatasetViewRequest(BaseModel):
        dataset_id: str

    class DatasetExportRequest(BaseModel):
        export_format: str
        output_path: Optional[str] = None
        options: Optional[Dict[str, Any]] = None

    class DatasetDeleteRequest(BaseModel):
        dataset_id: str

    class DatasetResponse(BaseModel):
        task_id: Optional[str] = None
        status: str
        message: Optional[str] = None
        dataset_id: Optional[str] = None
        data: Optional[Dict[str, Any]] = None

    class DatasetListResponse(BaseModel):
        datasets: List[Dict[str, Any]]
        total: int
        limit: int
        offset: int

    class DatasetFormatResponse(BaseModel):
        task_id: Optional[str] = None
        status: str
        message: Optional[str] = None
        input_dataset_id: Optional[str] = None

from llm_client import get_improved_prompts_batch
from utils.adversarial_generator import AdversarialPromptGenerator

router = APIRouter(prefix="/dataset", tags=["Datasets"])

# Initialize service (optional)
dataset_service = DatasetService() if DatasetService else None

def _ensure_service_available():
    if dataset_service is None:
        raise HTTPException(status_code=501, detail="DatasetService is not available in this build")

# ----------------------------------------------
# Prompt-generation-only dataset creation models
# ----------------------------------------------

class GenerateDatasetRequest(BaseModel):
    use_case: str = Field(..., description="High-level use case or context from the user")
    prompt_count: int = Field(ge=1, le=500, description="Number of prompts to generate")
    system_prompt: Optional[str] = Field(None, description="Optional system prompt of target model")
    additional_details: Optional[str] = Field(None, description="Any extra details for context")
    augment: bool = Field(True, description="Whether to run augmentation to improve prompts")
    save: bool = Field(True, description="Whether to persist dataset to disk")
    dataset_name: Optional[str] = Field(None, description="Custom name for the dataset")
    export_format: str = Field("json", pattern="^(json|csv)$", description="Storage format")

class GeneratedDatasetResponse(BaseModel):
    dataset_id: Optional[str] = None
    name: Optional[str] = None
    status: str
    count: int
    path: Optional[str] = None
    prompts: List[Dict[str, Any]]
    context: Dict[str, Any]

class PoisoningAnalysisResponse(BaseModel):
    is_poisoned: bool
    security_score: int  # 0-100, where 100 is completely safe
    total_entries: int
    suspicious_entries: int
    analysis_details: Dict[str, Any]
    suspicious_entries_details: Optional[List[Dict[str, Any]]] = None
    semantic_analysis: Optional[Dict[str, Any]] = None  # LLM-based semantic analysis results

@router.get("/", response_model=DatasetListResponse)
async def list_datasets(
    limit: int = 100,
    offset: int = 0,
    dataset_type: Optional[str] = None,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """List all available datasets with optional filtering"""
    try:
        _ensure_service_available()
        datasets = await dataset_service.list_datasets(
            limit=limit, 
            offset=offset, 
            dataset_type=dataset_type
        )
        return DatasetListResponse(
            datasets=datasets,
            total=len(datasets),
            limit=limit,
            offset=offset
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list datasets: {str(e)}")

@router.post("/download", response_model=DatasetResponse)
async def download_dataset(
    request: DatasetDownloadRequest,
    background_tasks: BackgroundTasks,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Download a dataset from HuggingFace or other sources"""
    try:
        _ensure_service_available()
        # Start download in background
        task_id = str(uuid.uuid4())
        background_tasks.add_task(
            dataset_service.download_dataset,
            request.dataset_id,
            request.subset,
            request.format,
            task_id
        )
        
        return DatasetResponse(
            task_id=task_id,
            status="downloading",
            message=f"Dataset {request.dataset_id} download started",
            dataset_id=request.dataset_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start download: {str(e)}")

@router.post("/format", response_model=DatasetFormatResponse)
async def format_dataset(
    request: DatasetFormatRequest,
    background_tasks: BackgroundTasks,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Format a dataset for specific use cases"""
    try:
        _ensure_service_available()
        task_id = str(uuid.uuid4())
        background_tasks.add_task(
            dataset_service.format_dataset,
            request.input_dataset_id,
            request.format_type,
            request.output_format,
            request.options,
            task_id
        )
        
        return DatasetFormatResponse(
            task_id=task_id,
            status="formatting",
            message=f"Dataset formatting started",
            input_dataset_id=request.input_dataset_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start formatting: {str(e)}")

# IMPORTANT: Specific routes MUST come before parameterized routes like /{dataset_id}
# to avoid route matching conflicts. Keep /analyses and /analysis/{analysis_id} here.

@router.get("/analyses")
async def list_dataset_analyses(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    scope: Optional[str] = None,  # "mine" | "others" | None/"all"
    x_proxy_user: str = Header(None, alias="x-proxy-user")
):
    """List dataset analyses with optional filtering.

    scope: 'mine' (only the calling user's), 'others' (everyone else's),
    default no ownership filter.
    """
    # Import db from main module
    import sys
    from user_utils import extract_username_from_identifier

    main_module = sys.modules.get('__main__') or sys.modules.get('main')
    db = getattr(main_module, 'db', None)

    if db is None:
        from db_factory import get_database
        db = get_database()  # PostgreSQL or SQLite

    # Normalize user_id to extract username from email if needed
    raw_user_id = x_proxy_user or "anonymous"
    user_id = extract_username_from_identifier(raw_user_id).lower()
    scope_filter = (scope or "all").lower()

    try:
        # List analyses (all users can see all analyses, similar to scans)
        analyses = db.list_dataset_analyses(
            user_id=None,  # Show all analyses
            status=status,
            limit=limit * 2 if scope_filter in ("mine", "others") else limit,
            offset=0 if scope_filter in ("mine", "others") else offset,
        )

        # Apply scope filter + add ownership flag and progress for running analyses
        filtered_analyses = []
        for analysis in analyses:
            analysis["can_view_details"] = True  # All users can view for now
            # Normalize both sides for comparison to handle email vs username
            analysis_owner = extract_username_from_identifier(analysis.get("created_by", "")).lower()
            analysis["is_owner"] = analysis_owner == user_id

            # Ownership scope filter (mine / others)
            if scope_filter == "mine" and analysis_owner != user_id:
                continue
            if scope_filter == "others" and analysis_owner == user_id:
                continue

            # Add progress if currently running
            try:
                running_dataset_analyses = getattr(main_module, 'running_dataset_analyses', {})
                if analysis["analysis_id"] in running_dataset_analyses:
                    analysis["progress"] = running_dataset_analyses[analysis["analysis_id"]].get("progress", 0)
            except Exception:
                pass

            filtered_analyses.append(analysis)

        analyses = filtered_analyses[:limit]
        
        return {
            "status": "ok",
            "analyses": analyses,
            "total": len(analyses)
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to list analyses: {str(e)}",
            "analyses": []
        }

@router.get("/analysis/{analysis_id}")
async def get_dataset_analysis(
    analysis_id: str,
    x_proxy_user: str = Header(None, alias="x-proxy-user")
):
    """Get detailed dataset analysis results by ID"""
    # Import db from main module
    import sys
    main_module = sys.modules.get('__main__') or sys.modules.get('main')
    db = getattr(main_module, 'db', None)
    
    if db is None:
        from db_factory import get_database
        db = get_database()  # PostgreSQL or SQLite
    
    user_id = x_proxy_user or "anonymous"
    
    try:
        analysis = db.get_dataset_analysis(analysis_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return {
            "status": "ok",
            "analysis": analysis
        }
        
    except HTTPException:
        raise
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get analysis: {str(e)}",
            "analysis": None
        }

@router.get("/{dataset_id}", response_model=DatasetResponse)
async def view_dataset(
    dataset_id: str,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """View detailed information about a specific dataset"""
    try:
        _ensure_service_available()
        dataset_info = await dataset_service.get_dataset_info(dataset_id)
        if not dataset_info:
            raise HTTPException(status_code=404, detail="Dataset not found")
        
        return DatasetResponse(
            dataset_id=dataset_id,
            status="available",
            data=dataset_info
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dataset: {str(e)}")

@router.post("/{dataset_id}/export", response_model=DatasetResponse)
async def export_dataset(
    dataset_id: str,
    request: DatasetExportRequest,
    background_tasks: BackgroundTasks,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Export a dataset in specified format"""
    try:
        _ensure_service_available()
        task_id = str(uuid.uuid4())
        background_tasks.add_task(
            dataset_service.export_dataset,
            dataset_id,
            request.export_format,
            request.output_path,
            request.options,
            task_id
        )
        
        return DatasetResponse(
            task_id=task_id,
            status="exporting",
            message=f"Dataset export started",
            dataset_id=dataset_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start export: {str(e)}")

@router.delete("/{dataset_id}", response_model=DatasetResponse)
async def delete_dataset(
    dataset_id: str,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Delete a dataset"""
    try:
        _ensure_service_available()
        success = await dataset_service.delete_dataset(dataset_id)
        if not success:
            raise HTTPException(status_code=404, detail="Dataset not found")
        
        return DatasetResponse(
            dataset_id=dataset_id,
            status="deleted",
            message=f"Dataset {dataset_id} deleted successfully"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete dataset: {str(e)}")

@router.get("/{dataset_id}/status")
async def get_dataset_status(
    dataset_id: str,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Get the current status of a dataset operation"""
    try:
        _ensure_service_available()
        status = await dataset_service.get_dataset_status(dataset_id)
        return {"dataset_id": dataset_id, "status": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@router.post("/{dataset_id}/validate")
async def validate_dataset(
    dataset_id: str,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Validate a dataset for integrity and format compliance"""
    try:
        _ensure_service_available()
        validation_result = await dataset_service.validate_dataset(dataset_id)
        return {
            "dataset_id": dataset_id,
            "validation_result": validation_result,
            "is_valid": validation_result.get("is_valid", False)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate dataset: {str(e)}")


@router.post("/generate", response_model=GeneratedDatasetResponse)
async def generate_dataset(
    request: GenerateDatasetRequest,
    auth_ctx: Dict[str, Any] = Depends(lambda: {"token": "dummy", "claims": {}})
):
    """Generate a dataset of prompts (optionally augmented) without running scans.

    - Uses AdversarialPromptGenerator to create base prompts.
    - Optionally includes Garak techniques for enhanced adversarial testing.
    - Optionally augments them via the LLM client (batch API).
    - Optionally saves the dataset to data/datasets/generated/ in JSON or CSV.
    """
    try:
        # Check if Garak enhancement is requested (backward compatibility)
        use_garak = getattr(request, 'use_garak', False)
        
        if use_garak:
            # Use enhanced generator with Garak integration
            from utils.garak_enhanced_generator import GarakEnhancedGenerator
            generator = GarakEnhancedGenerator()
            
            # Prepare target context for augmentation
            target_context = {
                "use_case": request.use_case,
                "system_prompt": request.system_prompt or "",
                "additional_details": request.additional_details or "",
            }
            
            # Generate enhanced prompts
            base_prompts = await generator.generate_enhanced_prompts(
                count=request.prompt_count,
                use_garak=True,
                use_augmentation=False,  # We'll handle augmentation separately
                target_context=target_context if request.augment else None
            )
        else:
            # Use traditional generator (backward compatibility)
            target_context = {
                "use_case": request.use_case,
                "system_prompt": request.system_prompt or "",
                "additional_details": request.additional_details or "",
            }
            base_prompts = await AdversarialPromptGenerator.generate_adversarial_prompts(
                count=request.prompt_count,
                target_model_context=target_context
            )

        # 2) Optional augmentation
        final_prompts: List[Dict[str, Any]] = []
        if request.augment:
            # Prepare batch payload for augmentation
            prompt_payload = [
                {
                    "original_prompt": p["prompt"],
                    "technique": p.get("technique", "adversarial"),
                    "base_goal": p.get("type", "adversarial"),
                }
                for p in base_prompts
            ]

            target_ctx = {
                "use_case": request.use_case,
                "system_prompt": request.system_prompt or "",
                "additional_details": request.additional_details or "",
            }

            improved = await get_improved_prompts_batch(
                prompt_data=prompt_payload,
                target_model_context=target_ctx,
                verbose=False,
            )

            # Merge back maintaining metadata - no fallback
            for i, p in enumerate(base_prompts):
                if i < len(improved) and improved[i]:
                    final_prompts.append({
                        **p,
                        "prompt": improved[i],
                        "augmented": True,
                    })
                else:
                    raise Exception(f"Augmentation failed for prompt {i+1}: no improved prompt available")
        else:
            # No augmentation, pass through
            for p in base_prompts:
                final_prompts.append({**p, "augmented": False})

        # 3) Optional save
        dataset_id = None
        output_path = None
        name = request.dataset_name or f"generated_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        context = {
            "use_case": request.use_case,
            "system_prompt": request.system_prompt,
            "additional_details": request.additional_details,
            "augment": request.augment,
        }

        if request.save:
            dataset_id = str(uuid.uuid4())
            base_dir = Path("data/datasets/generated").resolve()
            base_dir.mkdir(parents=True, exist_ok=True)
            # Strip any path components from the dataset name to prevent traversal
            import re as _re
            safe_name = _re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:64]
            if request.export_format == "csv":
                candidate = (base_dir / f"{safe_name}_{dataset_id}.csv").resolve()
                if not str(candidate).startswith(str(base_dir)):
                    raise HTTPException(status_code=400, detail="Invalid dataset name")
                output_path = str(candidate)
                AdversarialPromptGenerator.export_to_csv(final_prompts, output_path)
            else:
                candidate = (base_dir / f"{safe_name}_{dataset_id}.json").resolve()
                if not str(candidate).startswith(str(base_dir)):
                    raise HTTPException(status_code=400, detail="Invalid dataset name")
                output_path = str(candidate)
                # Wrap in metadata similar to JSON exporter but include context/name
                from json import dump
                with open(output_path, "w", encoding="utf-8") as f:
                    dump({
                        "id": dataset_id,
                        "name": name,
                        "created_at": datetime.utcnow().isoformat(),
                        "count": len(final_prompts),
                        "context": context,
                        "prompts": final_prompts,
                    }, f, indent=2)

        return GeneratedDatasetResponse(
            dataset_id=dataset_id,
            name=name,
            status="generated" if not request.save else "saved",
            count=len(final_prompts),
            path=output_path,
            prompts=final_prompts,
            context=context,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate dataset: {str(e)}")


def _perform_semantic_analysis(texts: List[str], suspicious_indices: List[int]) -> Dict[str, Any]:
    """
    Perform semantic analysis using LLM to identify data poisoning patterns
    
    Args:
        texts: List of all text entries from the dataset
        suspicious_indices: Indices of entries flagged by Isolation Forest
        
    Returns:
        Dictionary containing semantic analysis results
    """
    try:
        # Import the LLM client (same as scan augmentation)
        from llm_client import APILLMClient
        from rich.console import Console

        console = Console()
        llm_client_inst = APILLMClient(console=console)
        
        # Prepare suspicious entries for analysis (limit to 8 for API efficiency)
        suspicious_texts = [texts[i] for i in suspicious_indices[:8]]
        
        # Create specialized prompt data for dataset poisoning detection
        prompt_data = [{
            "original_prompt": f"""Analyze these {len(suspicious_texts)} text entries flagged by Isolation Forest for potential dataset poisoning:

Dataset Context:
- Total entries: {len(texts)}
- Suspicious entries detected: {len(suspicious_indices)}
- Analysis method: Hybrid (Isolation Forest + Semantic Analysis)

Suspicious entries to analyze:
{chr(10).join([f"Entry {i+1}: {text[:400] + '...' if len(text) > 400 else text}" for i, text in enumerate(suspicious_texts)])}

Analyze for:
1. Data poisoning patterns (backdoor injection, label flipping, adversarial examples)
2. Semantic coherence and outliers
3. Common attack signatures
4. False positive likelihood

Provide analysis in JSON format:
{{
    "poisoning_type": "detected type or 'none'",
    "confidence_score": 85,
    "patterns_detected": ["pattern1", "pattern2"],
    "risk_assessment": "low/medium/high",
    "recommended_actions": ["action1", "action2"],
    "semantic_coherence": "coherence assessment",
    "false_positive_likelihood": 25
}}""",
            "technique": "semantic_analysis",
            "base_goal": "dataset_security"
        }]
        
        # Use dataset poisoning specific context
        target_model_context = {
            "system_prompt": """You are an expert cybersecurity analyst specializing in machine learning dataset security and poisoning detection. Your role is to identify malicious patterns, backdoors, and anomalies in training datasets that could compromise model integrity.

Key responsibilities:
- Detect data poisoning attacks (backdoor injection, label manipulation, adversarial examples)
- Assess semantic coherence and identify outliers
- Provide actionable security recommendations
- Distinguish between genuine anomalies and false positives

Focus on practical, evidence-based analysis with specific threat indicators.""",
            "use_case": "Dataset poisoning detection and security analysis for machine learning training data",
            "additional_details": f"Analyzing {len(suspicious_texts)} entries flagged by statistical analysis (Isolation Forest) from a dataset of {len(texts)} total entries. Provide structured JSON analysis with confidence scores and actionable recommendations."
        }
        
        # Get semantic analysis from LLM
        improved_prompts = llm_client_inst.get_improved_prompts_batch(
            prompt_data=prompt_data,
            target_model_context=target_model_context,
            verbose=True
        )
        
        if improved_prompts and len(improved_prompts) > 0:
            analysis_response = improved_prompts[0]
            
            # Try to parse JSON from the response
            try:
                # Look for JSON in the response
                if "```json" in analysis_response:
                    json_start = analysis_response.find("```json") + 7
                    json_end = analysis_response.find("```", json_start)
                    json_text = analysis_response[json_start:json_end].strip()
                elif "{" in analysis_response and "}" in analysis_response:
                    json_start = analysis_response.find("{")
                    json_end = analysis_response.rfind("}") + 1
                    json_text = analysis_response[json_start:json_end]
                else:
                    json_text = analysis_response
                
                semantic_result = json.loads(json_text)
                
                return {
                    "status": "success",
                    "analysis": semantic_result,
                    "entries_analyzed": len(suspicious_texts),
                    "model_used": "gemini-2.5-flash",
                    "method": "llm_client"
                }
                
            except json.JSONDecodeError:
                # If JSON parsing fails, return structured text analysis
                return {
                    "status": "partial_success",
                    "analysis": {
                        "raw_analysis": analysis_response,
                        "poisoning_type": "analysis_available",
                        "confidence_score": "see_raw_analysis",
                        "patterns_detected": ["Check raw analysis for details"],
                        "risk_assessment": "medium",
                        "recommended_actions": ["Review raw analysis output"],
                        "semantic_coherence": "See detailed analysis above",
                        "false_positive_likelihood": "unknown"
                    },
                    "entries_analyzed": len(suspicious_texts),
                    "model_used": "gemini-2.5-flash",
                    "method": "llm_client",
                    "note": "Structured parsing failed, see raw_analysis"
                }
        else:
            return {
                "status": "error",
                "message": "No response from Gemini analysis",
                "analysis": {
                    "poisoning_type": "analysis_failed",
                    "confidence_score": 0,
                    "patterns_detected": [],
                    "risk_assessment": "unknown",
                    "recommended_actions": ["Retry analysis", "Manual review recommended"],
                    "semantic_coherence": "Analysis could not be completed",
                    "false_positive_likelihood": "unknown"
                }
            }
            
    except ImportError:
        return {
            "status": "error",
            "message": "LLM client not available",
            "analysis": {
                "poisoning_type": "analysis_unavailable",
                "confidence_score": 0,
                "patterns_detected": [],
                "risk_assessment": "unknown",
                "recommended_actions": ["Configure LLM integration"],
                "semantic_coherence": "Semantic analysis disabled",
                "false_positive_likelihood": "unknown"
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Semantic analysis error: {str(e)}",
            "analysis": {
                "poisoning_type": "analysis_error",
                "confidence_score": 0,
                "patterns_detected": [],
                "risk_assessment": "unknown", 
                "recommended_actions": ["Check system logs", "Retry analysis"],
                "semantic_coherence": f"Error: {str(e)[:100]}",
                "false_positive_likelihood": "unknown"
            }
        }


def _parse_dataset_file(file_content: bytes, filename: str) -> List[str]:
    """Parse uploaded file content and extract text data for analysis."""
    try:
        file_extension = Path(filename).suffix.lower()
        
        if file_extension == '.csv':
            # Parse CSV file
            df = pd.read_csv(io.BytesIO(file_content))
            # Try to find text columns (prompt, text, content, message, etc.)
            text_columns = []
            for col in df.columns:
                if any(keyword in col.lower() for keyword in ['prompt', 'text', 'content', 'message', 'input']):
                    text_columns.append(col)
            
            if not text_columns:
                # If no obvious text columns, use all string columns
                text_columns = [col for col in df.columns if df[col].dtype == 'object']
            
            if not text_columns:
                raise ValueError("No text columns found in CSV file")
            
            # Combine all text columns
            texts = []
            for _, row in df.iterrows():
                combined_text = ' '.join(str(row[col]) for col in text_columns if pd.notna(row[col]))
                if combined_text.strip():
                    texts.append(combined_text.strip())
            
            return texts
            
        elif file_extension in ['.json', '.jsonl']:
            content_str = file_content.decode('utf-8')
            
            if file_extension == '.jsonl':
                # Parse JSONL (one JSON object per line)
                texts = []
                for line in content_str.strip().split('\n'):
                    if line.strip():
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict):
                                # Extract text from common fields
                                text = ""
                                for key in ['prompt', 'text', 'content', 'message', 'input']:
                                    if key in obj and obj[key]:
                                        text += str(obj[key]) + " "
                                if text.strip():
                                    texts.append(text.strip())
                            elif isinstance(obj, str):
                                texts.append(obj)
                        except json.JSONDecodeError:
                            continue
                return texts
            else:
                # Parse regular JSON
                data = json.loads(content_str)
                texts = []
                
                if isinstance(data, list):
                    # Array of items
                    for item in data:
                        if isinstance(item, str):
                            texts.append(item)
                        elif isinstance(item, dict):
                            # Extract text from common fields
                            text = ""
                            for key in ['prompt', 'text', 'content', 'message', 'input']:
                                if key in item and item[key]:
                                    text += str(item[key]) + " "
                            if text.strip():
                                texts.append(text.strip())
                                
                elif isinstance(data, dict):
                    # Check if it's a dataset wrapper
                    if 'prompts' in data and isinstance(data['prompts'], list):
                        for item in data['prompts']:
                            if isinstance(item, str):
                                texts.append(item)
                            elif isinstance(item, dict) and 'prompt' in item:
                                texts.append(str(item['prompt']))
                    else:
                        # Single object, extract text fields
                        text = ""
                        for key in ['prompt', 'text', 'content', 'message', 'input']:
                            if key in data and data[key]:
                                text += str(data[key]) + " "
                        if text.strip():
                            texts.append(text.strip())
                
                return texts
                
        elif file_extension in ['.xlsx', '.xls']:
            df = pd.read_excel(io.BytesIO(file_content), engine='openpyxl' if file_extension == '.xlsx' else None)
            text_columns = [col for col in df.columns if any(k in str(col).lower() for k in ['prompt', 'text', 'content', 'message', 'input'])]
            if not text_columns:
                text_columns = [col for col in df.columns if df[col].dtype == 'object']
            if not text_columns:
                raise ValueError("No text columns found in Excel file")
            texts = []
            for _, row in df.iterrows():
                combined_text = ' '.join(str(row[col]) for col in text_columns if pd.notna(row[col]))
                if combined_text.strip():
                    texts.append(combined_text.strip())
            return texts

        elif file_extension == '.txt':
            # Parse plain text file
            content_str = file_content.decode('utf-8')
            # Split by lines and filter empty lines
            texts = [line.strip() for line in content_str.split('\n') if line.strip()]
            return texts

        else:
            raise ValueError(f"Unsupported file format: {file_extension}. Supported: .csv, .xlsx, .xls, .json, .jsonl, .txt")
            
    except Exception as e:
        raise ValueError(f"Failed to parse file: {str(e)}")


def _analyze_dataset_poisoning(texts: List[str]) -> PoisoningAnalysisResponse:
    """Analyze dataset for poisoning using Isolation Forest algorithm."""
    try:
        if len(texts) < 10:
            raise ValueError("Dataset must contain at least 10 entries for meaningful analysis")
        
        # 1. Feature extraction using TF-IDF
        vectorizer = TfidfVectorizer(
            max_features=1000,  # Limit features for performance
            min_df=1,  # Minimum document frequency
            max_df=0.95,  # Maximum document frequency (remove very common words)
            stop_words='english',
            ngram_range=(1, 2)  # Unigrams and bigrams
        )
        
        # Convert texts to TF-IDF features
        try:
            tfidf_matrix = vectorizer.fit_transform(texts)
        except Exception:
            # Fallback: use simple character-level features if TF-IDF fails
            features = []
            for text in texts:
                feature_vector = [
                    len(text),  # Length
                    len(text.split()),  # Word count
                    len(set(text.lower())),  # Unique character count
                    text.count('!'),  # Exclamation marks
                    text.count('?'),  # Question marks
                    text.count('@'),  # At symbols
                    text.count('#'),  # Hash symbols
                    sum(1 for c in text if c.isupper()),  # Uppercase count
                    sum(1 for c in text if c.isdigit()),  # Digit count
                ]
                features.append(feature_vector)
            tfidf_matrix = np.array(features)
        
        # 2. Normalize features
        if hasattr(tfidf_matrix, 'toarray'):
            features_dense = tfidf_matrix.toarray()
        else:
            features_dense = tfidf_matrix
            
        scaler = StandardScaler()
        try:
            features_normalized = scaler.fit_transform(features_dense)
        except:
            # If scaling fails, use original features
            features_normalized = features_dense
        
        # 3. Apply Isolation Forest
        # Contamination rate: expected proportion of outliers in the dataset
        # For poisoning detection, we expect 5-20% contamination typically
        contamination_rate = min(0.2, max(0.05, 10 / len(texts)))  # Adaptive based on dataset size
        
        isolation_forest = IsolationForest(
            contamination=contamination_rate,
            random_state=42,
            n_estimators=100
        )
        
        # Fit and predict (-1 for outliers, 1 for inliers)
        predictions = isolation_forest.fit_predict(features_normalized)
        anomaly_scores = isolation_forest.decision_function(features_normalized)
        
        # 4. Identify suspicious entries
        suspicious_indices = np.where(predictions == -1)[0]
        suspicious_count = len(suspicious_indices)
        
        # 5. Semantic Analysis with Gemini (if suspicious entries found)
        semantic_analysis = None
        if suspicious_count > 0:
            print(f"[Dataset Analysis] Performing semantic analysis on {suspicious_count} suspicious entries...")
            semantic_analysis = _perform_semantic_analysis(texts, suspicious_indices.tolist())
        
        # 6. Hybrid scoring: Combine Statistical + Semantic Analysis
        anomaly_ratio = suspicious_count / len(texts)
        base_security_score = max(0, int(100 * (1 - anomaly_ratio * 2)))  # Scale anomaly ratio
        
        # Adjust security score based on semantic analysis
        final_security_score = base_security_score
        hybrid_confidence = "statistical_only"
        
        if semantic_analysis and semantic_analysis.get("status") == "success":
            semantic_data = semantic_analysis.get("analysis", {})
            semantic_confidence = semantic_data.get("confidence_score", 50)
            false_positive_likelihood = semantic_data.get("false_positive_likelihood", 50)
            
            # If semantic analysis suggests high false positive rate, increase security score
            if isinstance(false_positive_likelihood, (int, float)) and false_positive_likelihood > 70:
                final_security_score = min(100, base_security_score + 20)
                hybrid_confidence = "high_false_positive_adjusted"
            # If semantic analysis confirms poisoning with high confidence, decrease security score
            elif isinstance(semantic_confidence, (int, float)) and semantic_confidence > 80:
                poisoning_type = semantic_data.get("poisoning_type", "").lower()
                if poisoning_type not in ["none", "analysis_failed", "analysis_unavailable"]:
                    final_security_score = max(0, base_security_score - 15)
                    hybrid_confidence = "semantic_confirmed"
            else:
                hybrid_confidence = "semantic_moderate"
        
        # 7. Determine if dataset is considered poisoned (enhanced with semantic insights)
        is_poisoned = anomaly_ratio > 0.15 or final_security_score < 70
        
        # If semantic analysis suggests low risk, be less aggressive
        if semantic_analysis and semantic_analysis.get("status") == "success":
            semantic_risk = semantic_analysis.get("analysis", {}).get("risk_assessment", "medium")
            if semantic_risk == "low" and final_security_score > 60:
                is_poisoned = False
        
        # 8. Prepare enhanced analysis details
        analysis_details = {
            "statistical_analysis": {
                "contamination_rate": contamination_rate,
                "features_count": features_normalized.shape[1],
                "anomaly_threshold": float(np.min(anomaly_scores[predictions == -1])) if suspicious_count > 0 else None,
                "anomaly_ratio": float(anomaly_ratio),
                "avg_anomaly_score": float(np.mean(anomaly_scores[predictions == -1])) if suspicious_count > 0 else None,
                "base_security_score": base_security_score
            },
            "hybrid_scoring": {
                "method": "isolation_forest_plus_semantic",
                "confidence_level": hybrid_confidence,
                "final_security_score": final_security_score,
                "adjustment_applied": final_security_score != base_security_score
            },
            "algorithm": "Hybrid (Isolation Forest + Gemini Semantic Analysis)",
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        # 8. Prepare suspicious entries details
        suspicious_entries_details = []
        if suspicious_count > 0:
            # Sort by anomaly score (most anomalous first)
            sorted_indices = suspicious_indices[np.argsort(anomaly_scores[suspicious_indices])]
            
            for idx in sorted_indices:
                content_preview = texts[idx][:200] + "..." if len(texts[idx]) > 200 else texts[idx]
                anomaly_score = float(anomaly_scores[idx])
                
                # Determine risk level based on anomaly score
                if anomaly_score < np.percentile(anomaly_scores[predictions == -1], 33):
                    risk_level = "HIGH"
                elif anomaly_score < np.percentile(anomaly_scores[predictions == -1], 66):
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"
                
                suspicious_entries_details.append({
                    "index": int(idx),
                    "anomaly_score": anomaly_score,
                    "content_preview": content_preview,
                    "risk_level": risk_level
                })
        
        return PoisoningAnalysisResponse(
            is_poisoned=is_poisoned,
            security_score=final_security_score,
            total_entries=len(texts),
            suspicious_entries=suspicious_count,
            analysis_details=analysis_details,
            suspicious_entries_details=suspicious_entries_details,
            semantic_analysis=semantic_analysis
        )
        
    except Exception as e:
        raise ValueError(f"Analysis failed: {str(e)}")


@router.post("/analyze-poisoning")
async def analyze_dataset_poisoning(
    dataset_file: UploadFile = File(...),
    scan_name: str = Form(None),
    x_proxy_user: str = Header(None, alias="x-proxy-user")
):
    """
    Analyze uploaded dataset for potential poisoning attacks using hybrid approach.
    
    Combines Isolation Forest statistical analysis with Gemini 2.5 Flash semantic analysis
    for more accurate detection of data poisoning attacks.
    
    Supports CSV, JSON, JSONL, and TXT files up to 10MB.
    Returns analysis_id immediately and processes in background using worker queue.
    Saves analysis to database for persistence.
    """
    import uuid
    from datetime import datetime
    import sys
    
    # Import db and dataset_queue from main module
    main_module = sys.modules.get('__main__') or sys.modules.get('main')
    db = getattr(main_module, 'db', None)
    dataset_queue = getattr(main_module, 'dataset_queue', None)
    
    if db is None:
        from db_factory import get_database
        db = get_database()  # PostgreSQL or SQLite
    
    # Debug logging
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Dataset queue check: main_module={main_module}, dataset_queue={dataset_queue}")
    
    if dataset_queue is None:
        # Try alternative import method
        try:
            import main as main_import
            dataset_queue = getattr(main_import, 'dataset_queue', None)
            logger.info(f"Alternative import: dataset_queue={dataset_queue}")
        except Exception as e:
            logger.error(f"Failed to import main module: {e}")
    
    if dataset_queue is None:
        raise HTTPException(
            status_code=503,
            detail="Dataset analysis service is not available. Please ensure the API server has fully started."
        )
    
    # Normalize user_id to extract username from email if needed
    from user_utils import extract_username_from_identifier
    raw_user_id = x_proxy_user or "anonymous"
    user_id = extract_username_from_identifier(raw_user_id)
    analysis_id = str(uuid.uuid4())
    file_size = 0
    final_scan_name = scan_name or dataset_file.filename
    
    try:
        # Validate file size (10MB limit)
        max_size = 10 * 1024 * 1024  # 10MB
        file_content = await dataset_file.read()
        file_size = len(file_content)
        
        if file_size > max_size:
            raise HTTPException(
                status_code=413, 
                detail=f"File too large. Maximum size is {max_size // 1024 // 1024}MB"
            )
        
        # Validate file type
        allowed_extensions = ['.csv', '.json', '.jsonl', '.txt']
        file_extension = Path(dataset_file.filename).suffix.lower()
        
        if file_extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Check if queue is full
        if dataset_queue.full():
            raise HTTPException(
                status_code=429,
                detail="Dataset analysis queue is full. Please try again later."
            )
        
        # Save initial analysis to database
        db.save_dataset_analysis(
            analysis_id=analysis_id,
            file_name=dataset_file.filename,
            scan_name=final_scan_name,
            status="queued",
            file_size=file_size,
            message="Analysis queued for processing...",
            created_by=user_id
        )
        
        # Enqueue the analysis (queue-based execution with worker pool)
        await dataset_queue.put((analysis_id, file_content, dataset_file.filename, final_scan_name))
        
        # Return immediately with analysis_id
        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "message": f"Analysis '{final_scan_name}' has been queued for execution",
            "file_name": dataset_file.filename,
            "file_size": file_size
        }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start analysis: {str(e)}"
        )

async def _run_analysis_background(analysis_id: str, file_content: bytes, file_name: str):
    """Background task to run dataset analysis - runs in thread pool to avoid blocking"""
    import asyncio
    import sys
    from datetime import datetime
    
    # Import db from main module
    main_module = sys.modules.get('__main__') or sys.modules.get('main')
    db = getattr(main_module, 'db', None)
    
    if db is None:
        from db_factory import get_database
        db = get_database()  # PostgreSQL or SQLite
    
    try:
        # Parse dataset file (CPU-intensive, run in thread)
        try:
            texts = await asyncio.to_thread(_parse_dataset_file, file_content, file_name)
        except ValueError as e:
            db.update_dataset_analysis_status(
                analysis_id=analysis_id,
                status="failed",
                message=f"Failed to parse file: {str(e)}",
                completed_at=datetime.utcnow().isoformat()
            )
            return
        
        if len(texts) == 0:
            db.update_dataset_analysis_status(
                analysis_id=analysis_id,
                status="failed",
                message="No text data found in the uploaded file",
                completed_at=datetime.utcnow().isoformat()
            )
            return
        
        # Perform poisoning analysis (CPU-intensive ML operations, run in thread)
        try:
            # Run the blocking ML analysis in a thread pool to avoid blocking the event loop
            result = await asyncio.to_thread(_analyze_dataset_poisoning, texts)
            
            # Convert Pydantic model to dict for database storage
            result_dict = result.model_dump() if hasattr(result, 'model_dump') else result.dict()
            
            # Update database with results (also blocking I/O, run in thread)
            await asyncio.to_thread(
                db.update_dataset_analysis_status,
                analysis_id=analysis_id,
                status="completed",
                results=result_dict,
                is_poisoned=result.is_poisoned,
                security_score=result.security_score,
                total_entries=result.total_entries,
                suspicious_entries=result.suspicious_entries,
                message="Analysis completed successfully",
                completed_at=datetime.utcnow().isoformat()
            )
            
        except ValueError as e:
            await asyncio.to_thread(
                db.update_dataset_analysis_status,
                analysis_id=analysis_id,
                status="failed",
                message=f"Analysis failed: {str(e)}",
                completed_at=datetime.utcnow().isoformat()
            )
            
    except Exception as e:
        await asyncio.to_thread(
            db.update_dataset_analysis_status,
            analysis_id=analysis_id,
            status="failed",
            message=f"Failed to analyze dataset: {str(e)}",
            completed_at=datetime.utcnow().isoformat()
        )
