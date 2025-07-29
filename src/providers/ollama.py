"""
Ollama provider integration for LLM enrichment.
Handles API endpoint, prompt formatting, and enrichment logic.
"""
# src/providers/ollama.py

import os
import json
import time
import logging
import requests
import re
import sys
import traceback
from datetime import datetime, timezone
from src.schemas import WazuhAlertInput, Enrichment, EnrichedAlertOutput
from src.core.yara_integration import get_yara_matches
from src.core.utils import load_prompt_template  # shared utility

# If you see an import error for dotenv, install with: pip install python-dotenv
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        pass  # fallback if dotenv is not installed

logger = logging.getLogger("llm_enrichment")

# Load environment variables from .env file
load_dotenv()

OLLAMA_API = os.getenv("OLLAMA_API", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")
PROMPT_TEMPLATE_PATH = "templates/prompt_template.txt"


def clean_llm_response(raw: str) -> str:
    """Cleans and extracts valid JSON object from raw LLM output.
    Handles code blocks, quoted JSON, and escaped JSON.
    """
    raw = raw.strip()
    # Remove code block markers
    if raw.startswith("```"):
        raw = raw.replace("```json", "").replace("```", "").strip()
    
    # Recursively remove leading/trailing quotes (single or double) and unescape
    while ((raw.startswith('"') and raw.endswith('"')) or
           (raw.startswith("'") and raw.endswith("'"))):
        raw = raw[1:-1].strip()
        try:
            raw = bytes(raw, "utf-8").decode("unicode_escape")
        except Exception:
            pass
    
    # Extract first {...} block, handling newlines properly
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if match:
        json_str = match.group(0)
        # Try to parse and re-dump to clean up formatting
        try:
            parsed = json.loads(json_str)
            return json.dumps(parsed)
        except json.JSONDecodeError:
            # If parsing fails, return the matched string as-is
            return json_str
    
    # Final fallback: try to parse as JSON string (if it's a dict, dump it back to string)
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return json.dumps(obj)
        if isinstance(obj, str):
            return clean_llm_response(obj)
    except Exception:
        pass
    
    raise ValueError(f"No JSON object found in LLM output: {repr(raw)}")


from typing import Optional

def warm_up_model(model: str) -> bool:
    """Pre-warm the Ollama model to reduce first-request latency"""
    try:
        logger.info(f"Warming up model {model}...")
        payload = {
            "model": model,
            "prompt": "Hello",
            "stream": False,
            "options": {"max_tokens": 1}
        }
        response = requests.post(OLLAMA_API, json=payload, timeout=600)
        response.raise_for_status()
        logger.info(f"Model {model} warmed up successfully")
        return True
    except Exception as e:
        logger.warning(f"Model warm-up failed: {e}")
        return False

def query_ollama(alert: dict, model: Optional[str] = None) -> EnrichedAlertOutput:
    """
    Enriches a Wazuh alert using the Ollama API.
    """
    logger.debug("Starting alert enrichment")
    
    raw_llm_response = None
    if model is None:
        # Use the model from environment variable
        model = os.getenv("LLM_MODEL", "llama3:8b")
    
    logger.debug(f"Using model: {model}")
    
    # Warm up model if this is likely the first request
    warm_up_model(model)
    
    try:
        alert_obj = WazuhAlertInput(**alert)
        logger.debug("Alert object created successfully")
    except Exception as e:
        logger.error(f"Invalid input alert format: {e}")
        raise ValueError(f"Invalid input alert format: {e}")

    # Defensive YARA handling: always define yara_results
    yara_results = []
    try:
        yara_results = get_yara_matches(alert)
        logger.debug("YARA matches retrieved")
    except Exception as e:
        logger.warning(f"YARA scan failed or no rules loaded: {e}")
        yara_results = []

    try:
        template = load_prompt_template(PROMPT_TEMPLATE_PATH)
        logger.debug("Template loaded")
        
        alert_json_str = json.dumps(alert_obj.model_dump(), indent=2)
        yara_results_str = json.dumps(yara_results, indent=2) if yara_results else "None"
        
        logger.debug("JSON strings created for prompt formatting")
        
        # Temporary workaround: construct prompt manually instead of using template.format()
        prompt = f"""You are a cybersecurity analyst specializing in alert enrichment and threat analysis.

Analyze the following security alert and provide enrichment data in JSON format.

TASK: Analyze this Wazuh security alert and provide contextual enrichment including:

RESPOND WITH ONLY A SINGLE VALID JSON OBJECT. NO markdown, NO explanations, NO extra text.

Required JSON format:
{{"summary_text": "Brief description of the security event", "tags": ["relevant", "security", "tags"], "risk_score": 50, "false_positive_likelihood": 0.1, "alert_category": "Category", "remediation_steps": ["Step 1", "Step 2"], "related_cves": [], "external_refs": []}}

INSTRUCTIONS:

ALERT TO ANALYZE:
{alert_json_str}

YARA MATCHES:
{yara_results_str}

JSON OUTPUT:"""
        logger.debug("Prompt formatted successfully")

        logger.info(f"Making Ollama request to: {OLLAMA_API}")
        logger.info(f"Using model: {model}")
        logger.debug(f"Prompt length: {len(prompt)} characters")
        
        # Make the actual Ollama API request
        start_time = time.time()
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 1000
            }
        }
        
        logger.info("Sending request to Ollama (this may take 1-5 minutes on first model load)...")
        response = requests.post(OLLAMA_API, json=payload, timeout=600)  # 10 minutes for first load
        response.raise_for_status()
        
        logger.debug("HTTP request completed successfully")
        
        response_data = response.json()
        raw_llm_response = response_data.get("response", "")
        
        logger.debug(f"Raw LLM response received: {len(raw_llm_response)} characters")
        
        # Clean and parse the LLM response
        logger.debug("Processing LLM response")
        
        cleaned_response = clean_llm_response(raw_llm_response)
        
        logger.debug(f"Response cleaned successfully: {len(cleaned_response)} characters")
        
        enrichment_data = json.loads(cleaned_response)
        
        logger.debug("LLM response parsed successfully")
        
        end_time = time.time()
        duration_ms = int((end_time - start_time) * 1000)
        
        # Create Enrichment object from parsed data with proper type conversion
        risk_score_raw = enrichment_data.get("risk_score", 0)
        risk_score = int(float(risk_score_raw)) if isinstance(risk_score_raw, (int, float)) else 0
        
        enrichment = Enrichment(
            summary_text=enrichment_data.get("summary_text", ""),
            tags=enrichment_data.get("tags", []),
            risk_score=risk_score,
            false_positive_likelihood=float(enrichment_data.get("false_positive_likelihood", 0.0)),
            alert_category=enrichment_data.get("alert_category", "unknown"),
            remediation_steps=enrichment_data.get("remediation_steps", []),
            related_cves=enrichment_data.get("related_cves", []),
            external_refs=enrichment_data.get("external_refs", []),
            llm_model_version=model,
            enriched_by="ollama",
            enrichment_duration_ms=duration_ms,
            yara_matches=yara_results,
            raw_llm_response=raw_llm_response
        )
        
        return EnrichedAlertOutput(
            alert_id=getattr(alert_obj, 'id', 'unknown'),
            alert=alert_obj,
            timestamp=datetime.now(timezone.utc),
            enrichment=enrichment
        )
    except Exception as e:
        logger.error(f"Failed during enrichment: {e}")
        # Return a minimal EnrichedAlertOutput on error
        # Try to build a minimal alert dict for fallback
        fallback_alert_id = alert.get("id", "unknown") if isinstance(alert, dict) else "unknown"
        # Build a minimal valid WazuhAlertInput
        from src.schemas import Rule, Agent, Manager, Decoder, Predecoder
        minimal_alert = WazuhAlertInput(
            id=fallback_alert_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule=Rule(id="0", level=0, description="Enrichment failed", firedtimes=0, mail=False),
            agent=Agent(id="0", name="unknown"),
            manager=Manager(name="unknown"),
            decoder=Decoder(name="unknown"),
            predecoder=Predecoder(program_name="unknown", timestamp="", hostname="unknown"),
            full_log="Enrichment failed",
            location="unknown"
        )
        return EnrichedAlertOutput(
            alert_id=fallback_alert_id,
            alert=minimal_alert,
            timestamp=datetime.now(timezone.utc),
            enrichment=Enrichment(
                summary_text=f"Enrichment failed: {e}",
                tags=[],
                risk_score=0,
                false_positive_likelihood=0.0,
                alert_category="error",
                remediation_steps=[],
                related_cves=[],
                external_refs=[],
                llm_model_version=model,
                enriched_by="ollama",
                enrichment_duration_ms=0,
                yara_matches=[]
            )
        )
