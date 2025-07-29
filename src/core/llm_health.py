"""
LLM Health Check and Wait functionality for the enrichment service.
Provides options to pause enrichment until LLM is available.
"""

import time
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from src.core.logger import log

class LLMHealthChecker:
    """Monitors LLM availability and provides wait functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.ollama_url = config.get('ollama_url', 'http://localhost:11434')
        self.model = config.get('model', 'llama3:8b')
        self.check_interval = config.get('health_check_interval', 30)  # seconds
        self.max_wait_time = config.get('max_wait_time', 3600)  # 1 hour max wait
        self.enable_wait_mode = config.get('wait_for_llm', False)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.backoff_multiplier = config.get('backoff_multiplier', 2)
        
        self._last_health_check = None
        self._last_health_status = False
        
    def check_ollama_health(self) -> Dict[str, Any]:
        """Check if Ollama is running and accessible."""
        try:
            # Test basic connectivity
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=10)
            if response.status_code != 200:
                return {
                    "healthy": False,
                    "error": f"HTTP {response.status_code}",
                    "details": "Ollama API not responding correctly"
                }
            
            # Check if our model is available
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            
            if self.model not in model_names:
                return {
                    "healthy": False,
                    "error": "Model not found",
                    "details": f"Model '{self.model}' not available. Available: {model_names}",
                    "available_models": model_names
                }
            
            return {
                "healthy": True,
                "model": self.model,
                "available_models": model_names,
                "ollama_url": self.ollama_url
            }
            
        except requests.exceptions.ConnectionError:
            return {
                "healthy": False,
                "error": "Connection refused",
                "details": f"Cannot connect to Ollama at {self.ollama_url}"
            }
        except requests.exceptions.Timeout:
            return {
                "healthy": False,
                "error": "Timeout",
                "details": "Ollama health check timed out"
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": "Unknown error",
                "details": str(e)
            }
    
    def test_model_inference(self) -> Dict[str, Any]:
        """Test if the model can actually perform inference."""
        try:
            test_payload = {
                "model": self.model,
                "prompt": "Respond with exactly: 'HEALTH_CHECK_OK'",
                "stream": False,
                "options": {"max_tokens": 10}
            }
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=test_payload,
                timeout=60
            )
            
            if response.status_code != 200:
                return {
                    "inference_healthy": False,
                    "error": f"HTTP {response.status_code}",
                    "details": "Model inference failed"
                }
            
            result = response.json()
            response_text = result.get("response", "").strip()
            
            return {
                "inference_healthy": True,
                "response": response_text,
                "generation_time": result.get("total_duration", 0) / 1e9
            }
            
        except Exception as e:
            return {
                "inference_healthy": False,
                "error": "Inference test failed",
                "details": str(e)
            }
    
    def wait_for_llm_available(self) -> bool:
        """
        Wait for LLM to become available.
        Returns True when LLM is ready, False if max wait time exceeded.
        """
        if not self.enable_wait_mode:
            return True  # Skip waiting if not enabled
            
        log("🔍 Wait-for-LLM mode enabled, checking availability...", tag="HEALTH")
        
        start_time = time.time()
        attempt = 0
        wait_interval = self.check_interval
        
        while time.time() - start_time < self.max_wait_time:
            attempt += 1
            
            log(f"🏥 Health check attempt #{attempt}", tag="HEALTH")
            
            # Check basic health
            health_status = self.check_ollama_health()
            
            if health_status["healthy"]:
                # Test inference capability
                log("✅ Ollama is running, testing model inference...", tag="HEALTH")
                inference_status = self.test_model_inference()
                
                if inference_status.get("inference_healthy", False):
                    elapsed = time.time() - start_time
                    log(f"🎉 LLM is fully operational! (waited {elapsed:.1f}s)", tag="HEALTH")
                    self._last_health_status = True
                    self._last_health_check = datetime.now(timezone.utc)
                    return True
                else:
                    log(f"⚠️ Model not responding correctly: {inference_status.get('details', 'Unknown')}", tag="HEALTH")
            else:
                error_msg = health_status.get("details", health_status.get("error", "Unknown"))
                log(f"❌ LLM not available: {error_msg}", tag="HEALTH")
            
            # Wait before next attempt with exponential backoff
            log(f"⏳ Waiting {wait_interval}s before next check...", tag="HEALTH")
            time.sleep(wait_interval)
            
            # Exponential backoff up to max interval
            wait_interval = min(wait_interval * self.backoff_multiplier, 300)  # Max 5 minutes
        
        # Timeout exceeded
        total_wait = time.time() - start_time
        log(f"⏰ Max wait time exceeded ({total_wait:.1f}s). Proceeding with degraded mode.", tag="HEALTH")
        return False
    
    def is_llm_healthy(self, force_check: bool = False) -> bool:
        """
        Check if LLM is currently healthy.
        Uses cached result unless force_check is True.
        """
        now = datetime.now(timezone.utc)
        
        # Use cached result if recent and not forcing
        if (not force_check and 
            self._last_health_check and 
            (now - self._last_health_check).total_seconds() < self.check_interval):
            return self._last_health_status
        
        # Perform fresh health check
        health_status = self.check_ollama_health()
        self._last_health_status = health_status["healthy"]
        self._last_health_check = now
        
        if not self._last_health_status:
            error_msg = health_status.get("details", health_status.get("error", "Unknown"))
            log(f"🏥 LLM health check failed: {error_msg}", tag="HEALTH")
        
        return self._last_health_status
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive health summary."""
        health = self.check_ollama_health()
        
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ollama_url": self.ollama_url,
            "model": self.model,
            "config": {
                "wait_for_llm": self.enable_wait_mode,
                "check_interval": self.check_interval,
                "max_wait_time": self.max_wait_time
            },
            "status": health
        }
        
        if health["healthy"]:
            inference = self.test_model_inference()
            summary["inference"] = inference
            
        return summary

def get_llm_health_config():
    """Get LLM health configuration from environment variables."""
    import os
    
    return {
        'ollama_url': os.getenv('OLLAMA_URL', 'http://localhost:11434'),
        'model': os.getenv('LLM_MODEL', 'llama3:8b'),
        'wait_for_llm': os.getenv('WAIT_FOR_LLM', 'false').lower() == 'true',
        'health_check_interval': int(os.getenv('LLM_HEALTH_CHECK_INTERVAL', '30')),
        'max_wait_time': int(os.getenv('LLM_MAX_WAIT_TIME', '3600')),
        'retry_attempts': int(os.getenv('LLM_RETRY_ATTEMPTS', '3')),
        'backoff_multiplier': float(os.getenv('LLM_BACKOFF_MULTIPLIER', '2.0'))
    }
