import json
import os
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = ROOT_DIR / "security.config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "block_on": ["CRITICAL", "HIGH"],
    "warn_on": ["MEDIUM", "LOW"],
    "allowed_directories": [
        "terraform/vulnerable",
        "terraform/remediated"
    ],
    "default_target": "terraform/vulnerable"
}

def get_security_config() -> Dict[str, Any]:
    if CONFIG_FILE.is_file():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_CONFIG, **data}
        except Exception as e:
            print(f"Warning: Failed to parse security.config.json: {e}")
    return DEFAULT_CONFIG
