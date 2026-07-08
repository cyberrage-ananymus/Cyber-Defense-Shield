"""
Utility functions for all modules
"""

import subprocess
import logging
import shlex
import os
from typing import List, Dict, Any, Optional, Tuple

try:
    import config as _config
except Exception:
    _config = None

logger = logging.getLogger(__name__)


def _cfg(name: str, default: Any) -> Any:
    """
    Read a tunable setting from config.py, falling back to a safe default.
    
    Detection and mitigation thresholds are kept here instead of hardcoded
    so they can be tuned to a system's real traffic profile.
    """
    return getattr(_config, name, default) if _config is not None else default


def run_command(cmd: List[str], timeout: int = 30, capture: bool = True) -> Tuple[int, str, str]:
    """
    Safe subprocess wrapper with proper error handling and logging.
    
    Args:
        cmd: Command list (already split, ready for subprocess)
        timeout: Timeout in seconds
        capture: Capture stdout/stderr
    
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    if not cmd or not isinstance(cmd, list):
        logger.error(f"Invalid command: {cmd}")
        return 1, "", "Invalid command"
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timeout ({timeout}s): {' '.join(cmd)}")
        return 124, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0]}")
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return 1, "", str(e)


def safe_quote(value: str) -> str:
    """
    Safely quote a string for shell operations.
    Prevents command injection attacks.
    """
    return shlex.quote(value)


def extract_port(address_port: str) -> Optional[str]:
    """
    Extract port from 'address:port' format (handles IPv4 and IPv6).
    """
    if not address_port or ':' not in address_port:
        return None
    return address_port.rsplit(':', 1)[1]


def extract_ip(address_port: str) -> Optional[str]:
    """
    Extract IP from 'address:port' format (handles IPv4 and IPv6).
    """
    if not address_port:
        return None
    if address_port.startswith('['):
        return address_port.split(']')[0].lstrip('[')
    if ':' in address_port:
        return address_port.rsplit(':', 1)[0]
    return address_port


class SafeCommand:
    """
    Context manager for safe command execution with logging.
    """
    def __init__(self, cmd: List[str], description: str = ""):
        self.cmd = cmd
        self.description = description or ' '.join(cmd)
        self.returncode = None
        self.stdout = ""
        self.stderr = ""
    
    def __enter__(self):
        logger.debug(f"Executing: {self.description}")
        self.returncode, self.stdout, self.stderr = run_command(self.cmd)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.returncode != 0:
            logger.warning(f"Command failed ({self.returncode}): {self.description}")
            if self.stderr:
                logger.debug(f"stderr: {self.stderr}")
        return False
    
    def success(self) -> bool:
        return self.returncode == 0
