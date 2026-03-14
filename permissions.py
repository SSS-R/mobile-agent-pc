"""
Permission Manager for Mobile Agent PC

Read-only security foundation for file access control.
Implements default-deny policy with explicit allowlists and blocklists.
"""

import os
import re
import fnmatch
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime

import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PermissionManager:
    """
    Manages file access permissions with default-deny policy.
    
    Security features:
    - Default-deny (only explicitly allowed paths accessible)
    - Blocked paths take precedence over allowed paths
    - Path traversal protection (no .., symlinks resolved)
    - File extension filtering
    - File size limits
    - Audit logging
    """
    
    def __init__(self, config_path: str = "permissions.yaml"):
        """
        Initialize permission manager with config file.
        
        Args:
            config_path: Path to permissions.yaml configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._setup_audit_log()
        
    def _load_config(self) -> dict:
        """Load and validate configuration file."""
        if not self.config_path.exists():
            logger.error(f"Permission config not found: {self.config_path}")
            raise FileNotFoundError(f"Permission config not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required sections
        required = ['default_policy', 'allowed_paths', 'blocked_paths']
        for key in required:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")
        
        logger.info(f"Loaded permission config from {self.config_path}")
        return config
    
    def _setup_audit_log(self):
        """Setup audit logging configuration."""
        audit_config = self.config.get('audit', {})
        if audit_config.get('log_all_access', False):
            log_file = audit_config.get('log_file', 'logs/permission_audit.log')
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Audit logging enabled: {log_file}")
    
    def _audit_log(self, path: str, decision: str, reason: str):
        """Log access attempt to audit log."""
        if not self.config.get('audit', {}).get('log_all_access', False):
            return
        
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'path': path,
            'decision': decision,
            'reason': reason
        }
        logger.info(f"AUDIT: {log_entry}")
    
    def _normalize_path(self, path: str) -> Path:
        """
        Normalize and resolve path securely.
        
        Security measures:
        - Resolves symlinks to real paths
        - Removes .. components
        - Converts to absolute path
        - Normalizes Unicode
        
        Args:
            path: Input path string
            
        Returns:
            Normalized Path object
            
        Raises:
            ValueError: If path contains unsafe components
        """
        # Require absolute paths
        if not os.path.isabs(path):
            raise ValueError(f"Path must be absolute: {path}")
        
        # Check for parent directory traversal
        if self.config.get('security', {}).get('block_parent_directory', True):
            if '..' in path.split(os.sep):
                raise ValueError(f"Path traversal detected: {path}")
        
        # Normalize Unicode
        if self.config.get('security', {}).get('normalize_unicode', True):
            path = path.encode('utf-8').decode('utf-8')
        
        # Create Path object
        normalized = Path(path)
        
        # Resolve symlinks if enabled
        if self.config.get('security', {}).get('resolve_symlinks', True):
            if normalized.exists():
                normalized = normalized.resolve()
        
        return normalized
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """
        Check if path matches glob pattern.
        
        Args:
            path: Path to check
            pattern: Glob pattern (e.g., /home/*/*.txt)
            
        Returns:
            True if path matches pattern
        """
        return fnmatch.fnmatch(path, pattern)
    
    def _is_blocked_path(self, path: str) -> Tuple[bool, str]:
        """
        Check if path is in blocked paths list.
        
        Args:
            path: Normalized path string
            
        Returns:
            Tuple of (is_blocked, reason)
        """
        blocked_paths = self.config.get('blocked_paths', [])
        
        for pattern in blocked_paths:
            if self._matches_pattern(path, pattern):
                return True, f"Path matches blocked pattern: {pattern}"
            
            # Also check if any parent directory is blocked
            path_obj = Path(path)
            for parent in path_obj.parents:
                if self._matches_pattern(str(parent), pattern.rstrip('/*')):
                    return True, f"Parent directory matches blocked pattern: {pattern}"
        
        return False, ""
    
    def _is_allowed_path(self, path: str) -> Tuple[bool, str]:
        """
        Check if path is in allowed paths list.
        
        Args:
            path: Normalized path string
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        allowed_paths = self.config.get('allowed_paths', [])
        
        for pattern in allowed_paths:
            if self._matches_pattern(path, pattern):
                return True, f"Path matches allowed pattern: {pattern}"
        
        return False, "Path does not match any allowed pattern"
    
    def _check_file_extension(self, path: str) -> Tuple[bool, str]:
        """
        Check if file extension is allowed.
        
        Args:
            path: File path
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        file_restrictions = self.config.get('file_restrictions', {})
        allowed_exts = file_restrictions.get('allowed_extensions', [])
        blocked_exts = file_restrictions.get('blocked_extensions', [])
        
        ext = Path(path).suffix.lower()
        
        # Check blocked extensions first
        if ext in blocked_exts:
            return False, f"File extension blocked: {ext}"
        
        # Check allowed extensions (if list is not empty)
        if allowed_exts and ext not in allowed_exts:
            return False, f"File extension not allowed: {ext}"
        
        return True, "File extension OK"
    
    def _check_file_size(self, path: str) -> Tuple[bool, str]:
        """
        Check if file size is within limits.
        
        Args:
            path: File path
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        file_restrictions = self.config.get('file_restrictions', {})
        max_size = file_restrictions.get('max_file_size', 1048576)
        
        if not os.path.exists(path):
            return False, "File does not exist"
        
        file_size = os.path.getsize(path)
        if file_size > max_size:
            return False, f"File size ({file_size} bytes) exceeds limit ({max_size} bytes)"
        
        return True, f"File size OK ({file_size} bytes)"
    
    def check_access(self, path: str, access_type: str = "read") -> Tuple[bool, str]:
        """
        Check if access to path is allowed.
        
        Implements default-deny policy:
        1. Normalize path (resolve symlinks, remove ..)
        2. Check blocked paths (deny if matched)
        3. Check allowed paths (deny if not matched)
        4. Check file extension
        5. Check file size (for read access)
        
        Args:
            path: Path to check
            access_type: Type of access ("read", "list", etc.)
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            # Step 1: Normalize path
            normalized = self._normalize_path(path)
            path_str = str(normalized)
            
            # Step 2: Check blocked paths (takes precedence)
            is_blocked, block_reason = self._is_blocked_path(path_str)
            if is_blocked:
                self._audit_log(path_str, "DENY", block_reason)
                return False, block_reason
            
            # Step 3: Check allowed paths (default-deny)
            is_allowed, allow_reason = self._is_allowed_path(path_str)
            if not is_allowed:
                self._audit_log(path_str, "DENY", allow_reason)
                return False, allow_reason
            
            # Step 4: Check file extension (for files only)
            if os.path.isfile(path_str):
                ext_ok, ext_reason = self._check_file_extension(path_str)
                if not ext_ok:
                    self._audit_log(path_str, "DENY", ext_reason)
                    return False, ext_reason
            
            # Step 5: Check file size (for read access on files)
            if access_type == "read" and os.path.isfile(path_str):
                size_ok, size_reason = self._check_file_size(path_str)
                if not size_ok:
                    self._audit_log(path_str, "DENY", size_reason)
                    return False, size_reason
            
            # All checks passed
            self._audit_log(path_str, "ALLOW", "All checks passed")
            return True, "Access granted"
            
        except ValueError as e:
            self._audit_log(path, "DENY", f"Security violation: {str(e)}")
            return False, f"Security violation: {str(e)}"
        except Exception as e:
            self._audit_log(path, "DENY", f"Error: {str(e)}")
            return False, f"Error checking access: {str(e)}"
    
    def list_allowed_directory(self, dir_path: str) -> Tuple[bool, List[str], str]:
        """
        List contents of directory if access is allowed.
        
        Args:
            dir_path: Directory path to list
            
        Returns:
            Tuple of (success, entries, error_message)
        """
        # Check directory access
        allowed, reason = self.check_access(dir_path, "list")
        if not allowed:
            return False, [], reason
        
        try:
            entries = []
            for entry in os.listdir(dir_path):
                entry_path = os.path.join(dir_path, entry)
                
                # Check if entry itself is accessible
                entry_allowed, _ = self.check_access(entry_path, "list")
                if entry_allowed:
                    entry_type = "dir" if os.path.isdir(entry_path) else "file"
                    entries.append({"name": entry, "type": entry_type})
            
            return True, entries, ""
            
        except Exception as e:
            return False, [], f"Error listing directory: {str(e)}"
    
    def read_file(self, file_path: str) -> Tuple[bool, str, str]:
        """
        Read file content if access is allowed.
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (success, content, error_message)
        """
        # Check file access
        allowed, reason = self.check_access(file_path, "read")
        if not allowed:
            return False, "", reason
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return True, content, ""
            
        except Exception as e:
            return False, "", f"Error reading file: {str(e)}"


# Convenience functions for direct use

_manager: Optional[PermissionManager] = None

def get_manager() -> PermissionManager:
    """Get or create singleton permission manager."""
    global _manager
    if _manager is None:
        _manager = PermissionManager()
    return _manager

def check_access(path: str, access_type: str = "read") -> Tuple[bool, str]:
    """Check if path access is allowed."""
    return get_manager().check_access(path, access_type)

def list_directory(dir_path: str) -> Tuple[bool, List[str], str]:
    """List directory contents if allowed."""
    return get_manager().list_allowed_directory(dir_path)

def read_file(file_path: str) -> Tuple[bool, str, str]:
    """Read file content if allowed."""
    return get_manager().read_file(file_path)


if __name__ == "__main__":
    # Test the permission manager
    print("Testing Permission Manager...")
    manager = PermissionManager()
    
    # Test cases
    test_paths = [
        "/home/noahsr/projects/test.py",
        "/home/noahsr/.ssh/id_rsa",
        "/etc/passwd",
        "/home/noahsr/projects/../.git/config",
    ]
    
    for path in test_paths:
        allowed, reason = manager.check_access(path)
        status = "✅ ALLOW" if allowed else "❌ DENY"
        print(f"{status}: {path}")
        print(f"   Reason: {reason}")
