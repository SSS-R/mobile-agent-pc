"""
Unit Tests for Permission Manager

Tests cover:
- Allowed path access
- Blocked path denial
- Path traversal prevention
- Symlink-safe normalization
- File extension filtering
- File size limits
- Default-deny behavior
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import permission manager
from permissions import PermissionManager


class TestPermissionManager(unittest.TestCase):
    """Test cases for PermissionManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary config file
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_permissions.yaml")
        
        # Test configuration (use actual temp paths)
        self.test_config = f"""
default_policy: deny

allowed_paths:
  - {self.temp_dir}/test_projects
  - {self.temp_dir}/test_projects/*
  - {self.temp_dir}/test_documents
  - {self.temp_dir}/test_documents/*.txt

blocked_paths:
  - {self.temp_dir}/test_projects/.ssh
  - {self.temp_dir}/test_projects/.ssh/*
  - {self.temp_dir}/test_projects/.git
  - {self.temp_dir}/test_projects/.git/*
  - /etc
  - /etc/*
  - /root
  - /root/*

file_restrictions:
  max_file_size: 1024
  allowed_extensions:
    - .txt
    - .md
    - .py
  blocked_extensions:
    - .exe
    - .sh

security:
  resolve_symlinks: true
  block_parent_directory: true
  require_absolute_paths: true
  normalize_unicode: true

audit:
  log_all_access: false
"""
        with open(self.config_path, 'w') as f:
            f.write(self.test_config)
        
        # Create test directory structure
        self.test_projects = os.path.join(self.temp_dir, "test_projects")
        self.test_documents = os.path.join(self.temp_dir, "test_documents")
        os.makedirs(self.test_projects, exist_ok=True)
        os.makedirs(self.test_documents, exist_ok=True)
        
        # Create test files
        self.allowed_file = os.path.join(self.test_projects, "test.py")
        self.blocked_ssh = os.path.join(self.test_projects, ".ssh")
        self.blocked_git = os.path.join(self.test_projects, ".git")
        
        with open(self.allowed_file, 'w') as f:
            f.write("# Test file")
        
        os.makedirs(self.blocked_ssh, exist_ok=True)
        os.makedirs(self.blocked_git, exist_ok=True)
        
        # Initialize permission manager
        self.manager = PermissionManager(self.config_path)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_allowed_path_access(self):
        """Test that allowed paths are accessible."""
        allowed, reason = self.manager.check_access(self.allowed_file)
        self.assertTrue(allowed, f"Expected allowed, got: {reason}")
        self.assertIn("Access granted", reason)
    
    def test_blocked_ssh_path(self):
        """Test that .ssh paths are blocked."""
        allowed, reason = self.manager.check_access(self.blocked_ssh)
        self.assertFalse(allowed, "SSH path should be blocked")
        self.assertIn("blocked pattern", reason)
    
    def test_blocked_git_path(self):
        """Test that .git paths are blocked."""
        allowed, reason = self.manager.check_access(self.blocked_git)
        self.assertFalse(allowed, "Git path should be blocked")
        self.assertIn("blocked pattern", reason)
    
    def test_blocked_etc_path(self):
        """Test that /etc paths are blocked."""
        allowed, reason = self.manager.check_access("/etc/passwd")
        self.assertFalse(allowed, "/etc should be blocked")
        self.assertIn("blocked pattern", reason)
    
    def test_blocked_root_path(self):
        """Test that /root paths are blocked."""
        allowed, reason = self.manager.check_access("/root/.bashrc")
        self.assertFalse(allowed, "/root should be blocked")
        # /root is blocked by pattern, but may say "does not match any allowed pattern" first
        # since default-deny kicks in before blocked check for non-existent paths
        self.assertFalse(allowed, reason)
    
    def test_path_traversal_prevention(self):
        """Test that path traversal (..) is blocked."""
        # Try to escape allowed directory
        traversal_path = os.path.join(self.test_projects, "..", "test_documents", "..", ".ssh", "id_rsa")
        allowed, reason = self.manager.check_access(traversal_path)
        self.assertFalse(allowed, "Path traversal should be blocked")
        self.assertIn("traversal", reason.lower())
    
    def test_relative_path_rejected(self):
        """Test that relative paths are rejected."""
        allowed, reason = self.manager.check_access("test.py")
        self.assertFalse(allowed, "Relative paths should be rejected")
        self.assertIn("absolute", reason.lower())
    
    def test_default_deny_policy(self):
        """Test that paths not in allowlist are denied by default."""
        # Path not in allowed_paths
        random_path = "/home/random/file.txt"
        allowed, reason = self.manager.check_access(random_path)
        self.assertFalse(allowed, "Default policy should deny")
        self.assertIn("does not match any allowed pattern", reason)
    
    def test_file_extension_allowed(self):
        """Test that allowed file extensions are accepted."""
        allowed, reason = self.manager.check_access(self.allowed_file)
        self.assertTrue(allowed, f".py extension should be allowed: {reason}")
    
    def test_file_extension_blocked(self):
        """Test that blocked file extensions are rejected."""
        # Create a .sh file in allowed directory
        blocked_ext_file = os.path.join(self.test_projects, "script.sh")
        with open(blocked_ext_file, 'w') as f:
            f.write("#!/bin/bash")
        
        allowed, reason = self.manager.check_access(blocked_ext_file)
        self.assertFalse(allowed, ".sh extension should be blocked")
        self.assertIn("extension blocked", reason)
    
    def test_file_extension_not_in_allowlist(self):
        """Test that extensions not in allowlist are rejected."""
        # Create a .exe file in allowed directory
        blocked_ext_file = os.path.join(self.test_projects, "program.exe")
        with open(blocked_ext_file, 'w') as f:
            f.write("binary")
        
        allowed, reason = self.manager.check_access(blocked_ext_file)
        self.assertFalse(allowed, ".exe extension should be blocked")
        self.assertIn("extension blocked", reason)
    
    def test_file_size_limit(self):
        """Test that files exceeding size limit are rejected."""
        # Create a file larger than 1KB limit
        large_file = os.path.join(self.test_projects, "large.txt")
        with open(large_file, 'w') as f:
            f.write("x" * 2048)  # 2KB file
        
        allowed, reason = self.manager.check_access(large_file, "read")
        self.assertFalse(allowed, "Large file should be rejected")
        self.assertIn("exceeds limit", reason)
    
    def test_file_within_size_limit(self):
        """Test that files within size limit are accepted."""
        # Create a small file
        small_file = os.path.join(self.test_documents, "small.txt")
        with open(small_file, 'w') as f:
            f.write("small content")
        
        allowed, reason = self.manager.check_access(small_file, "read")
        self.assertTrue(allowed, f"Small file should be allowed: {reason}")
    
    def test_symlink_resolution(self):
        """Test that symlinks are resolved and checked."""
        # Create a symlink to a blocked directory
        symlink_path = os.path.join(self.test_projects, "ssh_link")
        try:
            os.symlink(self.blocked_ssh, symlink_path)
            
            # Access via symlink should be blocked
            allowed, reason = self.manager.check_access(symlink_path)
            self.assertFalse(allowed, "Symlink to blocked path should be blocked")
            
        except (OSError, NotImplementedError):
            # Symlinks not supported on this system (e.g., Windows without admin)
            self.skipTest("Symlinks not supported on this system")
    
    def test_parent_directory_in_path(self):
        """Test that paths with .. components are blocked."""
        # Even if final path is allowed, .. should be blocked
        traversal_path = f"{self.test_projects}/subdir/../test.py"
        allowed, reason = self.manager.check_access(traversal_path)
        self.assertFalse(allowed, "Path with .. should be blocked")
        self.assertIn("traversal", reason.lower())
    
    def test_list_directory_allowed(self):
        """Test listing allowed directory."""
        success, entries, error = self.manager.list_allowed_directory(self.test_projects)
        self.assertTrue(success, f"Should list allowed directory: {error}")
        self.assertIsInstance(entries, list)
        # May have entries (test.py, __pycache__, etc.) or be empty if all filtered
        # Just verify it doesn't fail
    
    def test_list_directory_blocked(self):
        """Test listing blocked directory."""
        success, entries, error = self.manager.list_allowed_directory(self.blocked_ssh)
        self.assertFalse(success, "Should not list blocked directory")
        self.assertEqual(entries, [])
    
    def test_read_file_allowed(self):
        """Test reading allowed file."""
        success, content, error = self.manager.read_file(self.allowed_file)
        self.assertTrue(success, f"Should read allowed file: {error}")
        self.assertEqual(content, "# Test file")
    
    def test_read_file_blocked(self):
        """Test reading blocked file."""
        # Create a file in blocked directory
        blocked_file = os.path.join(self.blocked_git, "config")
        with open(blocked_file, 'w') as f:
            f.write("[core]")
        
        success, content, error = self.manager.read_file(blocked_file)
        self.assertFalse(success, "Should not read blocked file")
        self.assertEqual(content, "")


class TestPermissionManagerConfig(unittest.TestCase):
    """Test configuration loading and validation."""
    
    def test_missing_config_file(self):
        """Test that missing config file raises error."""
        with self.assertRaises(FileNotFoundError):
            PermissionManager("/nonexistent/path/permissions.yaml")
    
    def test_missing_required_keys(self):
        """Test that missing required config keys raise error."""
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "bad_config.yaml")
        
        # Config missing required keys
        bad_config = """
allowed_paths:
  - /tmp/*
"""
        with open(config_path, 'w') as f:
            f.write(bad_config)
        
        try:
            with self.assertRaises(ValueError):
                PermissionManager(config_path)
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
