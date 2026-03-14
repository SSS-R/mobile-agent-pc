"""
Unit Tests for File Browser API (Phase 2B.1)

Tests cover:
- Allowed directory listing
- Blocked directory denial
- Path traversal prevention
- Safe metadata only (no sensitive info)
- Integration with permissions.py
"""

import os
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app
from permissions import PermissionManager


class TestFileBrowserAPI(unittest.TestCase):
    """Test cases for /files/list endpoint."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
        
        # Create temporary directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.test_projects = os.path.join(self.temp_dir, "test_projects")
        self.test_documents = os.path.join(self.temp_dir, "test_documents")
        self.blocked_ssh = os.path.join(self.test_projects, ".ssh")
        self.blocked_git = os.path.join(self.test_projects, ".git")
        
        os.makedirs(self.test_projects, exist_ok=True)
        os.makedirs(self.test_documents, exist_ok=True)
        os.makedirs(self.blocked_ssh, exist_ok=True)
        os.makedirs(self.blocked_git, exist_ok=True)
        
        # Create test files
        self.test_file = os.path.join(self.test_projects, "test.py")
        with open(self.test_file, 'w') as f:
            f.write("# Test file")
        
        self.readme = os.path.join(self.test_projects, "README.md")
        with open(self.readme, 'w') as f:
            f.write("# Test Project")
        
        # Create test config
        self.config_path = os.path.join(self.temp_dir, "test_permissions.yaml")
        
        # Build config with proper YAML formatting
        config_lines = [
            "default_policy: deny",
            "",
            "allowed_paths:",
            f"  - {self.temp_dir}/test_projects",
            f"  - {self.temp_dir}/test_projects/*",
            f"  - {self.temp_dir}/test_documents",
            f"  - {self.temp_dir}/test_documents/*.txt",
            "",
            "blocked_paths:",
            f"  - {self.temp_dir}/test_projects/.ssh",
            f"  - {self.temp_dir}/test_projects/.ssh/*",
            f"  - {self.temp_dir}/test_projects/.git",
            f"  - {self.temp_dir}/test_projects/.git/*",
            "  - /etc",
            "  - /etc/*",
            "  - /root",
            "  - /root/*",
            "",
            "file_restrictions:",
            "  max_file_size: 1048576",
            "  allowed_extensions:",
            "    - .txt",
            "    - .md",
            "    - .py",
            "    - .json",
            "    - .yaml",
            "  blocked_extensions:",
            "    - .exe",
            "    - .sh",
            "",
            "security:",
            "  resolve_symlinks: true",
            "  block_parent_directory: true",
            "  require_absolute_paths: true",
            "  normalize_unicode: true",
            "",
            "audit:",
            "  log_all_access: false",
        ]
        
        with open(self.config_path, 'w') as f:
            f.write('\n'.join(config_lines))
        
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_list_allowed_directory(self):
        """Test listing an allowed directory."""
        # Create a test manager with our config
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.test_projects}
            )
        
        self.assertEqual(response.status_code, 200)
        entries = response.json()
        self.assertIsInstance(entries, list)
        
        # Should have test.py and README.md
        names = [e["name"] for e in entries]
        self.assertIn("test.py", names)
        self.assertIn("README.md", names)
    
    def test_list_directory_returns_safe_metadata(self):
        """Test that only safe metadata is returned."""
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.test_projects}
            )
        
        self.assertEqual(response.status_code, 200)
        entries = response.json()
        
        # Each entry should have only: name, type, size (optional)
        for entry in entries:
            self.assertIn("name", entry)
            self.assertIn("type", entry)
            self.assertIn(entry["type"], ["file", "dir"])
            
            # Files should have size
            if entry["type"] == "file":
                self.assertIn("size", entry)
                self.assertIsInstance(entry["size"], int)
                self.assertGreater(entry["size"], 0)
            
            # No sensitive metadata
            self.assertNotIn("path", entry)
            self.assertNotIn("permissions", entry)
            self.assertNotIn("owner", entry)
            self.assertNotIn("modified", entry)
    
    def test_list_blocked_ssh_directory(self):
        """Test that .ssh directory listing is denied."""
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.blocked_ssh}
            )
        
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("blocked", detail.lower())
    
    def test_list_blocked_git_directory(self):
        """Test that .git directory listing is denied."""
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.blocked_git}
            )
        
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("blocked", detail.lower())
    
    def test_list_etc_directory_denied(self):
        """Test that /etc directory listing is denied."""
        response = self.client.get(
            "/files/list",
            params={"path": "/etc"}
        )
        
        self.assertEqual(response.status_code, 403)
    
    def test_list_root_directory_denied(self):
        """Test that /root directory listing is denied."""
        response = self.client.get(
            "/files/list",
            params={"path": "/root"}
        )
        
        self.assertEqual(response.status_code, 403)
    
    def test_list_nonexistent_directory(self):
        """Test that nonexistent directory returns 404 or 403."""
        response = self.client.get(
            "/files/list",
            params={"path": "/nonexistent/path"}
        )
        
        self.assertIn(response.status_code, [403, 404])
    
    def test_list_relative_path_rejected(self):
        """Test that relative paths are rejected."""
        response = self.client.get(
            "/files/list",
            params={"path": "test_projects"}
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("absolute", response.json()["detail"].lower())
    
    def test_list_path_traversal_blocked(self):
        """Test that path traversal (..) is blocked."""
        traversal_path = f"{self.test_projects}/../test_documents"
        response = self.client.get(
            "/files/list",
            params={"path": traversal_path}
        )
        
        self.assertEqual(response.status_code, 403)
        self.assertIn("traversal", response.json()["detail"].lower())
    
    def test_list_parent_directory_in_path_blocked(self):
        """Test that paths with .. components are blocked."""
        traversal_path = f"{self.test_projects}/subdir/../test.py"
        response = self.client.get(
            "/files/list",
            params={"path": traversal_path}
        )
        
        self.assertEqual(response.status_code, 403)
    
    def test_list_directory_sorting(self):
        """Test that directories are listed before files."""
        subdir = os.path.join(self.test_projects, "subdir")
        os.makedirs(subdir, exist_ok=True)
        
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.test_projects}
            )
        
        self.assertEqual(response.status_code, 200)
        entries = response.json()
        
        # Directories should come first
        types = [e["type"] for e in entries]
        if "dir" in types and "file" in types:
            first_file_idx = types.index("file")
            last_dir_idx = len(types) - 1 - types[::-1].index("dir")
            self.assertLess(last_dir_idx, first_file_idx)
    
    def test_list_skips_inaccessible_entries(self):
        """Test that inaccessible entries are skipped, not error."""
        blocked_file = os.path.join(self.blocked_ssh, "id_rsa")
        with open(blocked_file, 'w') as f:
            f.write("secret")
        
        test_manager = PermissionManager(self.config_path)
        
        with patch('main.get_manager', return_value=test_manager):
            response = self.client.get(
                "/files/list",
                params={"path": self.test_projects}
            )
        
        self.assertEqual(response.status_code, 200)
        entries = response.json()
        
        # Should not include .ssh or its contents
        names = [e["name"] for e in entries]
        self.assertNotIn(".ssh", names)


class TestFileBrowserIntegration(unittest.TestCase):
    """Integration tests with permission manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_permission_manager_integration(self):
        """Test that permission manager is actually used."""
        response = self.client.get(
            "/files/list",
            params={"path": "/etc"}
        )
        
        # Should be denied by permission manager
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
