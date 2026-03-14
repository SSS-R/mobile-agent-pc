"""
Unit Tests for File Read API (Phase 2B.2)

Tests cover:
- Allowed file read
- Blocked file denial
- Path traversal prevention
- Extension filtering
- File size limits
- Binary file rejection
- Missing file handling
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app
from permissions import PermissionManager


class TestFileReadAPI(unittest.TestCase):
    """Test cases for /files/read endpoint."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
        
        # Create temporary directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.test_projects = os.path.join(self.temp_dir, "test_projects")
        self.test_documents = os.path.join(self.temp_dir, "test_documents")
        self.blocked_ssh = os.path.join(self.test_projects, ".ssh")
        
        os.makedirs(self.test_projects, exist_ok=True)
        os.makedirs(self.test_documents, exist_ok=True)
        os.makedirs(self.blocked_ssh, exist_ok=True)
        
        # Create test files
        self.test_file = os.path.join(self.test_projects, "test.py")
        with open(self.test_file, 'w') as f:
            f.write("# Test file content\nprint('hello')")
        
        self.readme = os.path.join(self.test_projects, "README.md")
        with open(self.readme, 'w') as f:
            f.write("# Test Project\n\nThis is a test.")
        
        self.text_file = os.path.join(self.test_documents, "notes.txt")
        with open(self.text_file, 'w') as f:
            f.write("Some notes here")
        
        # Create blocked file
        self.blocked_file = os.path.join(self.blocked_ssh, "id_rsa")
        with open(self.blocked_file, 'w') as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----")
        
        # Create test config
        self.config_path = os.path.join(self.temp_dir, "test_permissions.yaml")
        
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
            "  - /etc",
            "  - /etc/*",
            "  - /root",
            "  - /root/*",
            "",
            "file_restrictions:",
            "  max_file_size: 1024",
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
        
        self.test_manager = PermissionManager(self.config_path)
        
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_read_allowed_file(self):
        """Test reading an allowed file."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.test_file}
            )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("content", data)
        self.assertIn("size", data)
        self.assertEqual(data["size"], len("# Test file content\nprint('hello')"))
        self.assertIn("print('hello')", data["content"])
    
    def test_read_allowed_md_file(self):
        """Test reading an allowed markdown file."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.readme}
            )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("content", data)
        self.assertIn("# Test Project", data["content"])
    
    def test_read_allowed_txt_file(self):
        """Test reading an allowed text file."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.text_file}
            )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("content", data)
        self.assertEqual(data["content"], "Some notes here")
    
    def test_read_blocked_ssh_file(self):
        """Test that reading files in .ssh is denied."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.blocked_file}
            )
        
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("blocked", detail.lower())
    
    def test_read_etc_file_denied(self):
        """Test that reading /etc files is denied."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": "/etc/passwd"}
            )
        
        self.assertEqual(response.status_code, 403)
    
    def test_read_root_file_denied(self):
        """Test that reading /root files is denied."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": "/root/.bashrc"}
            )
        
        self.assertEqual(response.status_code, 403)
    
    def test_read_missing_file(self):
        """Test that missing file returns 404."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": "/nonexistent/file.txt"}
            )
        
        self.assertIn(response.status_code, [403, 404])
    
    def test_read_relative_path_rejected(self):
        """Test that relative paths are rejected."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": "test.py"}
            )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("absolute", response.json()["detail"].lower())
    
    def test_read_path_traversal_blocked(self):
        """Test that path traversal (..) is blocked."""
        traversal_path = f"{self.test_projects}/../test_documents/notes.txt"
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": traversal_path}
            )
        
        self.assertEqual(response.status_code, 403)
        self.assertIn("traversal", response.json()["detail"].lower())
    
    def test_read_blocked_extension(self):
        """Test that blocked extensions are rejected."""
        # Create a .sh file in allowed directory
        blocked_ext_file = os.path.join(self.test_projects, "script.sh")
        with open(blocked_ext_file, 'w') as f:
            f.write("#!/bin/bash\necho hello")
        
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": blocked_ext_file}
            )
        
        # Permission manager denies blocked extensions with 403
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("extension", detail.lower())
    
    def test_read_extension_not_in_allowlist(self):
        """Test that extensions not in allowlist are rejected."""
        # Create a .exe file
        blocked_ext_file = os.path.join(self.test_projects, "program.exe")
        with open(blocked_ext_file, 'w') as f:
            f.write("binary")
        
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": blocked_ext_file}
            )
        
        # Permission manager denies disallowed extensions with 403
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("extension", detail.lower())
    
    def test_read_oversized_file(self):
        """Test that files exceeding size limit are rejected."""
        # Create a file larger than 1KB limit
        large_file = os.path.join(self.test_documents, "large.txt")
        with open(large_file, 'w') as f:
            f.write("x" * 2048)  # 2KB file
        
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": large_file}
            )
        
        # Permission manager denies oversized files with 403
        self.assertEqual(response.status_code, 403)
        detail = response.json()["detail"]
        self.assertIn("exceeds", detail.lower())
    
    def test_read_directory_not_file(self):
        """Test that reading a directory returns error."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.test_projects}
            )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("not a file", response.json()["detail"].lower())
    
    def test_read_returns_size(self):
        """Test that response includes file size."""
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": self.test_file}
            )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("size", data)
        self.assertIsInstance(data["size"], int)
        self.assertGreater(data["size"], 0)
    
    def test_read_binary_file_rejected(self):
        """Test that binary files are rejected with 415."""
        # Create a binary-like file
        binary_file = os.path.join(self.test_projects, "data.bin")
        with open(binary_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
        
        with patch('main.get_manager', return_value=self.test_manager):
            response = self.client.get(
                "/files/read",
                params={"path": binary_file}
            )
        
        # Should be rejected either by extension or content
        self.assertIn(response.status_code, [403, 415])


class TestFileReadIntegration(unittest.TestCase):
    """Integration tests with permission manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
    
    def test_permission_manager_integration(self):
        """Test that permission manager is actually used."""
        response = self.client.get(
            "/files/read",
            params={"path": "/etc/passwd"}
        )
        
        # Should be denied by permission manager
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
