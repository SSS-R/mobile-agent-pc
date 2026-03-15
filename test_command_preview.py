"""
Unit Tests for Command Preview API (Phase 2C.2)

Tests cover:
- Valid command preview
- Denied command preview
- Shell character detection
- Path traversal detection
- Safety analysis accuracy
"""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient
from main import app


class TestCommandPreviewAPI(unittest.TestCase):
    """Test cases for /command/preview endpoint."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
    
    def test_preview_allowed_command(self):
        """Test preview of an allowed command."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "ls -la /home"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'ls')
        self.assertIn('-la', data['arguments'])
        self.assertTrue(data['is_valid'])
        self.assertTrue(data['is_allowed'])
    
    def test_preview_denied_command(self):
        """Test preview of a denied command."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "rm -rf /"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'rm')
        self.assertFalse(data['is_allowed'])
        self.assertIn('denied', data['reason'].lower())
    
    def test_preview_shell_injection(self):
        """Test preview detects shell injection attempts."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "ls | grep test"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertFalse(data['is_valid'])
        self.assertTrue(data['safety_analysis']['shell_characters_detected'])
    
    def test_preview_path_traversal(self):
        """Test preview detects path traversal."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "cat ../../../etc/passwd"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertFalse(data['is_valid'])
        self.assertTrue(data['safety_analysis']['path_traversal_detected'])
    
    def test_preview_sudo_command(self):
        """Test preview of sudo command (denied)."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "sudo apt update"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'sudo')
        self.assertFalse(data['is_allowed'])
        self.assertTrue(data['safety_analysis']['command_in_denylist'])
    
    def test_preview_git_status(self):
        """Test preview of allowed git command."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "git status"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'git')
        self.assertEqual(data['arguments'], ['status'])
        self.assertTrue(data['is_allowed'])
    
    def test_preview_empty_command(self):
        """Test preview of empty command."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": ""}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertFalse(data['is_valid'])
    
    def test_preview_command_with_quotes(self):
        """Test preview of command with quoted arguments."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "grep \"hello world\" file.txt"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'grep')
        self.assertIn('hello world', data['arguments'])
    
    def test_preview_safety_analysis_complete(self):
        """Test that safety analysis includes all fields."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "ls -la"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        safety = data['safety_analysis']
        
        # Verify all expected fields exist
        self.assertIn('shell_characters_detected', safety)
        self.assertIn('path_traversal_detected', safety)
        self.assertIn('absolute_path_required', safety)
        self.assertIn('command_in_allowlist', safety)
        self.assertIn('command_in_denylist', safety)
    
    def test_preview_bash_shell_denied(self):
        """Test preview of bash command (denied)."""
        response = self.client.get(
            "/command/preview",
            params={"cmd": "bash script.sh"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data['command'], 'bash')
        self.assertFalse(data['is_allowed'])
        self.assertTrue(data['safety_analysis']['command_in_denylist'])


if __name__ == "__main__":
    unittest.main(verbosity=2)
