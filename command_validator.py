"""
Command Validator for Mobile Agent PC

Validates and parses command requests against allowlist/denylist configuration.
Security-first design: default-deny, explicit allowlist only.

This module does NOT execute commands - it only validates them.
"""

import os
import re
import shlex
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CommandValidator:
    """
    Validates command requests against security configuration.
    
    Security features:
    - Default-deny policy
    - Explicit allowlist
    - Hard denylist
    - Argument restrictions
    - Path restrictions
    - Output restrictions
    """
    
    def __init__(self, config_path: str = "commands.yaml"):
        """
        Initialize command validator with config file.
        
        Args:
            config_path: Path to commands.yaml configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
    def _load_config(self) -> dict:
        """Load and validate configuration file."""
        if not self.config_path.exists():
            logger.error(f"Command config not found: {self.config_path}")
            raise FileNotFoundError(f"Command config not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required sections
        required = ['default_policy', 'allowed_commands', 'denied_commands']
        for key in required:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")
        
        logger.info(f"Loaded command config from {self.config_path}")
        return config
    
    def parse_command(self, command_string: str) -> Tuple[Optional[str], List[str], str]:
        """
        Parse command string into command and arguments.
        
        Security measures:
        - No shell interpolation (no $, `, |, ;, etc.)
        - No command chaining
        - No redirections
        
        Args:
            command_string: Command string to parse (e.g., "ls -la /path")
            
        Returns:
            Tuple of (command, args, error_message)
            
        Raises:
            ValueError: If command contains dangerous shell characters
        """
        # Check for dangerous shell characters
        dangerous_chars = ['|', ';', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\\', '\n', '\r']
        for char in dangerous_chars:
            if char in command_string:
                return None, [], f"Dangerous shell character detected: {char}"
        
        # Check for command chaining
        if '&&' in command_string or '||' in command_string:
            return None, [], "Command chaining is not allowed"
        
        # Check for redirections
        if '>' in command_string or '>>' in command_string:
            return None, [], "Output redirection is not allowed"
        
        # Parse command using shlex (handles quoted arguments safely)
        try:
            parts = shlex.split(command_string)
        except ValueError as e:
            return None, [], f"Invalid command syntax: {e}"
        
        if not parts:
            return None, [], "Empty command"
        
        command = parts[0]
        args = parts[1:]
        
        return command, args, ""
    
    def is_command_allowed(self, command: str, args: List[str] = None) -> Tuple[bool, str]:
        """
        Check if a command is allowed by the allowlist/denylist.
        
        Args:
            command: Command name (e.g., "ls", "git")
            args: Command arguments (optional)
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        if args is None:
            args = []
        
        allowed_commands = self.config.get('allowed_commands', [])
        denied_commands = self.config.get('denied_commands', [])
        
        # Check denylist first (takes precedence)
        if command in denied_commands:
            return False, f"Command '{command}' is explicitly denied"
        
        # Check for denied subcommands (e.g., git push)
        for denied_cmd in denied_commands:
            if command.startswith(denied_cmd + ' '):
                return False, f"Command '{command}' is explicitly denied"
        
        # Check allowlist
        if command in allowed_commands:
            # Check argument restrictions
            arg_restrictions = self.config.get('argument_restrictions', {}).get(command, {})
            blocked_args = arg_restrictions.get('blocked_args', [])
            
            for arg in args:
                if arg in blocked_args:
                    return False, f"Argument '{arg}' is blocked for command '{command}'"
            
            return True, f"Command '{command}' is allowed"
        
        # Check for allowed subcommands (e.g., git status)
        full_command = f"{command} {args[0]}" if args else command
        if full_command in allowed_commands:
            return True, f"Command '{full_command}' is allowed"
        
        # Default deny
        return False, f"Command '{command}' is not in allowlist"
    
    def validate_command(self, command_string: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Fully validate a command request.
        
        Checks:
        1. Parse command (no shell interpolation)
        2. Check allowlist/denylist
        3. Check argument restrictions
        4. Check path restrictions
        
        Args:
            command_string: Full command string (e.g., "ls -la /path")
            
        Returns:
            Tuple of (is_valid, reason, parsed_command_info)
        """
        # Step 1: Parse command
        command, args, parse_error = self.parse_command(command_string)
        
        if parse_error:
            return False, parse_error, {}
        
        # Step 2: Check allowlist/denylist
        allowed, allow_reason = self.is_command_allowed(command, args)
        
        if not allowed:
            return False, allow_reason, {'command': command, 'args': args}
        
        # Step 3: Check path restrictions
        path_restrictions = self.config.get('path_restrictions', {}).get('all_commands', {})
        
        if path_restrictions.get('require_absolute_paths', False):
            for arg in args:
                if arg.startswith('/') and not os.path.isabs(arg):
                    return False, "Relative paths are not allowed", {'command': command, 'args': args}
        
        if path_restrictions.get('block_parent_traversal', False):
            for arg in args:
                if '..' in arg:
                    return False, "Parent directory traversal (..) is not allowed", {'command': command, 'args': args}
        
        # Command is valid
        return True, "Command validated successfully", {
            'command': command,
            'args': args,
            'full_command': command_string
        }
    
    def get_allowed_commands(self) -> List[str]:
        """Get list of all allowed commands."""
        return self.config.get('allowed_commands', [])
    
    def get_denied_commands(self) -> List[str]:
        """Get list of all denied commands."""
        return self.config.get('denied_commands', [])
    
    def get_output_restrictions(self) -> Dict[str, Any]:
        """Get output restriction settings."""
        return self.config.get('output_restrictions', {})
    
    def get_audit_config(self) -> Dict[str, Any]:
        """Get audit logging configuration."""
        return self.config.get('audit', {})


# Convenience functions for direct use

_validator: Optional[CommandValidator] = None

def get_validator() -> CommandValidator:
    """Get or create singleton command validator."""
    global _validator
    if _validator is None:
        _validator = CommandValidator()
    return _validator

def validate_command(command_string: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate a command request."""
    return get_validator().validate_command(command_string)

def is_command_allowed(command: str, args: List[str] = None) -> Tuple[bool, str]:
    """Check if a command is allowed."""
    return get_validator().is_command_allowed(command, args)

def parse_command(command_string: str) -> Tuple[Optional[str], List[str], str]:
    """Parse command string into command and arguments."""
    return get_validator().parse_command(command_string)


if __name__ == "__main__":
    # Test the command validator
    print("Testing Command Validator...")
    validator = CommandValidator()
    
    # Test cases
    test_commands = [
        "ls -la /home/noahsr/projects",
        "cat file.txt",
        "git status",
        "rm -rf /",  # Should be denied
        "sudo apt update",  # Should be denied
        "bash",  # Should be denied
        "ls | grep test",  # Should be denied (pipe)
        "cat file.txt > output.txt",  # Should be denied (redirection)
    ]
    
    for cmd in test_commands:
        valid, reason, info = validator.validate_command(cmd)
        status = "✅ ALLOW" if valid else "❌ DENY"
        print(f"{status}: {cmd}")
        print(f"   Reason: {reason}")
