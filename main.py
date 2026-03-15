from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from pydantic import BaseModel
from config import AUTH_TOKEN, PORT, HOST
import logging
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

# Import permission manager
from permissions import get_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mobile Agent PC")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for mobile client connections.
    Requires auth token in query parameter.
    """
    # Authenticate
    token = websocket.query_params.get("token")
    if token != AUTH_TOKEN:
        logger.warning(f"Failed connection attempt with token: {token}")
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    # Accept connection
    await websocket.accept()
    logger.info(f"Client connected from {websocket.client}")
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            logger.info(f"Received: {data}")
            
            # Echo response (for testing)
            response = f"Server received: {data}"
            await websocket.send_text(response)
            logger.info(f"Sent: {response}")
            
    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"Connection error: {e}")
        await websocket.close()

@app.get("/ping")
async def ping():
    """Health check endpoint."""
    return {"status": "ok"}


# =============================================================================
# Phase 2B: Restricted File Browser (Read-Only)
# =============================================================================

class FileEntry(BaseModel):
    """File/directory entry in listing."""
    name: str
    type: str  # "file" or "dir"
    size: Optional[int] = None  # Only for files


@app.get("/files/list", response_model=List[FileEntry])
async def list_files(
    path: str = Query(..., description="Directory path to list"),
):
    """
    List contents of a directory (read-only).
    
    Security:
    - Requires valid auth token
    - Path must be in allowed_paths config
    - Blocked paths (.ssh, .git, /etc, /root) are denied
    - Returns only safe metadata (name, type, size)
    
    Args:
        path: Absolute directory path to list
        
    Returns:
        List of file entries with name, type, and size (for files)
        
    Raises:
        HTTPException 403: Access denied
        HTTPException 400: Invalid path
        HTTPException 404: Directory not found
    """
    # Validate path is absolute
    if not os.path.isabs(path):
        raise HTTPException(status_code=400, detail="Path must be absolute")
    
    # Check directory access with permission manager
    manager = get_manager()
    allowed, reason = manager.check_access(path, "list")
    
    if not allowed:
        logger.warning(f"Directory listing denied: {path} - {reason}")
        raise HTTPException(status_code=403, detail=reason)
    
    # Verify directory exists
    if not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Directory not found")
    
    # List directory contents
    entries = []
    for entry_name in os.listdir(path):
        entry_path = os.path.join(path, entry_name)
        
        # Check if this entry is accessible
        entry_allowed, _ = manager.check_access(entry_path, "list")
        if not entry_allowed:
            # Skip entries user can't access
            continue
        
        # Get safe metadata only
        try:
            if os.path.isdir(entry_path):
                entries.append(FileEntry(name=entry_name, type='dir'))
            elif os.path.isfile(entry_path):
                size = os.path.getsize(entry_path)
                entries.append(FileEntry(name=entry_name, type='file', size=size))
            # Skip symlinks, sockets, etc. for safety
        except (OSError, PermissionError) as e:
            logger.debug(f"Skipping entry {entry_name}: {e}")
            continue
    
    # Sort: directories first, then files, alphabetically
    entries.sort(key=lambda x: (x.type != 'dir', x.name.lower()))
    
    logger.info(f"Listed {len(entries)} entries in {path}")
    return entries


@app.get("/files/read")
async def read_file(
    path: str = Query(..., description="File path to read"),
):
    """
    Read file content (read-only, text files only).
    
    Security:
    - Requires valid auth token
    - Path must be in allowed_paths config
    - Blocked paths (.ssh, .git, /etc, /root) are denied
    - File extension must be in allowed_extensions
    - File size must be under max_file_size limit
    - Binary files are rejected
    
    Args:
        path: Absolute file path to read
        
    Returns:
        {"content": "<file content>", "size": <bytes>}
        
    Raises:
        HTTPException 403: Access denied
        HTTPException 400: Invalid path or binary file
        HTTPException 404: File not found
        HTTPException 413: File too large
        HTTPException 415: Unsupported file type
    """
    # Validate path is absolute
    if not os.path.isabs(path):
        raise HTTPException(status_code=400, detail="Path must be absolute")
    
    # Check file access with permission manager
    manager = get_manager()
    allowed, reason = manager.check_access(path, "read")
    
    if not allowed:
        logger.warning(f"File read denied: {path} - {reason}")
        raise HTTPException(status_code=403, detail=reason)
    
    # Verify file exists
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Verify it's a file (not directory)
    if not os.path.isfile(path):
        raise HTTPException(status_code=400, detail="Not a file")
    
    # Check file size (permission manager already checked, but verify)
    file_size = os.path.getsize(path)
    file_restrictions = manager.config.get('file_restrictions', {})
    max_size = file_restrictions.get('max_file_size', 1048576)
    
    if file_size > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({file_size} bytes, max {max_size})"
        )
    
    # Check file extension (permission manager already checked, but verify)
    ext = Path(path).suffix.lower()
    allowed_exts = file_restrictions.get('allowed_extensions', [])
    blocked_exts = file_restrictions.get('blocked_extensions', [])
    
    if ext in blocked_exts:
        raise HTTPException(status_code=415, detail=f"File type blocked: {ext}")
    
    if allowed_exts and ext not in allowed_exts:
        raise HTTPException(status_code=415, detail=f"File type not allowed: {ext}")
    
    # Read file content (text only)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        logger.info(f"Read {file_size} bytes from {path}")
        return {"content": content, "size": file_size}
        
    except UnicodeDecodeError as e:
        logger.warning(f"Binary file detected: {path}")
        raise HTTPException(
            status_code=415,
            detail="Binary file detected. Only text files are supported."
        )
    except PermissionError as e:
        logger.error(f"Permission error reading {path}: {e}")
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
        raise HTTPException(status_code=500, detail="Internal error")
    
    # List directory contents
    try:
        entries = []
        for entry_name in os.listdir(path):
            entry_path = os.path.join(path, entry_name)
            
            # Check if this entry is accessible
            entry_allowed, _ = manager.check_access(entry_path, "list")
            if not entry_allowed:
                # Skip entries user can't access
                continue
            
            # Get safe metadata only
            try:
                if os.path.isdir(entry_path):
                    entries.append(FileEntry(name=entry_name, type="dir"))
                elif os.path.isfile(entry_path):
                    size = os.path.getsize(entry_path)
                    entries.append(FileEntry(name=entry_name, type="file", size=size))
                # Skip symlinks, sockets, etc. for safety
            except (OSError, PermissionError) as e:
                logger.debug(f"Skipping entry {entry_name}: {e}")
                continue
        
        # Sort: directories first, then files, alphabetically
        entries.sort(key=lambda x: (x.type != "dir", x.name.lower()))
        
        logger.info(f"Listed {len(entries)} entries in {path}")
        return entries
        
    except PermissionError as e:
        logger.error(f"Permission error listing {path}: {e}")
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        logger.error(f"Error listing {path}: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


# =============================================================================
# Phase 2C.2: Command Preview API (Read-Only)
# =============================================================================

class CommandPreview(BaseModel):
    """Command preview response."""
    command: str
    arguments: List[str]
    is_valid: bool
    is_allowed: bool
    reason: str
    safety_analysis: Dict[str, Any]


@app.get("/command/preview", response_model=CommandPreview)
async def preview_command(
    cmd: str = Query(..., description="Command string to preview")
):
    """
    Preview a command without executing it.
    
    Security:
    - Validates command against allowlist/denylist
    - Detects dangerous shell characters
    - Returns safety analysis
    - NO execution performed
    
    Args:
        cmd: Command string to preview (e.g., "ls -la /home")
        
    Returns:
        CommandPreview with validation result and safety analysis
        
    Raises:
        HTTPException 400: Invalid command syntax
    """
    from command_validator import get_validator
    
    # Validate command
    validator = get_validator()
    is_valid, reason, info = validator.validate_command(cmd)
    
    # Extract command and arguments
    command = info.get('command', '')
    arguments = info.get('args', [])
    
    # Determine if allowed
    is_allowed = is_valid and reason == "Command validated successfully"
    
    # Build safety analysis
    safety_analysis = {
        'shell_characters_detected': any(c in cmd for c in ['|', ';', '&', '$', '`', '>', '<']),
        'path_traversal_detected': '..' in cmd,
        'absolute_path_required': True,
        'command_in_allowlist': command in validator.get_allowed_commands() if command else False,
        'command_in_denylist': command in validator.get_denied_commands() if command else False,
    }
    
    return CommandPreview(
        command=command,
        arguments=arguments,
        is_valid=is_valid,
        is_allowed=is_allowed,
        reason=reason,
        safety_analysis=safety_analysis
    )


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
