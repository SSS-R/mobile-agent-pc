from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from pydantic import BaseModel
from config import AUTH_TOKEN, PORT, HOST
import logging
import os
from pathlib import Path
from typing import List, Optional

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


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
