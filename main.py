from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from config import AUTH_TOKEN, PORT, HOST
import logging

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

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
