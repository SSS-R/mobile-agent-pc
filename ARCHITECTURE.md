# Architecture

## System Overview

Mobile Agent PC is a WebSocket server that enables mobile devices to communicate with local AI coding agents running on a PC.

**Current Scope:** Milestone 1 — Core WebSocket communication (bidirectional messaging with authentication).

---

## System Components

```
┌─────────────────┐
│  Mobile Device  │
│   (Browser)     │
│  test-client.html│
└────────┬────────┘
         │ WebSocket Connection
         │ ws://127.0.0.1:8765/ws?token=xxx
         ▼
┌─────────────────┐
│   Uvicorn       │
│  (ASGI Server)  │
│  Port: 8765     │
└────────┬────────┘
         │ Routes WebSocket
         ▼
┌─────────────────┐
│   FastAPI App   │
│    (main.py)    │
│  @app.websocket │
└────────┬────────┘
         │ Validates Token
         ▼
┌─────────────────┐
│  Auth Middleware│
│   (config.py)   │
│  Token Check    │
└────────┬────────┘
         │ Accept/Reject
         ▼
┌─────────────────┐
│  Message Logger │
│   (console)     │
│  Logs all msgs  │
└─────────────────┘
```

---

## Components

| Component | File | Purpose |
|-----------|------|---------|
| **WebSocket Server** | `main.py` | Handles bidirectional client connections |
| **Auth Middleware** | `config.py` | Validates connection tokens |
| **ASGI Server** | Uvicorn | Runs the FastAPI application |
| **Test Client** | `test-client.html` | Browser-based WebSocket client |

---

## Data Flow

### Connection Flow

1. **Client** opens browser (`test-client.html`)
2. **Client** clicks Connect button
3. **Client** sends WebSocket handshake to `ws://127.0.0.1:8765/ws?token=<token>`
4. **Server** validates token against `AUTH_TOKEN` in `config.py`
5. **Server** accepts or rejects connection
6. **Client** displays connection status (green/red)

### Message Flow

1. **Client** types message in input field
2. **Client** clicks Send (or presses Enter)
3. **Client** sends message via WebSocket
4. **Server** receives message, logs to console
5. **Server** sends echo response
6. **Client** displays response in message log

---

## Current Scope (Milestone 1)

**Implemented:**
- ✅ WebSocket server with `/ws` endpoint
- ✅ Token-based authentication
- ✅ Bidirectional messaging
- ✅ Echo response (for testing)
- ✅ Health check endpoint (`/ping`)
- ✅ Browser test client

**Not Yet Implemented:**
- ❌ File browser
- ❌ Code diff viewer
- ❌ Remote command execution
- ❌ Multi-agent orchestration
- ❌ Mobile PWA (using browser test client for now)

---

## Network Configuration

| Setting | Value | Configurable |
|---------|-------|--------------|
| Host | `127.0.0.1` | Yes (`config.py`) |
| Port | `8765` | Yes (`config.py`) |
| Protocol | WebSocket | N/A |
| Auth | Token (query param) | Yes (`config.py`) |

---

## Future Considerations

- **WSS (WebSocket Secure)** — Required for production
- **Reverse Proxy** — nginx for load balancing
- **Session Management** — Persist connections across restarts
- **Rate Limiting** — Prevent abuse
- **Multi-client Support** — Handle multiple mobile devices
