# Mobile Agent PC

WebSocket server for controlling local AI coding agents from mobile devices.

## Project Overview

This project provides a WebSocket server that runs on your PC and allows mobile devices to:
- Connect to local AI coding agents
- Send/receive messages in real-time
- View agent reasoning and logs
- Execute remote commands (future)

**Milestone 1 Status:** ✅ Complete — Core WebSocket communication working

---

## Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment (requires python3-venv package)
python3 -m venv .venv

# Install dependencies
.venv/bin/pip install -r requirements.txt
```

### 2. Run the Server

```bash
cd /home/noahsr/projects/mobile-agent-pc
.venv/bin/python main.py
```

Server starts on: `ws://127.0.0.1:8765`

### 3. Open the Test Client

**Option A: Direct file in browser**
```bash
firefox test-client.html
# or
google-chrome test-client.html
```

**Option B: Drag and drop**
- Open your browser
- Drag `test-client.html` into the browser window

### 4. Connect

1. Click **Connect** button in the test client
2. Default token: `mvp-secret-token-123`
3. Status should show "Connected" (green)
4. Type a message and click **Send**
5. Server responds with echo

---

## Configuration

Edit `config.py` to change settings:

```python
AUTH_TOKEN = "mvp-secret-token-123"  # Change for production!
HOST = "127.0.0.1"                    # Bind address
PORT = 8765                           # WebSocket port
```

---

## API Endpoints

### WebSocket: `/ws`

**Connection:**
```
ws://127.0.0.1:8765/ws?token=<AUTH_TOKEN>
```

**Message Format:**
- Send: Plain text
- Receive: Plain text (echo for now)

### HTTP: `/ping`

**Health Check:**
```bash
curl http://127.0.0.1:8765/ping
# Response: {"status": "ok"}
```

---

## Project Structure

```
mobile-agent-pc/
├── main.py              # FastAPI WebSocket server
├── config.py            # Configuration (token, port, host)
├── requirements.txt     # Python dependencies
├── test-client.html     # Browser test client
├── README.md            # This file
├── TASKS.md             # Project task board
├── .gitignore           # Git ignore rules
└── .venv/               # Virtual environment (not in git)
```

---

## Development

### Run Tests

```bash
# Test server health
curl http://127.0.0.1:8765/ping

# Test WebSocket connection
# Open test-client.html in browser
```

### Add New Features

1. Check `TASKS.md` for backlog items
2. Move task to "In Progress"
3. Implement feature
4. Test and verify
5. Move to "Done"

---

## Security Notes

⚠️ **Current setup is for local development only:**

- Auth token is hardcoded (change in production)
- No encryption (use WSS for production)
- Localhost only (no external access)
- No rate limiting

**For production:**
- Use environment variables for secrets
- Enable WSS (WebSocket Secure)
- Add reverse proxy (nginx)
- Implement rate limiting
- Add proper authentication system

---

## Roadmap

### Phase 1: Core Communication ✅
- [x] WebSocket server
- [x] Auth middleware
- [x] Test client
- [ ] Mobile PWA

### Phase 2: Remote Operations
- [ ] File browser
- [ ] Code diff viewer
- [ ] Remote command execution

### Phase 3: Multi-Agent
- [ ] Agent orchestration
- [ ] Task scheduling
- [ ] Push notifications

---

## Troubleshooting

### "python3-venv not found"
```bash
sudo apt install -y python3.12-venv
```

### "Port already in use"
```bash
# Check what's using port 8765
lsof -i :8765

# Or change port in config.py
```

### "Connection refused"
- Make sure server is running
- Check firewall settings
- Verify host is `127.0.0.1` (not `localhost`)

---

## License

MIT License - See LICENSE file for details.
