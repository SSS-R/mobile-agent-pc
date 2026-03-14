# Dependencies

## Core Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `fastapi` | 0.135.1 | Web framework for building WebSocket APIs |
| `uvicorn` | 0.41.0 | ASGI server to run FastAPI application |

---

## Dependency Details

### FastAPI (0.135.1)

**Purpose:** Modern web framework for building APIs with WebSocket support.

**Why We Use It:**
- Built-in WebSocket endpoint support (`@app.websocket`)
- Automatic request/response validation
- Async/await support for concurrent connections
- Easy-to-use decorator-based routing

**Key Features Used:**
- `@app.websocket("/ws")` — WebSocket route decorator
- `WebSocket` class — Connection management
- `WebSocketDisconnect` — Exception handling

**Documentation:** https://fastapi.tiangolo.com/

---

### Uvicorn (0.41.0)

**Purpose:** ASGI server that runs the FastAPI application.

**Why We Use It:**
- High-performance ASGI server
- Built for async Python applications
- Simple command-line interface
- Production-ready with worker support

**How We Run It:**
```bash
.venv/bin/python main.py
# Which calls: uvicorn.run(app, host=HOST, port=PORT)
```

**Documentation:** https://www.uvicorn.org/

---

## Transitive Dependencies

Installed automatically by pip:

| Library | Purpose |
|---------|---------|
| `starlette` | ASGI framework (FastAPI dependency) |
| `pydantic` | Data validation and settings management |
| `typing-extensions` | Backported type hints |
| `anyio` | Async networking library |
| `h11` | HTTP/1.1 protocol library |
| `click` | Command-line interface (Uvicorn dependency) |
| `annotated-doc` | Documentation helpers |

---

## System Dependencies

### Python 3.12

**Required:** Python 3.12 or compatible version

### Python venv Package (Debian/Ubuntu)

**Required:** `python3.12-venv` package

**Why:** Debian/Ubuntu Python installations do not include the `venv` module by default.

**Install:**
```bash
sudo apt install -y python3.12-venv
```

**Error Without It:**
```
The virtual environment was not created successfully because ensurepip is not
available. On Debian/Ubuntu systems, you need to install the python3-venv package.
```

**Reference:** `[PAT-20260313-005] python-venv-debian-requirement`

---

## Installation

### Create Virtual Environment

```bash
# Requires python3.12-venv package installed first
python3 -m venv .venv
```

### Install Dependencies

```bash
.venv/bin/pip install -r requirements.txt
```

### Verify Installation

```bash
.venv/bin/python -c "import fastapi; import uvicorn; print('OK')"
```

---

## Version Constraints

Current `requirements.txt`:
```
fastapi>=0.100.0
uvicorn>=0.23.0
```

**Why These Versions:**
- FastAPI 0.100+ — Stable API, modern features, WebSocket improvements
- Uvicorn 0.23+ — Compatible with FastAPI 0.100+, bug fixes

**Upgrade Policy:**
- Minor version updates: Safe to upgrade
- Major version updates: Test in staging first

---

## Development Dependencies

**None currently.**

**Recommended additions:**
- `pytest` — Testing framework
- `httpx` — Async HTTP client for testing
- `pytest-asyncio` — Async test support
- `black` — Code formatter
- `flake8` — Linting

---

## Related Documentation

- `README.md` — Project overview and setup
- `ARCHITECTURE.md` — System components and data flow
- `TASKS.md` — Project task board
