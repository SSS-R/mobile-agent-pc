# Project Task Board

## Milestone 1: "Hello WebSocket"

**Goal:** Prove bidirectional communication between PC and phone.

**Success Criteria:**
- Server starts on `ws://127.0.0.1:8765`
- Browser connects with token
- Send message from browser → server logs it
- Server sends response → browser displays it
- Connection survives 30 seconds idle

---

## Backlog
Ideas, future improvements (not yet ready to work).

- [ ] Add reconnection logic
- [ ] Add session persistence
- [ ] Build mobile PWA UI
- [ ] Add message encryption

---

## Ready
Tasks ready to work (approved, dependencies met).

- [ ]

---

## In Progress
Currently being implemented.

- [ ] 

---

## Done
Completed tasks.

- [x] Create project directory structure
- [x] Write main.py with FastAPI WebSocket /ws endpoint
- [x] Write config.py with auth token and port settings
- [x] Write requirements.txt with dependencies
- [x] Install dependencies (pip)
- [x] Test server with wscat or browser
- [x] Create test-client.html for manual testing

---

## Notes

- Estimated time per task: 10-30 minutes
- Main uncertainty: pip install may need `--break-system-packages`
- Reuse FastAPI from test-api project if possible
