# Demo Checklist — Mobile Agent PC

## Pre-Demo Setup

- [ ] Backend server running on port 8765
- [ ] Permissions configured for `/home/noahsr/projects`
- [ ] Auth token generated and saved

## End-to-End Flow Test

### 1. Dashboard Screen
- [ ] Server status shows "Online" (green indicator)
- [ ] Latency displays in milliseconds
- [ ] Refresh button updates latency
- [ ] Quick action cards visible

### 2. File Browser Screen
- [ ] Can navigate to `/home/noahsr/projects`
- [ ] Directory entries show with folder icon
- [ ] File entries show with file icon and size
- [ ] Clicking folder navigates into it
- [ ] Breadcrumb navigation works
- [ ] Clicking file opens file viewer
- [ ] File content displays correctly
- [ ] Back button returns to file list

### 3. Command Preview Screen
- [ ] Can type command in textarea
- [ ] Preview button validates command
- [ ] Allowed commands show green "Allowed" status
- [ ] Denied commands show red "Denied" status
- [ ] Safety analysis displays all fields
- [ ] Clear button resets the form

## Error States

- [ ] Offline state shows when backend unreachable
- [ ] Error banners display meaningful messages
- [ ] Empty directories show "This folder is empty"
- [ ] Invalid commands show validation errors

## Performance

- [ ] Dashboard loads in < 2 seconds
- [ ] File navigation feels responsive
- [ ] Command preview returns in < 1 second

## Security

- [ ] Blocked paths (.ssh, .git, /etc, /root) return 403
- [ ] Path traversal (..) is rejected
- [ ] Dangerous commands (rm, sudo, bash) are denied
- [ ] Auth token required for all endpoints

## Known Issues

None at this time.

---

**Last Verified:** 2026-03-15
**Status:** ✅ Demo Ready
