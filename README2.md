# Anchor — a self-binding website blocker for Windows

Anchor blocks **YouTube** and **Reddit** across *every* browser and desktop app, and
makes itself **hard to turn off** until a timer you set expires. It's a commitment
device for your own focus — like Cold Turkey or Freedom, but small and fully yours.

---

## For you (the person using it) — setup in 3 steps

1. **Build it once** (see "Building" below) — or if you were handed a `dist\Anchor`
   folder, skip to step 2.
2. Right-click **`Anchor.exe`** → **Run as administrator**. (It won't run without admin —
   it needs that to filter the network and manage its service.)
3. In the window, choose a duration and click **Start Lock**. That's it — blocking
   begins within a few seconds and keeps working even after you close the window or reboot.

The folder you run must contain **three files together**:
`Anchor.exe`, `WinDivert.dll`, `WinDivert64.sys`.

---

## How it works (plain version)

- A tiny **background service** watches your network connections. When something tries to
  reach YouTube or Reddit, it quietly drops the connection. Because this happens *below*
  the apps, it works for Chrome, Edge, Firefox, Electron apps — everything at once.
- To stay light on CPU/battery, it inspects only the **first "hello" packet** of each secure
  connection (the one carrying the site name) and ignores all bulk upload/download traffic.
- It reads the site name from the **TLS "hello"** (the `SNI` field), which is visible even
  when your browser uses encrypted DNS (DoH). So the usual DoH bypass doesn't work here.
- It also drops matching **DNS lookups** and adds **hosts-file** entries as a cheap backup layer.
- A **second "guardian" service** restarts the blocker if it ever gets killed, and the
  blocker restarts the guardian — a mutual watchdog. Both auto-start at boot and
  auto-restart on failure.

## The lock (why it's hard to quit)

- The countdown measures **active running time**, tracked with a monotonic timer.
  **Changing your system clock does nothing** — you can't skip the lock by moving time forward.
- While locked, the services are **hardened**: `net stop`, Services.msc, and Task Manager
  can't stop them, and the app refuses to uninstall.
- The lock timer is stored **encrypted** (DPAPI) in two places, so deleting one copy
  won't unlock you.
- **Safety caps**: no single lock can exceed **7 days**, and **Safe Mode always disables
  everything** — so you can never truly lock yourself out. See `RECOVERY.md`.

## Honest limitations (by design)

You are an administrator on your own PC, so this is **friction, not an unbreakable wall** —
that's the point, and it's what makes it safe:

- A determined admin can boot into **Safe Mode** and remove it (this is the intended escape hatch).
- The block relies on the site name (`SNI`) being visible. A future browser feature,
  **Encrypted ClientHello (ECH)**, would hide it; if you ever enable ECH, SNI blocking weakens.
  (The DNS + hosts layers still apply.)
- The video-CDN domain `googlevideo.com` is blocked, which is YouTube-specific; it won't
  affect Google Search, Gmail, Docs, etc.

## Changing what's blocked

Edit the list in [`src/Blocklist.cs`](src/Blocklist.cs) (`DefaultDomains`) and rebuild.
Matching is by domain **and its subdomains**, so `youtube.com` also covers `m.youtube.com`.

---

## Building

You only need this once. From a normal PowerShell window (no admin required to build):

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```

The script installs the .NET SDK if missing, downloads WinDivert, and produces a ready-to-run
folder at **`dist\Anchor\`**. Then run `dist\Anchor\Anchor.exe` as administrator.

### Project layout

| File | What it is |
|------|------------|
| `src/Program.cs` | Entry point; picks GUI / service / guardian mode |
| `src/MainForm.cs` | The window you interact with |
| `src/Blocklist.cs` | **What gets blocked** (edit here) + the matching rule |
| `src/PacketParser.cs` | Reads the hostname (SNI / DNS) out of a raw packet |
| `src/FilterEngine.cs` | The WinDivert loop: receive → decide → drop or pass |
| `src/WinDivert.cs` | Minimal wrapper around the WinDivert driver |
| `src/HostsFile.cs` | Secondary hosts-file block layer |
| `src/LockState.cs` | The tamper-resistant lock timer |
| `src/ServiceHost.cs` | The two Windows services + their worker loop |
| `src/ServiceControl.cs` | Install / uninstall / harden (all via `sc.exe`) |
| `src/AppPaths.cs`, `src/Log.cs` | Where files live; simple logging |

Log file (handy for seeing what the service did): `C:\ProgramData\Anchor\anchor.log`.
