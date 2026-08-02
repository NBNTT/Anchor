# Anchor

**Simple, local, bypass-resistant, low-level app blocker.** Take back control of your time
with one click — a free blocker that works entirely on your own device.

Anchor blocks **YouTube** and **Reddit** across *every* browser and desktop app, and makes
itself **hard to turn off** until a timer you set expires. It's a commitment device for your
own focus — like Cold Turkey or Freedom, but small, local, and fully yours.

- No account, no server, no telemetry — nothing leaves your machine.
- Works below the browser, so it can't be dodged by switching browsers or using encrypted DNS.
- Open source, MIT licensed, and documented down to the escape hatch.

---

## Setup — 3 steps

1. **Build it once** (see [Building](#building)) — this produces a ready-to-run `dist\Anchor` folder.
2. Right-click **`Anchor.exe`** → **Run as administrator**. (It won't run without admin — it
   needs that to filter the network and manage its service.)
3. Choose a duration and click **Start Lock**. Blocking begins within a few seconds and keeps
   working after you close the window or reboot.

The folder you run must contain **three files together**:
`Anchor.exe`, `WinDivert.dll`, `WinDivert64.sys`.

> **Windows SmartScreen**: the build isn't code-signed, so Windows may warn on first run.
> Choose *More info → Run anyway*, or build it yourself from source (recommended).

---

## How it works

- A tiny **background service** watches outbound connections. When something tries to reach a
  blocked site, it drops the connection. Because this happens *below* the applications, it
  covers Chrome, Edge, Firefox, Electron apps — everything at once.
- It reads the site name from the **TLS ClientHello** (the `SNI` field), which stays visible
  even when the browser uses **encrypted DNS (DoH)** — so the usual DoH bypass doesn't work.
- It also covers **QUIC / HTTP-3** (UDP 443, which Chrome and Google use heavily) by decrypting
  the QUIC **Initial** packet — whose keys derive from public values in the packet itself
  ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)) — to read the same site name.
  Switching to HTTP-3 doesn't dodge the block.
- A ClientHello is often **split across several packets** (Chrome's post-quantum handshake is
  ~2 KB), so Anchor reassembles the handshake per connection before deciding. Dropping any one
  segment is enough to stop the connection.
- It drops matching **DNS lookups** and writes **hosts-file** entries as cheap backup layers,
  and while locked it asks browsers to stop using DoH via the documented **enterprise policy**
  (`DnsOverHttpsMode=off`), restoring your previous setting afterwards. Anchor never *blocks*
  DNS traffic — see the safety note below for why that matters.
- A **guardian service** restarts the blocker if it's killed, and the blocker restarts the
  guardian — a mutual watchdog. Both auto-start at boot and auto-restart on failure.
- Only handshake and DNS packets are examined; bulk traffic is passed straight through, and
  logging is throttled so a blocked site's retry storm can't bog the filter down.

## Safety — Anchor fails open, on purpose

A blocker that can break your computer is worse than no blocker. So:

- **It only ever blocks the content domains listed in `src/Blocklist.cs`.** It will not block
  DNS resolvers, time servers, updates, or certificate checks. Blocking infrastructure once
  took a browser fully offline during development — a browser with "Secure DNS" pointed at a
  specific provider does *not* fall back to system DNS — so that is now a hard rule, enforced
  by a regression test.
- **A dead-man switch.** While blocking, Anchor verifies every 30 seconds that ordinary HTTPS
  still works (a real TLS handshake to a neutral IP, so it works even if DNS is broken). If
  that fails for ~90 seconds it disables blocking automatically, logs why, and backs off.
- **A crash can't blackhole traffic.** The packet handle is always closed if the filter thread
  exits, so a bug means "traffic flows", never "traffic disappears".
- **Dry-run mode.** Create `C:\ProgramData\Anchor\DRYRUN` *before* starting a lock and that
  lock is observe-only: it logs what it would block and changes nothing. Useful for verifying
  a change safely. (Read only when a lock starts, so it can't switch off a running lock.)

## The lock — why it's hard to quit

- The countdown measures **active running time** via a monotonic timer.
  **Changing your system clock does nothing** — you can't fast-forward out of a lock.
- While locked, the services are **hardened**: `net stop`, Services.msc, and Task Manager
  can't stop them, and the app refuses to uninstall.
- The timer is stored **encrypted** (DPAPI) in two places, so deleting one copy won't unlock you.
- Locks run from **1 minute to 7 days**. You can always *extend* a lock; you can never shorten
  one, and there is deliberately no manual off switch.
- **Safety caps**: no single lock exceeds **7 days**, and **Safe Mode always disables
  everything** — you can never truly lock yourself out. See [RECOVERY.md](RECOVERY.md).

## Convenience

- **System-tray icon** with live status; closing the window hides to the tray, and blocking
  continues regardless.
- **Start at login** — one checkbox registers a Scheduled Task so the tray icon returns after
  every reboot, elevated, with no UAC prompt.
- **Auto-update** — launching a newer `Anchor.exe` refreshes the installed background service
  in place. It refuses while a lock is active (that would interrupt blocking *and* be an easy
  bypass) and never downgrades.

## Honest limitations (by design)

You are an administrator on your own PC, so this is **friction, not an unbreakable wall** —
that's the point, and it's what keeps it safe:

- A determined admin can boot into **Safe Mode** and remove it. This is the *intended* escape
  hatch, and it's why Anchor never touches the boot process or marks itself a critical process.
- Blocking relies on the site name being visible. **Encrypted ClientHello (ECH)** would hide it;
  if ECH becomes enabled in your browser, SNI-based blocking weakens (DNS + hosts layers remain).
- QUIC coverage targets **QUIC v1** (what browsers use today). The rarely-deployed v2 falls
  through to the DNS/hosts layers.
- `googlevideo.com` is blocked (YouTube's video CDN). This is YouTube-specific and does not
  affect Google Search, Gmail, or Docs.

## Changing what's blocked

Edit `DefaultDomains` in [`src/Blocklist.cs`](src/Blocklist.cs) and rebuild. Matching covers a
domain **and its subdomains**, so `youtube.com` also covers `m.youtube.com` — while
`youtubei.googleapis.com` can be blocked without affecting the rest of `googleapis.com`.

---

## Building

From a normal PowerShell window (no admin needed to *build*):

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

The script installs the .NET SDK if missing, downloads [WinDivert](https://reqrypt.org/windivert.html),
publishes a single self-contained `Anchor.exe` (no .NET install needed to *run* it), and assembles
**`dist\Anchor\`** plus a Desktop shortcut. Then run `dist\Anchor\Anchor.exe` as administrator.

**Requirements:** Windows 10/11 x64, and administrator rights to run.

### Project layout

| File | What it is |
|------|------------|
| `src/Program.cs` | Entry point; picks GUI / tray / service / guardian mode |
| `src/MainForm.cs` | The window and tray icon |
| `src/Blocklist.cs` | **What gets blocked** (edit here) + the matching rule |
| `src/PacketParser.cs` | Reads the hostname (TLS SNI / DNS) out of a raw packet |
| `src/QuicParser.cs` | Decrypts QUIC Initial packets to read the SNI (RFC 9001) |
| `src/FilterEngine.cs` | The WinDivert loop: receive → decide → drop or pass |
| `src/WinDivert.cs` | Minimal wrapper around the WinDivert driver |
| `src/HostsFile.cs` | Secondary hosts-file block layer |
| `src/LockState.cs` | The tamper-resistant lock timer |
| `src/ServiceHost.cs` | The two Windows services + their worker loop |
| `src/ServiceControl.cs` | Install / uninstall / harden / auto-update (via `sc.exe`) |
| `src/StartupTask.cs` | The "start at login" Scheduled Task |
| `src/DohPolicy.cs` | Turns browser DoH off via policy (and puts it back) |
| `src/NetworkHealth.cs` | The dead-man switch that makes Anchor fail open |
| `src/AppPaths.cs`, `src/Log.cs` | Where files live; simple logging |

Log file (useful for seeing what the service did): `C:\ProgramData\Anchor\anchor.log`.

### Third-party

Anchor uses [WinDivert](https://reqrypt.org/windivert.html) (LGPLv3 / GPLv2), downloaded at
build time and not redistributed in this repository.

## License

[MIT](LICENSE).

> Anchor is a self-control tool for your own computer. It's designed to be removable by the
> machine's owner (see [RECOVERY.md](RECOVERY.md)) and is not intended for monitoring or
> restricting anyone else.
