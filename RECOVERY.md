# Anchor — Break-Glass Recovery

Keep this file. It's the way out if you ever *really* need to disable Anchor before its lock
timer finishes.

You will need to be an administrator on the PC (you are, on your own machine).

---

## First: the automatic safety net

You may not need to do anything. While blocking is on, Anchor verifies every 30 seconds that
ordinary HTTPS still works — a real TLS handshake to neutral infrastructure, by IP address, so
the check still works even if DNS is the thing that's broken. If that fails for ~90 seconds,
Anchor **turns blocking off by itself**, logs why, and backs off before retrying. Anchor is
built to fail *open*: a missed block is always better than an unusable computer.

Check `C:\ProgramData\Anchor\anchor.log` to see whether this happened.

**There is deliberately no manual "off" switch.** By design, the only way out of an active
lock is Safe Mode (below) — anything easier would make the commitment meaningless.

> **Known limit, stated honestly:** the automatic check detects a *total* loss of connectivity.
> If Anchor ever broke only *part* of your networking (one browser, one protocol) while the
> machine was otherwise online, the watchdog would not notice, and Safe Mode below is your
> route out. This happened once, on 2026-08-01, and the cause was fixed — Anchor now only ever
> blocks the YouTube/Reddit domains listed in `src/Blocklist.cs` and never touches DNS or other
> infrastructure.

---

## Option A — Just wait

The lock only counts time while your PC is on and Anchor is running, and it's capped at
**7 days** per lock. Doing nothing is always a valid, safe exit.

---

## Option B — Safe Mode removal (the real escape hatch)

1. **Boot into Safe Mode:**
   - Settings → System → Recovery → **Advanced startup** → *Restart now*, **or** hold
     **Shift** while clicking Restart.
   - Then: **Troubleshoot → Advanced options → Startup Settings → Restart**, and press
     **4** (Safe Mode) or **5** (Safe Mode with Networking).

2. In Safe Mode, open **PowerShell as administrator** and run these commands. They restore
   normal permissions, stop and delete both services, and remove the block:

   ```powershell
   # Restore normal service permissions (undo the hardening)
   $sd = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
   sc.exe sdset Anchor $sd
   sc.exe sdset AnchorGuardian $sd

   # Stop and delete both services
   sc.exe stop AnchorGuardian; sc.exe stop Anchor
   sc.exe delete AnchorGuardian; sc.exe delete Anchor

   # Clear the saved lock timer (file + registry)
   Remove-Item "C:\ProgramData\Anchor\state.dat" -ErrorAction SilentlyContinue
   reg delete "HKLM\SOFTWARE\Anchor" /f 2>$null
   ```

3. **Clean the hosts file** (removes the backup block layer). Open
   `C:\Windows\System32\drivers\etc\hosts` in Notepad (as admin) and delete everything
   between the lines:

   ```
   # ANCHOR-START ...
   ...
   # ANCHOR-END
   ```

4. (Optional) Delete the program folder: `C:\Program Files\Anchor`.

5. **Reboot** back into normal Windows. Anchor is gone.

---

## Notes

- If `sc.exe sdset` ever says *access denied*, you're not fully elevated — reopen PowerShell
  with **Run as administrator**, or make sure you're actually in Safe Mode (the services must
  be stopped, which Safe Mode guarantees).
- This procedure is intentionally documented. "Hard to remove" here means *high friction*,
  not *impossible* — that guardrail is what keeps the tool from ever bricking a machine you
  need for schoolwork.

#RUN THESE COMMANDS (DO NOT DELETE)
reg load HKLM\OfflineSystem C:\Windows\System32\config\SYSTEM
reg delete HKLM\OfflineSystem\ControlSet001\Services\Anchor /f
reg delete HKLM\OfflineSystem\ControlSet001\Services\AnchorGuardian /f
reg unload HKLM\OfflineSystem
del "C:\ProgramData\Anchor\state.dat"
rmdir /s /q "C:\Program Files\Anchor"
reg load HKLM\OfflineSoftware C:\Windows\System32\config\SOFTWARE
reg delete HKLM\OfflineSoftware\Anchor /f
reg unload HKLM\OfflineSoftware
notepad C:\Windows\System32\drivers\etc\hosts
exit
