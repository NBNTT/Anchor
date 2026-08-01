# Anchor — Break-Glass Recovery

Keep this file. It's the guaranteed way out if you ever *really* need to disable Anchor
before its lock timer finishes. It works because **Anchor's services do not run in Windows
Safe Mode.**

You will need to be an administrator on the PC (you are, on your own machine).

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
