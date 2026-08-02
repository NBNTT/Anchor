using System.Drawing;
using System.Windows.Forms;

namespace Anchor;

/// <summary>
/// The window you see when you run Anchor.exe. It shows whether blocking is on, lets you
/// START (or EXTEND) a lock, and lets you UNINSTALL when you're not locked.
///
/// The layout is built with docked panels + a FlowLayoutPanel for the input row, so the
/// controls never overlap regardless of Windows display scaling (the old version used
/// fixed pixel positions, which is what caused the number box to be covered by text).
///
/// The GUI does NOT do the blocking itself. It just writes the lock timer; the background
/// service reads it within a few seconds and enforces it, even after you close this window.
/// </summary>
public sealed class MainForm : Form
{
    // ---- palette (kept in one place so the look is consistent) ----
    private static readonly Color Accent    = Color.FromArgb(59, 76, 202);   // indigo
    private static readonly Color CardBg     = Color.FromArgb(246, 247, 249);
    private static readonly Color BorderCol  = Color.FromArgb(223, 226, 231);
    private static readonly Color Muted      = Color.FromArgb(110, 115, 125);
    private static readonly Color ActiveRed  = Color.FromArgb(214, 45, 45);
    private static readonly Color IdleGreen  = Color.FromArgb(45, 156, 66);

    private Panel _statusStrip = null!;   // colored strip on the status card
    private Label _statusLabel = null!;
    private Label _detailLabel = null!;
    private NumericUpDown _amount = null!;
    private ComboBox _unit = null!;
    private Button _startButton = null!;
    private Button _uninstallButton = null!;
    private System.Windows.Forms.Timer _refreshTimer = null!;

    private CheckBox _startupCheck = null!;

    // ---- system tray ----
    private NotifyIcon _tray = null!;
    private ToolStripMenuItem _trayStatus = null!;
    private bool _reallyExit;       // Exit menu sets this; otherwise closing just hides to tray
    private bool _balloonShown;     // only nag once about "still running in the tray"

    // ---- start hidden (tray only) ----
    private readonly bool _startHidden;
    private bool _firstShow = true;

    /// <summary>App version, read from the assembly (single source of truth = csproj &lt;Version&gt;).</summary>
    private static readonly string AppVersion = BuildVersionString();
    private static string BuildVersionString()
    {
        var v = typeof(MainForm).Assembly.GetName().Version;
        return v == null ? "v1.0.0" : $"v{v.Major}.{v.Minor}.{v.Build}";
    }

    public MainForm(bool startHidden = false)
    {
        _startHidden = startHidden;

        BuildUi();
        TrySetWindowIcon();
        BuildTray();
        InitStartupCheck();
        EnsureInstalled();
        RefreshStatus();

        _refreshTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _refreshTimer.Tick += (_, _) => RefreshStatus();
        _refreshTimer.Start();
    }

    /// <summary>When launched with --tray, swallow the very first "show" so only the tray icon appears.</summary>
    protected override void SetVisibleCore(bool value)
    {
        if (_startHidden && _firstShow)
        {
            _firstShow = false;
            base.SetVisibleCore(false);
            return;
        }
        base.SetVisibleCore(value);
    }

    // ===================== UI layout =====================

    private void BuildUi()
    {
        Text = $"Anchor {AppVersion}";
        ClientSize = new Size(600, 588);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;
        Font = new Font("Segoe UI", 10f);
        AutoScaleMode = AutoScaleMode.Dpi;

        // ---- header band ----
        // The two lines live in a docked TableLayoutPanel (not fixed pixel positions), so the
        // text is always laid out to fit and can never be clipped by the panel edge.
        var header = new Panel { Dock = DockStyle.Top, Height = 104, BackColor = Accent };
        var headerText = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Color.Transparent,
            Padding = new Padding(24, 14, 16, 14),
        };
        headerText.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        headerText.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var title = new Label
        {
            Text = "⚓  Anchor",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 21f),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 2),
            BackColor = Color.Transparent,
        };
        var subtitle = new Label
        {
            Text = "Blocks YouTube & Reddit across every browser and app.",
            ForeColor = Color.FromArgb(214, 220, 255),
            Font = new Font("Segoe UI", 9.5f),
            AutoSize = true,
            Margin = new Padding(2, 0, 0, 0),
            BackColor = Color.Transparent,
        };
        headerText.Controls.Add(title, 0, 0);
        headerText.Controls.Add(subtitle, 0, 1);
        header.Controls.Add(headerText);

        // ---- body ----
        var body = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };

        // Status card (with a colored strip on the left that reflects on/off).
        var statusCard = MakeCard(new Point(24, 18), new Size(552, 88));
        _statusStrip = new Panel { Location = new Point(0, 0), Size = new Size(6, 88), BackColor = IdleGreen };
        _statusLabel = new Label
        {
            Font = new Font("Segoe UI Semibold", 15f),
            AutoSize = true,
            Location = new Point(22, 18),
            BackColor = Color.Transparent,
        };
        _detailLabel = new Label
        {
            Font = new Font("Segoe UI", 10f),
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(24, 52),
            BackColor = Color.Transparent,
        };
        statusCard.Controls.AddRange(new Control[] { _statusStrip, _statusLabel, _detailLabel });

        // Lock card.
        var lockCard = MakeCard(new Point(24, 122), new Size(552, 156));
        var lockTitle = new Label
        {
            Text = "Start a lock",
            Font = new Font("Segoe UI Semibold", 11f),
            AutoSize = true,
            Location = new Point(20, 14),
            BackColor = Color.Transparent,
        };
        var forLabel = new Label
        {
            Text = "Block for",
            Font = new Font("Segoe UI", 10f),
            AutoSize = true,
            Location = new Point(20, 58),
            BackColor = Color.Transparent,
        };

        // The input row lives in a FlowLayoutPanel so the number box, unit box, and button
        // are always spaced out and never overlap (this fixes the covered-box bug).
        var inputRow = new FlowLayoutPanel
        {
            Location = new Point(110, 48),
            Size = new Size(430, 46),
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
        };
        _amount = new NumericUpDown
        {
            Width = 84,
            Minimum = 1,
            Maximum = 168,
            Value = 2,
            Font = new Font("Segoe UI", 13f),
            TextAlign = HorizontalAlignment.Center,
            Margin = new Padding(0, 2, 10, 0),
        };
        _unit = new ComboBox
        {
            Width = 100,
            DropDownStyle = ComboBoxStyle.DropDownList,
            Font = new Font("Segoe UI", 11f),
            Margin = new Padding(0, 4, 0, 0),
        };
        _unit.Items.AddRange(new object[] { "Minutes", "Hours", "Days" });
        _unit.SelectedIndexChanged += OnUnitChanged;
        _unit.SelectedIndex = 1;                 // default to Hours
        ApplyUnitRange();                        // set the matching min/max for that unit
        _startButton = new Button { Size = new Size(180, 40), Margin = new Padding(14, 1, 0, 0) };
        StylePrimary(_startButton, Accent);
        _startButton.Click += OnStartClicked;
        inputRow.Controls.AddRange(new Control[] { _amount, _unit, _startButton });

        var capNote = new Label
        {
            Text = "From 1 minute up to 7 days. You can extend a lock, but never shorten it.",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(20, 112),
            BackColor = Color.Transparent,
        };
        lockCard.Controls.AddRange(new Control[] { lockTitle, forLabel, inputRow, capNote });

        // How-it-works note.
        var howLabel = new Label
        {
            Text =
                "The countdown only advances while your PC is on and Anchor is running — changing the " +
                "system clock won't skip it. While locked, Anchor resists being stopped or uninstalled. " +
                "If you truly need out, boot Windows into Safe Mode (see RECOVERY.md).",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Muted,
            AutoSize = false,
            Size = new Size(552, 74),
            Location = new Point(24, 292),
            BackColor = Color.Transparent,
        };

        _startupCheck = new CheckBox
        {
            Text = "Start automatically at login (keeps the tray icon on)",
            AutoSize = true,
            Location = new Point(24, 374),
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.FromArgb(60, 63, 70),
        };

        _uninstallButton = new Button { Size = new Size(150, 34), Location = new Point(24, 408) };
        StyleSecondary(_uninstallButton);
        _uninstallButton.Text = "Uninstall Anchor";
        _uninstallButton.Click += OnUninstallClicked;

        var versionLabel = new Label
        {
            Text = AppVersion,
            Font = new Font("Segoe UI", 8.5f),
            ForeColor = Color.FromArgb(150, 154, 162),
            AutoSize = true,
            Location = new Point(524, 420),
            BackColor = Color.Transparent,
        };

        body.Controls.AddRange(new Control[]
        {
            statusCard, lockCard, howLabel, _startupCheck, _uninstallButton, versionLabel,
        });

        // Add body first, then header, so the docked header sits above the fill body correctly.
        Controls.Add(body);
        Controls.Add(header);
    }

    /// <summary>Use the app's own embedded anchor icon for the window title bar + taskbar.</summary>
    private void TrySetWindowIcon()
    {
        try { Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!); }
        catch { /* fall back to the default icon if extraction fails */ }
    }

    // ===================== start at login =====================

    /// <summary>Reflect the current login-task state in the checkbox, then wire up the toggle.</summary>
    private void InitStartupCheck()
    {
        try { _startupCheck.Checked = StartupTask.IsEnabled(); } catch { /* leave unchecked */ }
        _startupCheck.CheckedChanged += OnStartupToggled;
    }

    private void OnStartupToggled(object? sender, EventArgs e)
    {
        try
        {
            if (_startupCheck.Checked)
                StartupTask.Enable(Environment.ProcessPath!);   // launch THIS exe at login, in tray mode
            else
                StartupTask.Disable();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Couldn't change the login setting: " + ex.Message,
                "Anchor", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            // Put the checkbox back to the real state without re-firing the handler.
            _startupCheck.CheckedChanged -= OnStartupToggled;
            try { _startupCheck.Checked = StartupTask.IsEnabled(); } catch { }
            _startupCheck.CheckedChanged += OnStartupToggled;
        }
    }

    // ===================== system tray =====================

    /// <summary>
    /// Put an anchor icon in the notification area so you can see status at a glance and
    /// reach the app quickly. Closing the window hides to the tray instead of quitting —
    /// but note the BLOCKING itself is done by the background services, so it keeps running
    /// no matter what you do with this window or the tray icon.
    /// </summary>
    private void BuildTray()
    {
        var menu = new ContextMenuStrip();

        var versionItem = new ToolStripMenuItem($"Anchor {AppVersion}") { Enabled = false };
        menu.Items.Add(versionItem);
        menu.Items.Add(new ToolStripSeparator());

        _trayStatus = new ToolStripMenuItem("Status") { Enabled = false };
        var openItem = new ToolStripMenuItem("Open Anchor", null, (_, _) => ShowFromTray());
        var exitItem = new ToolStripMenuItem("Close this window", null, (_, _) => { _reallyExit = true; Close(); });

        menu.Items.Add(_trayStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(openItem);
        menu.Items.Add(exitItem);

        _tray = new NotifyIcon
        {
            Icon = Icon ?? SystemIcons.Application,
            Text = "Anchor",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _tray.DoubleClick += (_, _) => ShowFromTray();
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
        BringToFront();
    }

    /// <summary>Closing the window hides it to the tray (unless "Close this window" was used).</summary>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            if (!_balloonShown)
            {
                _balloonShown = true;
                _tray.ShowBalloonTip(3000, "Anchor",
                    "Still here in the tray. Your block keeps running in the background.",
                    ToolTipIcon.Info);
            }
            return;
        }

        // Real exit: remove the tray icon so it doesn't linger as a ghost.
        _tray.Visible = false;
        _tray.Dispose();
        base.OnFormClosing(e);
    }

    /// <summary>A flat, subtly-shaded "card" panel with a 1px border.</summary>
    private static Panel MakeCard(Point location, Size size)
    {
        var card = new Panel { Location = location, Size = size, BackColor = CardBg };
        card.Paint += (s, e) =>
        {
            using var pen = new Pen(BorderCol);
            e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
        };
        return card;
    }

    private static void StylePrimary(Button b, Color accent)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = ControlPaint.Dark(accent, 0.03f);
        b.FlatAppearance.MouseDownBackColor = ControlPaint.Dark(accent, 0.08f);
        b.BackColor = accent;
        b.ForeColor = Color.White;
        b.Font = new Font("Segoe UI Semibold", 10.5f);
        b.Cursor = Cursors.Hand;
    }

    private static void StyleSecondary(Button b)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderColor = BorderCol;
        b.FlatAppearance.BorderSize = 1;
        b.BackColor = Color.White;
        b.ForeColor = Muted;
        b.Font = new Font("Segoe UI", 9.5f);
        b.Cursor = Cursors.Hand;
    }

    // ===================== behavior =====================

    private void EnsureInstalled()
    {
        try
        {
            if (!ServiceControl.IsInstalled())
            {
                _statusLabel.Text = "Setting up…";
                _statusLabel.Refresh();
                ServiceControl.Install();
            }
            else
            {
                // If this exe is newer than the installed background service, refresh it now
                // so you never have to uninstall/reinstall by hand to pick up a new build.
                _statusLabel.Text = "Checking for updates…";
                _statusLabel.Refresh();
                switch (ServiceControl.TryAutoUpdate())
                {
                    case ServiceControl.UpdateResult.Updated:
                        _tray.ShowBalloonTip(4000, "Anchor updated",
                            $"The background blocker was refreshed to {AppVersion}.", ToolTipIcon.Info);
                        break;
                    case ServiceControl.UpdateResult.BlockedByLock:
                        _tray.ShowBalloonTip(6000, "Anchor update waiting",
                            "A newer version is ready. It will install once your current lock ends.",
                            ToolTipIcon.Info);
                        break;
                }

                ServiceControl.EnsureRunning(AppPaths.ServiceName);
                ServiceControl.EnsureRunning(AppPaths.GuardianName);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this,
                "Setup failed. Make sure you ran Anchor as administrator and that WinDivert.dll and " +
                "WinDivert64.sys are in the same folder as Anchor.exe.\n\nDetails: " + ex.Message,
                "Anchor", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void RefreshStatus()
    {
        var state = LockState.Load();

        string trayText;
        if (state.IsLocked)
        {
            _statusStrip.BackColor = ActiveRed;
            _statusLabel.Text = "Blocking active";
            _statusLabel.ForeColor = ActiveRed;
            _detailLabel.Text = $"Active time remaining: {Format(state.Remaining)}";
            _startButton.Text = "Extend Lock";
            _uninstallButton.Enabled = false;
            trayText = $"Anchor — Blocking: {Format(state.Remaining)} left";
        }
        else
        {
            _statusStrip.BackColor = IdleGreen;
            _statusLabel.Text = "Not blocking";
            _statusLabel.ForeColor = IdleGreen;
            _detailLabel.Text = "No lock is active. Start one below to begin blocking.";
            _startButton.Text = "Start Lock";
            _uninstallButton.Enabled = true;
            trayText = "Anchor — Not blocking";
        }

        // Keep the tray tooltip + menu header in sync (NotifyIcon.Text caps at 63 chars).
        if (_tray != null)
        {
            _tray.Text = trayText.Length > 63 ? trayText[..63] : trayText;
            _trayStatus.Text = trayText.Replace("Anchor — ", "");
        }
    }

    /// <summary>Keep the number box's range sensible for whichever unit is selected.</summary>
    private void OnUnitChanged(object? sender, EventArgs e) => ApplyUnitRange();

    private void ApplyUnitRange()
    {
        // Upper bounds all correspond to the same 7-day cap enforced in LockState.
        (decimal max, decimal fallback) = _unit.SelectedItem?.ToString() switch
        {
            "Minutes" => (10080m, 30m),   // 7 days in minutes
            "Days" => (7m, 1m),
            _ => (168m, 2m),              // Hours: 7 days in hours
        };

        _amount.Maximum = max;
        if (_amount.Value > max) _amount.Value = fallback;
    }

    private void OnStartClicked(object? sender, EventArgs e)
    {
        var duration = _unit.SelectedItem?.ToString() switch
        {
            "Minutes" => TimeSpan.FromMinutes((double)_amount.Value),
            "Days" => TimeSpan.FromDays((double)_amount.Value),
            _ => TimeSpan.FromHours((double)_amount.Value),
        };

        if (duration > TimeSpan.FromDays(7)) duration = TimeSpan.FromDays(7);

        var confirm = MessageBox.Show(this,
            $"Start blocking YouTube and Reddit for {Format(duration)} of active time?\n\n" +
            "You will NOT be able to easily turn this off until it expires.",
            "Confirm lock", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (confirm != DialogResult.Yes) return;

        var state = LockState.Load();
        // Observe-only mode is captured here, at the moment the lock starts, and then lives
        // inside the lock — so it can't be switched on later to disable an enforcing lock.
        state.StartOrExtend(duration, dryRun: File.Exists(AppPaths.DryRunFile));
        state.Save();

        ServiceControl.EnsureRunning(AppPaths.ServiceName);
        ServiceControl.EnsureRunning(AppPaths.GuardianName);

        RefreshStatus();
        MessageBox.Show(this, "Lock started. Blocking will be active within a few seconds.",
            "Anchor", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void OnUninstallClicked(object? sender, EventArgs e)
    {
        var state = LockState.Load();
        if (state.IsLocked)
        {
            MessageBox.Show(this,
                "You can't uninstall while a lock is active. Wait for it to expire " +
                "(or use the Safe Mode recovery in RECOVERY.md).",
                "Anchor", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var confirm = MessageBox.Show(this,
            "Completely remove Anchor and stop all blocking?",
            "Uninstall", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;

        try
        {
            ServiceControl.Uninstall();
            MessageBox.Show(this, "Anchor has been removed.", "Anchor",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Uninstall failed: " + ex.Message, "Anchor",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>Turn a TimeSpan into a friendly "2d 3h 15m" string.</summary>
    private static string Format(TimeSpan t)
    {
        if (t.TotalSeconds < 1) return "0m";
        var parts = new List<string>();
        if (t.Days > 0) parts.Add($"{t.Days}d");
        if (t.Hours > 0) parts.Add($"{t.Hours}h");
        if (t.Minutes > 0) parts.Add($"{t.Minutes}m");
        if (parts.Count == 0) parts.Add("<1m");
        return string.Join(" ", parts);
    }
}
