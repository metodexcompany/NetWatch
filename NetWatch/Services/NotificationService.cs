using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace NetWatch.Services;

public class NotificationService : IDisposable
{
    private readonly NotifyIcon _trayIcon;

    public event Action? OnOpen;
    public event Action? OnExit;

    public NotificationService()
    {
        _trayIcon = new NotifyIcon
        {
            Text = "NetWatch — мониторинг сети",
            Visible = true
        };

        // Load icon from embedded resource or generate
        try
        {
            var icoPath = Path.Combine(AppContext.BaseDirectory, "netwatch.ico");
            if (File.Exists(icoPath))
                _trayIcon.Icon = new Icon(icoPath);
            else
                _trayIcon.Icon = SystemIcons.Shield;
        }
        catch { _trayIcon.Icon = SystemIcons.Shield; }

        // Context menu
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть NetWatch", null, (_, _) => OnOpen?.Invoke());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => OnExit?.Invoke());
        _trayIcon.ContextMenuStrip = menu;

        // Double-click to open
        _trayIcon.DoubleClick += (_, _) => OnOpen?.Invoke();
    }

    public void ShowAlert(string title, string message)
    {
        _trayIcon.BalloonTipTitle = title;
        _trayIcon.BalloonTipText = message;
        _trayIcon.BalloonTipIcon = ToolTipIcon.Warning;
        _trayIcon.ShowBalloonTip(5000);
    }

    public void ShowInfo(string title, string message)
    {
        _trayIcon.BalloonTipTitle = title;
        _trayIcon.BalloonTipText = message;
        _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
        _trayIcon.ShowBalloonTip(3000);
    }

    public void UpdateTooltip(int connections, int suspicious)
    {
        var text = $"NetWatch — {connections} подкл.";
        if (suspicious > 0) text += $", {suspicious} угроз!";
        if (text.Length > 63) text = text[..63]; // NotifyIcon limit
        _trayIcon.Text = text;
    }

    public void Dispose()
    {
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
    }
}
