using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;

namespace NetWatch.Services;

public static class FirewallService
{
    private static readonly object _lock = new();
    private static List<string>? _cache;
    private static DateTime _cacheTime;

    // System processes that must NEVER be killed
    private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "smss", "csrss", "wininit",
        "winlogon", "services", "lsass", "svchost", "spoolsv",
        "dwm", "explorer", "taskhostw", "sihost", "fontdrvhost",
        "ctfmon", "conhost", "dllhost", "msdtc", "searchhost",
        "startmenuexperiencehost", "runtimebroker", "shellexperiencehost",
        "securityhealthservice", "securityhealthsystray",
        "audiodg", "dashost", "wmiprvse", "wudfhost",
        "memory compression", "ntoskrnl"
    };

    private static ProcessStartInfo HiddenCmd(string fileName, string args) => new()
    {
        FileName = fileName,
        Arguments = args,
        CreateNoWindow = true,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        WindowStyle = ProcessWindowStyle.Hidden
    };

    /// <summary>Block IP + kill process holding that connection</summary>
    public static (bool blocked, string killedProcess) Block(string ip)
    {
        string killed = "";
        try
        {
            // 1. Add firewall rule
            var name = $"NetWatch_Block_{ip}";
            var psi = HiddenCmd("netsh",
                $"advfirewall firewall add rule name=\"{name}\" dir=out action=block remoteip={ip} enable=yes");
            var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
            InvalidateCache();

            // 2. Find and kill process connected to this IP
            killed = KillConnectionTo(ip);

            return (proc?.ExitCode == 0, killed);
        }
        catch { return (false, killed); }
    }

    /// <summary>Find process connected to IP and kill it (if safe)</summary>
    private static string KillConnectionTo(string ip)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\StandardCimv2",
                $"SELECT OwningProcess FROM MSFT_NetTCPConnection WHERE RemoteAddress='{ip}' AND State=5");

            var pidsToKill = new HashSet<int>();
            foreach (ManagementObject obj in searcher.Get())
            {
                var pid = Convert.ToInt32(obj["OwningProcess"]);
                if (pid > 4) pidsToKill.Add(pid); // skip System (0, 4)
            }

            var killedNames = new List<string>();
            foreach (var pid in pidsToKill)
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    var name = proc.ProcessName;

                    // PROTECT system processes
                    if (ProtectedProcesses.Contains(name))
                        continue;

                    // Don't kill ourselves
                    if (pid == Environment.ProcessId)
                        continue;

                    proc.Kill();
                    killedNames.Add(name);
                }
                catch { }
            }

            return killedNames.Count > 0
                ? string.Join(", ", killedNames)
                : "";
        }
        catch { return ""; }
    }

    public static bool Unblock(string ip)
    {
        try
        {
            var name = $"NetWatch_Block_{ip}";
            var psi = HiddenCmd("netsh",
                $"advfirewall firewall delete rule name=\"{name}\"");
            var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
            InvalidateCache();
            return proc?.ExitCode == 0;
        }
        catch { return false; }
    }

    public static List<string> GetBlocked()
    {
        lock (_lock)
        {
            if (_cache != null && (DateTime.Now - _cacheTime).TotalSeconds < 15)
                return _cache;

            try
            {
                var psi = HiddenCmd("netsh", "advfirewall firewall show rule name=all dir=out");
                var proc = Process.Start(psi);
                if (proc == null) return _cache ?? new();
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                var blocked = new List<string>();
                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Contains("NetWatch_Block_"))
                    {
                        var parts = trimmed.Split("NetWatch_Block_", 2);
                        if (parts.Length == 2)
                        {
                            var ip = parts[1].Trim();
                            if (!string.IsNullOrEmpty(ip))
                                blocked.Add(ip);
                        }
                    }
                }
                _cache = blocked.Distinct().ToList();
                _cacheTime = DateTime.Now;
                return _cache;
            }
            catch { return _cache ?? new(); }
        }
    }

    public static bool IsBlocked(string ip) => GetBlocked().Contains(ip);

    private static void InvalidateCache()
    {
        lock (_lock) { _cache = null; }
    }
}
