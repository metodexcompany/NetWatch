using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using NetWatch.Models;

namespace NetWatch.Services;

public static class ConnectionMonitor
{
    // IP of ip-api.com — exclude our own GeoIP lookups
    private static readonly HashSet<string> SelfIPs = new();
    private static int _selfPid = Environment.ProcessId;

    public static void AddSelfIP(string ip)
    {
        SelfIPs.Add(ip);
    }

    public static List<ConnectionInfo> GetConnections(bool includeSelf = true)
    {
        var result = new List<ConnectionInfo>();
        int selfConnCount = 0;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\StandardCimv2",
                "SELECT LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State FROM MSFT_NetTCPConnection WHERE State=5");

            foreach (ManagementObject obj in searcher.Get())
            {
                var remoteIP = obj["RemoteAddress"]?.ToString() ?? "";
                var remotePort = Convert.ToInt32(obj["RemotePort"]);
                var pid = Convert.ToInt32(obj["OwningProcess"]);

                if (string.IsNullOrEmpty(remoteIP) || remoteIP == "0.0.0.0" || remoteIP == "::") continue;

                // Count own connections, show as one grouped line
                if (pid == _selfPid || (SelfIPs.Contains(remoteIP) && remotePort == 80))
                {
                    selfConnCount++;
                    continue;
                }

                string procName = "System";
                string exePath = "";
                try
                {
                    var proc = Process.GetProcessById(pid);
                    procName = proc.ProcessName;
                    try { exePath = proc.MainModule?.FileName ?? ""; } catch { }
                }
                catch { procName = $"PID:{pid}"; }

                var icon = procName.Length >= 2
                    ? procName[..2].ToUpper()
                    : procName.ToUpper();

                result.Add(new ConnectionInfo
                {
                    ProcessName = procName,
                    Pid = pid,
                    RemoteIP = remoteIP,
                    RemotePort = remotePort,
                    ExePath = exePath,
                    ProcessIcon = icon
                });
            }
        }
        catch
        {
            try
            {
                var props = IPGlobalProperties.GetIPGlobalProperties();
                var conns = props.GetActiveTcpConnections();
                foreach (var c in conns.Where(c => c.State == TcpState.Established))
                {
                    var ip = c.RemoteEndPoint.Address.ToString();
                    if (SelfIPs.Contains(ip) && c.RemoteEndPoint.Port == 80) continue;

                    result.Add(new ConnectionInfo
                    {
                        ProcessName = "unknown",
                        RemoteIP = ip,
                        RemotePort = c.RemoteEndPoint.Port,
                        ProcessIcon = "??"
                    });
                }
            }
            catch { }
        }

        // Add self as one grouped line
        if (includeSelf && selfConnCount > 0)
        {
            result.Add(new ConnectionInfo
            {
                ProcessName = "NetWatch",
                Pid = _selfPid,
                RemoteIP = "ip-api.com",
                RemotePort = 80,
                ExePath = Environment.ProcessPath ?? "",
                ProcessIcon = "NW",
                Service = $"GeoIP ({selfConnCount} запр.)",
                Country = "США",
                Org = "ip-api.com",
                Risk = RiskLevel.Safe
            });
        }

        return result;
    }
}
