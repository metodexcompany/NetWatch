using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;

namespace NetWatch.Services;

public class BandwidthTracker
{
    public record BwPoint(DateTime Time, double InMbps, double OutMbps);

    private readonly List<BwPoint> _history = new();
    private long _prevIn, _prevOut;
    private DateTime _prevTime;
    private readonly object _lock = new();

    public void Sample()
    {
        try
        {
            var ifaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            long totalIn = 0, totalOut = 0;
            foreach (var iface in ifaces)
            {
                var stats = iface.GetIPStatistics();
                totalIn += stats.BytesReceived;
                totalOut += stats.BytesSent;
            }

            var now = DateTime.Now;
            if (_prevTime != default)
            {
                var dt = (now - _prevTime).TotalSeconds;
                if (dt > 0.5)
                {
                    var inMbps = (totalIn - _prevIn) / dt * 8.0 / 1_000_000;
                    var outMbps = (totalOut - _prevOut) / dt * 8.0 / 1_000_000;

                    lock (_lock)
                    {
                        _history.Add(new BwPoint(now, Math.Max(0, inMbps), Math.Max(0, outMbps)));
                        if (_history.Count > 200) _history.RemoveAt(0);
                    }
                }
            }
            _prevIn = totalIn;
            _prevOut = totalOut;
            _prevTime = now;
        }
        catch { }
    }

    public List<BwPoint> GetHistory()
    {
        lock (_lock) { return _history.ToList(); }
    }

    public (double inMbps, double outMbps) GetCurrent()
    {
        lock (_lock)
        {
            if (_history.Count == 0) return (0, 0);
            var last = _history[^1];
            return (last.InMbps, last.OutMbps);
        }
    }
}
