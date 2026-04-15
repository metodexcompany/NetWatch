using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetWatch.Services;

public static class GeoIPService
{
    private static readonly ConcurrentDictionary<string, GeoResult> _cache = new();
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(3) };
    private static bool _resolvedSelf;

    public static bool Enabled { get; set; } = true;

    /// <summary>Resolve ip-api.com IPs so ConnectionMonitor can filter them out</summary>
    public static void ResolveSelfIPs()
    {
        if (_resolvedSelf) return;
        _resolvedSelf = true;
        try
        {
            var ips = Dns.GetHostAddresses("ip-api.com");
            foreach (var ip in ips)
                ConnectionMonitor.AddSelfIP(ip.ToString());
        }
        catch { }
    }

    public record GeoResult(string Country, string CountryCode, string Org, double Lat, double Lon);

    private static readonly string[] PrivatePrefixes = {
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "127.", "0."
    };

    public static bool IsPrivate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return true;
        if (IPAddress.IsLoopback(addr)) return true;
        foreach (var p in PrivatePrefixes)
            if (ip.StartsWith(p)) return true;
        return false;
    }

    public static GeoResult Lookup(string ip)
    {
        if (_cache.TryGetValue(ip, out var cached)) return cached;

        if (IsPrivate(ip))
        {
            var lan = new GeoResult("LAN", "LAN", "Local Network", 0, 0);
            _cache.TryAdd(ip, lan);
            return lan;
        }

        if (!Enabled)
            return new GeoResult("Выключено", "-", "-", 0, 0);

        // async fire-and-forget
        _ = LookupAsync(ip);
        return new GeoResult("...", "...", "...", 0, 0);
    }

    private static async Task LookupAsync(string ip)
    {
        try
        {
            var json = await _http.GetStringAsync(
                $"http://ip-api.com/json/{ip}?fields=country,countryCode,org,lat,lon");
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var result = new GeoResult(
                root.GetProperty("country").GetString() ?? "?",
                root.GetProperty("countryCode").GetString() ?? "?",
                root.GetProperty("org").GetString() ?? "?",
                root.TryGetProperty("lat", out var lat) ? lat.GetDouble() : 0,
                root.TryGetProperty("lon", out var lon) ? lon.GetDouble() : 0
            );
            _cache[ip] = result;
        }
        catch
        {
            _cache[ip] = new GeoResult("?", "?", "?", 0, 0);
        }
    }
}
