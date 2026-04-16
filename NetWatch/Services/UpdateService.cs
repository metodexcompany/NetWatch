using System;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetWatch.Services;

public static class UpdateService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    public static string CurrentVersion => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public record UpdateInfo(bool Available, string LatestVersion, string DownloadUrl);

    public static async Task<UpdateInfo> CheckAsync()
    {
        try
        {
            _http.DefaultRequestHeaders.UserAgent.Clear();
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetWatch");
            var json = await _http.GetStringAsync(
                "https://api.github.com/repos/metodexcompany/NetWatch/releases/latest");
            using var doc = JsonDocument.Parse(json);
            var tag = doc.RootElement.GetProperty("tag_name").GetString()?.TrimStart('v') ?? "0";
            var url = doc.RootElement.GetProperty("html_url").GetString() ?? "";

            var current = Version.Parse(CurrentVersion);
            var latest = Version.Parse(tag);
            return new UpdateInfo(latest > current, tag, url);
        }
        catch
        {
            return new UpdateInfo(false, CurrentVersion, "");
        }
    }
}
