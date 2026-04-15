using System;
using System.IO;
using System.Text.Json;

namespace NetWatch.Services;

public class AppSettings
{
    public bool GeoIPEnabled { get; set; } = true;
    public bool ShowSelfConnections { get; set; } = true;
    public int IntervalSeconds { get; set; } = 3;
}

public static class SettingsService
{
    public static readonly string DataDir;
    private static readonly string SettingsPath;

    static SettingsService()
    {
        // Store data in %APPDATA%\NetWatch (writable even from Program Files)
        DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetWatch");
        Directory.CreateDirectory(DataDir);
        SettingsPath = Path.Combine(DataDir, "settings.json");
    }

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
        }
        catch { }
        return new AppSettings();
    }

    public static void Save(AppSettings settings)
    {
        try
        {
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);
        }
        catch { }
    }
}
