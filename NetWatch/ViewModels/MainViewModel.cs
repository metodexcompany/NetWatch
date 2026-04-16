using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Threading.Tasks;
using System.Windows.Threading;
using NetWatch.Models;
using NetWatch.Services;

namespace NetWatch.ViewModels;

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    public RelayCommand(Action<object?> execute) => _execute = execute;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? p) => true;
    public void Execute(object? p) => _execute(p);
}

public class MainViewModel : INotifyPropertyChanged
{
    private readonly DispatcherTimer _timer;
    private readonly BandwidthTracker _bwTracker = new();
    private readonly HashSet<string> _alertSeen = new();
    private NotificationService? _notifications;
    private bool _firstScanDone;

    public ObservableCollection<ProcessGroup> Processes { get; } = new();
    public ObservableCollection<ConnectionInfo> AllConnections { get; } = new();
    public ObservableCollection<Alert> Alerts { get; } = new();
    public ObservableCollection<ServiceStat> TopServices { get; } = new();
    public List<BandwidthTracker.BwPoint> BandwidthHistory => _bwTracker.GetHistory();

    private int _totalConns;
    public int TotalConns { get => _totalConns; set { _totalConns = value; OnPropertyChanged(); } }

    private int _safeCount;
    public int SafeCount { get => _safeCount; set { _safeCount = value; OnPropertyChanged(); } }

    private int _unknownCount;
    public int UnknownCount { get => _unknownCount; set { _unknownCount = value; OnPropertyChanged(); } }

    private int _suspiciousCount;
    public int SuspiciousCount { get => _suspiciousCount; set { _suspiciousCount = value; OnPropertyChanged(); } }

    private int _processCount;
    public int ProcessCount { get => _processCount; set { _processCount = value; OnPropertyChanged(); } }

    private double _downloadMbps;
    public double DownloadMbps { get => _downloadMbps; set { _downloadMbps = value; OnPropertyChanged(); } }

    private double _uploadMbps;
    public double UploadMbps { get => _uploadMbps; set { _uploadMbps = value; OnPropertyChanged(); } }

    private int _alertCount;
    public int AlertCount { get => _alertCount; set { _alertCount = value; OnPropertyChanged(); } }

    private string _selectedProcess = "";
    public string SelectedProcess
    {
        get => _selectedProcess;
        set { _selectedProcess = value; OnPropertyChanged(); RefreshView(); }
    }

    public ObservableCollection<string> BlockedIPs { get; } = new();
    public ICommand BlockCommand { get; }
    public ICommand UnblockCommand { get; }
    public ICommand BlockProcessCommand { get; }

    private bool _geoIPEnabled = true;
    public bool GeoIPEnabled
    {
        get => _geoIPEnabled;
        set { _geoIPEnabled = value; OnPropertyChanged(); SaveSettings(); }
    }

    private bool _showSelfConnections = true;
    public bool ShowSelfConnections
    {
        get => _showSelfConnections;
        set { _showSelfConnections = value; OnPropertyChanged(); SaveSettings(); }
    }

    private int _intervalSeconds = 3;
    public int IntervalSeconds
    {
        get => _intervalSeconds;
        set { _intervalSeconds = value; OnPropertyChanged(); }
    }

    // First scan screen
    private bool _showScanScreen = true;
    public bool ShowScanScreen { get => _showScanScreen; set { _showScanScreen = value; OnPropertyChanged(); } }

    private string _scanStatus = "Сканирование сети...";
    public string ScanStatus { get => _scanStatus; set { _scanStatus = value; OnPropertyChanged(); } }

    // Update
    private bool _updateAvailable;
    public bool UpdateAvailable { get => _updateAvailable; set { _updateAvailable = value; OnPropertyChanged(); } }

    private string _updateVersion = "";
    public string UpdateVersion { get => _updateVersion; set { _updateVersion = value; OnPropertyChanged(); } }

    private string _updateUrl = "";
    public string UpdateUrl { get => _updateUrl; set { _updateUrl = value; OnPropertyChanged(); } }

    public event Action? NewAlert;
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel()
    {
        BlockCommand = new RelayCommand(p => { if (p is string ip) BlockIP(ip); });
        UnblockCommand = new RelayCommand(p => { if (p is string ip) UnblockIP(ip); });
        BlockProcessCommand = new RelayCommand(p => { if (p is string name) BlockProcess(name); });

        // Load saved settings
        var settings = SettingsService.Load();
        _geoIPEnabled = settings.GeoIPEnabled;
        _showSelfConnections = settings.ShowSelfConnections;
        _intervalSeconds = settings.IntervalSeconds;

        Task.Run(() => GeoIPService.ResolveSelfIPs());

        // Check for updates
        Task.Run(async () =>
        {
            var update = await UpdateService.CheckAsync();
            if (update.Available)
            {
                UpdateAvailable = true;
                UpdateVersion = update.LatestVersion;
                UpdateUrl = update.DownloadUrl;
            }
        });

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(_intervalSeconds) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Refresh();
    }

    public void SetInterval(int seconds)
    {
        _intervalSeconds = seconds;
        _timer.Stop();
        _timer.Interval = TimeSpan.FromSeconds(seconds);
        _timer.Start();
        OnPropertyChanged(nameof(IntervalSeconds));
        SaveSettings();
    }

    private void SaveSettings()
    {
        SettingsService.Save(new AppSettings
        {
            GeoIPEnabled = _geoIPEnabled,
            ShowSelfConnections = _showSelfConnections,
            IntervalSeconds = _intervalSeconds
        });
    }

    public void BlockIP(string ip)
    {
        var (blocked, killed) = FirewallService.Block(ip);
        RefreshBlocked();
        if (!string.IsNullOrEmpty(killed))
        {
            // Refresh immediately to remove killed process from list
            Refresh();
        }
    }

    public void UnblockIP(string ip)
    {
        FirewallService.Unblock(ip);
        RefreshBlocked();
    }

    private void RefreshBlocked()
    {
        BlockedIPs.Clear();
        foreach (var ip in FirewallService.GetBlocked())
            BlockedIPs.Add(ip);
    }

    public void Refresh()
    {
        // Pass GeoIP enabled state
        GeoIPService.Enabled = _geoIPEnabled;

        var rawConns = ConnectionMonitor.GetConnections(_showSelfConnections);

        // Enrich with GeoIP + Classification
        foreach (var c in rawConns)
        {
            if (_geoIPEnabled)
            {
                var geo = GeoIPService.Lookup(c.RemoteIP);
                c.Country = geo.Country;
                c.CountryCode = geo.CountryCode;
                c.Org = geo.Org;
            }
            c.IsSigned = !string.IsNullOrEmpty(c.ExePath) && SignatureChecker.IsSigned(c.ExePath);

            var (risk, service) = ClassificationService.Classify(c.Org, c.RemotePort, c.IsSigned);
            c.Risk = risk;
            c.Service = service;
        }

        // Group by process name
        var groups = rawConns
            .GroupBy(c => c.ProcessName)
            .Select(g =>
            {
                var first = g.First();
                var pg = new ProcessGroup
                {
                    Name = g.Key,
                    Icon = first.ProcessIcon,
                    ExePath = first.ExePath,
                    IsSigned = first.IsSigned,
                    Connections = g.ToList()
                };
                pg.SafeCount = g.Count(c => c.Risk == RiskLevel.Safe);
                pg.UnknownCount = g.Count(c => c.Risk == RiskLevel.Unknown);
                pg.SuspiciousCount = g.Count(c => c.Risk == RiskLevel.Suspicious);
                return pg;
            })
            .OrderByDescending(p => p.Count)
            .ToList();

        // Check alerts
        foreach (var c in rawConns.Where(c => c.Risk == RiskLevel.Suspicious))
        {
            var key = $"{c.ProcessName}|{c.RemoteIP}";
            if (_alertSeen.Add(key))
            {
                var reason = c.IsSigned
                    ? "Неизвестная организация, нестандартный порт"
                    : "Неподписанный процесс + подозрительное соединение";
                Alerts.Insert(0, new Alert
                {
                    Process = c.ProcessName, IP = c.RemoteIP, Port = c.RemotePort,
                    Service = c.Service, Country = c.Country, Org = c.Org,
                    Reason = reason, ExePath = c.ExePath
                });
                if (Alerts.Count > 100) Alerts.RemoveAt(Alerts.Count - 1);
                NewAlert?.Invoke();

                // Windows toast notification
                _notifications?.ShowAlert("NetWatch — Угроза",
                    $"{c.ProcessName} → {c.RemoteIP}:{c.RemotePort}\n{reason}");
            }
        }
        AlertCount = Alerts.Count;

        // Update tray tooltip
        _notifications?.UpdateTooltip(rawConns.Count, rawConns.Count(c => c.Risk == RiskLevel.Suspicious));

        // First scan done — show results
        if (!_firstScanDone)
        {
            _firstScanDone = true;
            ScanStatus = $"Найдено: {rawConns.Count} подключений\n" +
                         $"Процессов: {groups.Count}\n" +
                         $"Подозрительных: {rawConns.Count(c => c.Risk == RiskLevel.Suspicious)}";
        }

        // Bandwidth
        _bwTracker.Sample();
        var (dl, ul) = _bwTracker.GetCurrent();
        DownloadMbps = Math.Round(dl, 2);
        UploadMbps = Math.Round(ul, 2);

        // Update collections
        Processes.Clear();
        foreach (var p in groups) Processes.Add(p);

        ProcessCount = groups.Count;
        TotalConns = rawConns.Count;
        SafeCount = rawConns.Count(c => c.Risk == RiskLevel.Safe);
        UnknownCount = rawConns.Count(c => c.Risk == RiskLevel.Unknown);
        SuspiciousCount = rawConns.Count(c => c.Risk == RiskLevel.Suspicious);

        // Top services
        var svcStats = rawConns
            .Where(c => string.IsNullOrEmpty(SelectedProcess) || c.ProcessName == SelectedProcess)
            .GroupBy(c => c.Service)
            .Select(g => new ServiceStat { Name = g.Key, Count = g.Count(), Risk = g.First().Risk })
            .OrderByDescending(s => s.Count)
            .Take(10)
            .ToList();
        var maxSvc = svcStats.FirstOrDefault()?.Count ?? 1;
        foreach (var s in svcStats) s.Percent = (double)s.Count / maxSvc * 100;

        TopServices.Clear();
        foreach (var s in svcStats) TopServices.Add(s);

        RefreshView();
        RefreshBlocked();
        OnPropertyChanged(nameof(BandwidthHistory));
    }

    private void RefreshView()
    {
        var filtered = string.IsNullOrEmpty(SelectedProcess)
            ? Processes.SelectMany(p => p.Connections)
            : Processes.Where(p => p.Name == SelectedProcess).SelectMany(p => p.Connections);

        // Group by ProcessName + RemoteIP — show one line with count
        var grouped = filtered
            .GroupBy(c => $"{c.ProcessName}|{c.RemoteIP}")
            .Select(g =>
            {
                var first = g.First();
                first.DuplicateCount = g.Count();
                return first;
            })
            .OrderByDescending(c => c.DuplicateCount);

        AllConnections.Clear();
        foreach (var c in grouped) AllConnections.Add(c);
    }

    /// <summary>Ban ALL IPs of a process at once</summary>
    public void BlockProcess(string processName)
    {
        var ips = Processes
            .Where(p => p.Name == processName)
            .SelectMany(p => p.Connections)
            .Select(c => c.RemoteIP)
            .Where(ip => !GeoIPService.IsPrivate(ip))
            .Distinct()
            .ToList();

        foreach (var ip in ips)
            FirewallService.Block(ip);

        RefreshBlocked();
        Refresh();
    }

    public void SetNotificationService(NotificationService svc) => _notifications = svc;

    public void DismissAlerts()
    {
        Alerts.Clear();
        AlertCount = 0;
    }

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
