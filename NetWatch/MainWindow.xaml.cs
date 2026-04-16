using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using NetWatch.Services;
using NetWatch.ViewModels;

namespace NetWatch;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private NotificationService? _notify;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel();
        DataContext = _vm;

        // load icon
        try { Icon = new BitmapImage(new Uri("pack://application:,,,/Assets/netwatch.ico", UriKind.Absolute)); } catch { }

        // systray
        try
        {
            _notify = new NotificationService();
            _notify.OnOpen += () => Dispatcher.Invoke(() => { Show(); WindowState = WindowState.Normal; Activate(); });
            _notify.OnExit += () => Dispatcher.Invoke(() => { _notify?.Dispose(); System.Windows.Application.Current.Shutdown(); });
            _vm.SetNotificationService(_notify);
        }
        catch { }

        _vm.PropertyChanged += Vm_PropertyChanged;
        _vm.NewAlert += () => Dispatcher.Invoke(() =>
        {
            AlertBadge.Visibility = Visibility.Visible;
            AlertBadgeText.Text = _vm.AlertCount.ToString();
        });

        // First scan — show results after 3 seconds
        var scanTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        scanTimer.Tick += (_, _) =>
        {
            scanTimer.Stop();
            ScanProgress.IsIndeterminate = false;
            ScanProgress.Visibility = Visibility.Collapsed;
            ScanResults.Visibility = Visibility.Visible;

            var suspicious = _vm.SuspiciousCount;
            var text = $"Подключений: {_vm.TotalConns}\n" +
                       $"Процессов: {_vm.ProcessCount}\n";
            if (suspicious > 0)
                text += $"⚠ Подозрительных: {suspicious}";
            else
                text += "✓ Угроз не обнаружено";
            ScanResultText.Text = text;
        };
        scanTimer.Start();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        // Minimize to tray instead of taskbar
        if (WindowState == WindowState.Minimized)
        {
            Hide();
            _notify?.ShowInfo("NetWatch", "Работаю в фоне. Двойной клик для открытия.");
        }
        base.OnStateChanged(e);
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Close to tray, not exit
        e.Cancel = true;
        Hide();
        _notify?.ShowInfo("NetWatch", "Работаю в фоне. Двойной клик для открытия.");
    }

    private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.TotalConns) or nameof(MainViewModel.ProcessCount))
        {
            StatsText.Text = $"{_vm.ProcessCount} процессов · {_vm.TotalConns} подключений";
            Title = $"NetWatch — {_vm.ProcessCount} проц., {_vm.TotalConns} подкл.";
        }
        if (e.PropertyName == nameof(MainViewModel.AlertCount))
        {
            AlertBadge.Visibility = _vm.AlertCount > 0 ? Visibility.Visible : Visibility.Collapsed;
            AlertBadgeText.Text = _vm.AlertCount.ToString();
        }
        if (e.PropertyName == nameof(MainViewModel.UpdateAvailable) && _vm.UpdateAvailable)
        {
            UpdateBar.Visibility = Visibility.Visible;
            UpdateVersionText.Text = _vm.UpdateVersion;
        }
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            if (e.ClickCount == 2) ToggleMaximize();
            else DragMove();
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        // Real exit (not to tray)
        if (_notify != null) _notify.Dispose();
        System.Windows.Application.Current.Shutdown();
    }

    private void ToggleMaximize()
    {
        if (WindowState == WindowState.Maximized)
        { WindowState = WindowState.Normal; MaxBtn.Content = "□"; }
        else
        { WindowState = WindowState.Maximized; MaxBtn.Content = "❐"; }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => _vm.Refresh();

    private void Process_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is string name)
            _vm.SelectedProcess = _vm.SelectedProcess == name ? "" : name;
    }

    // ── Scan screen ──
    private void CloseScanScreen_Click(object sender, RoutedEventArgs e)
    {
        ScanScreen.Visibility = Visibility.Collapsed;
    }

    // ── Alerts ──
    private void AlertBadge_Click(object sender, MouseButtonEventArgs e)
    {
        AlertPanel.Visibility = AlertPanel.Visibility == Visibility.Visible
            ? Visibility.Collapsed : Visibility.Visible;
        SettingsPanel.Visibility = Visibility.Collapsed;
    }

    private void DismissAlerts_Click(object sender, RoutedEventArgs e)
    {
        _vm.DismissAlerts();
        AlertPanel.Visibility = Visibility.Collapsed;
    }

    // ── Settings ──
    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        SettingsPanel.Visibility = SettingsPanel.Visibility == Visibility.Visible
            ? Visibility.Collapsed : Visibility.Visible;
        AlertPanel.Visibility = Visibility.Collapsed;
    }

    private void CloseSettings_Click(object sender, RoutedEventArgs e)
        => SettingsPanel.Visibility = Visibility.Collapsed;

    private void GeoIPToggle_Changed(object sender, RoutedEventArgs e)
        => _vm.GeoIPEnabled = GeoIPToggle.IsChecked == true;

    private void ShowSelfToggle_Changed(object sender, RoutedEventArgs e)
        => _vm.ShowSelfConnections = ShowSelfToggle.IsChecked == true;

    private void Interval1_Click(object sender, RoutedEventArgs e) => _vm.SetInterval(1);
    private void Interval3_Click(object sender, RoutedEventArgs e) => _vm.SetInterval(3);
    private void Interval5_Click(object sender, RoutedEventArgs e) => _vm.SetInterval(5);
    private void Interval10_Click(object sender, RoutedEventArgs e) => _vm.SetInterval(10);

    // ── Update ──
    private void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_vm.UpdateUrl))
            Process.Start(new ProcessStartInfo(_vm.UpdateUrl) { UseShellExecute = true });
    }
}
