using System;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using NetWatch.ViewModels;

namespace NetWatch;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel();
        DataContext = _vm;

        // load icon from embedded resource
        try
        {
            Icon = new BitmapImage(new Uri("pack://application:,,,/Assets/netwatch.ico", UriKind.Absolute));
        }
        catch { }

        _vm.PropertyChanged += Vm_PropertyChanged;
        _vm.NewAlert += () => Dispatcher.Invoke(() =>
        {
            AlertBadge.Visibility = Visibility.Visible;
            AlertBadgeText.Text = _vm.AlertCount.ToString();
        });
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
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            if (e.ClickCount == 2)
                ToggleMaximize();
            else
                DragMove();
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void Close_Click(object sender, RoutedEventArgs e) => Application.Current.Shutdown();

    private void ToggleMaximize()
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            MaxBtn.Content = "□";
        }
        else
        {
            WindowState = WindowState.Maximized;
            MaxBtn.Content = "❐";
        }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => _vm.Refresh();

    private void Process_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is string name)
            _vm.SelectedProcess = _vm.SelectedProcess == name ? "" : name;
    }

    // ── Алерты ──
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

    // ── Настройки ──
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
}
