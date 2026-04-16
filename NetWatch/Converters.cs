using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using NetWatch.Models;
using Color = System.Windows.Media.Color;

namespace NetWatch;

public static class Converters
{
    public static readonly SignedColorConverter SignedColorConv = new();
    public static readonly SignedTextConverter SignedTextConv = new();
    public static readonly RiskToBrushConverter RiskToBrushConv = new();
    public static readonly PercentToWidthConverter PercentWidthConv = new();
    public static readonly CountToVisibilityConverter CountToVisConv = new();
}

public class SignedColorConverter : IValueConverter
{
    private static readonly SolidColorBrush Green = new(Color.FromRgb(0x34, 0xD0, 0x58));
    private static readonly SolidColorBrush Red = new(Color.FromRgb(0xF8, 0x51, 0x49));
    private static readonly SolidColorBrush Gray = new(Color.FromRgb(0x6B, 0x7B, 0x8D));

    public object Convert(object value, Type t, object p, CultureInfo c)
        => value is bool b ? (b ? Green : Red) : Gray;

    public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}

public class SignedTextConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
        => value is bool b ? (b ? "✓ Подписано" : "✗ Без подписи!") : "⏳";

    public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}

public class RiskToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Green = new(Color.FromRgb(0x34, 0xD0, 0x58));
    private static readonly SolidColorBrush Yellow = new(Color.FromRgb(0xE3, 0xB3, 0x41));
    private static readonly SolidColorBrush Red = new(Color.FromRgb(0xF8, 0x51, 0x49));

    public object Convert(object value, Type t, object p, CultureInfo c)
        => value is RiskLevel r ? r switch
        {
            RiskLevel.Safe => Green,
            RiskLevel.Unknown => Yellow,
            RiskLevel.Suspicious => Red,
            _ => Yellow
        } : Yellow;

    public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}

public class PercentToWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type t, object p, CultureInfo c)
    {
        if (values.Length >= 2 && values[0] is double pct && values[1] is double parentWidth)
            return Math.Max(2, pct / 100.0 * parentWidth);
        return 2.0;
    }

    public object[] ConvertBack(object v, Type[] t, object p, CultureInfo c) => throw new NotImplementedException();
}

public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
        => value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}
