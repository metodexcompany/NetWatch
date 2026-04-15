using System;

namespace NetWatch.Models;

public class Alert
{
    public DateTime Time { get; set; } = DateTime.Now;
    public string Process { get; set; } = "";
    public string IP { get; set; } = "";
    public int Port { get; set; }
    public string Service { get; set; } = "";
    public string Country { get; set; } = "";
    public string Org { get; set; } = "";
    public string Reason { get; set; } = "";
    public string ExePath { get; set; } = "";
    public string TimeStr => Time.ToString("HH:mm:ss");
}
