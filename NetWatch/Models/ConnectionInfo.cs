namespace NetWatch.Models;

public class ConnectionInfo
{
    public string ProcessName { get; set; } = "";
    public int Pid { get; set; }
    public string RemoteIP { get; set; } = "";
    public int RemotePort { get; set; }
    public string Country { get; set; } = "...";
    public string CountryCode { get; set; } = "";
    public string Org { get; set; } = "...";
    public string Service { get; set; } = "...";
    public RiskLevel Risk { get; set; } = RiskLevel.Unknown;
    public string ExePath { get; set; } = "";
    public bool IsSigned { get; set; }
    public string ProcessIcon { get; set; } = "";
    public int DuplicateCount { get; set; } = 1;
    public string DisplayCount => DuplicateCount > 1 ? $"×{DuplicateCount}" : "";
}

public enum RiskLevel
{
    Safe,      // known service
    Unknown,   // unknown org, standard port
    Suspicious // unknown org, non-standard port or unsigned process
}
