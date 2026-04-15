using System.Collections.Generic;

namespace NetWatch.Models;

public class ProcessGroup
{
    public string Name { get; set; } = "";
    public string Icon { get; set; } = "";
    public string ExePath { get; set; } = "";
    public bool IsSigned { get; set; }
    public List<ConnectionInfo> Connections { get; set; } = new();
    public int Count => Connections.Count;
    public int SafeCount { get; set; }
    public int UnknownCount { get; set; }
    public int SuspiciousCount { get; set; }
}
