namespace NetWatch.Models;

public class ServiceStat
{
    public string Name { get; set; } = "";
    public int Count { get; set; }
    public RiskLevel Risk { get; set; }
    public double Percent { get; set; }
}
