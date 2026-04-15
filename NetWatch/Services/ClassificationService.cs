using System;
using System.Collections.Generic;
using NetWatch.Models;

namespace NetWatch.Services;

public static class ClassificationService
{
    private static readonly Dictionary<string, string> KnownServices = new(StringComparer.OrdinalIgnoreCase)
    {
        ["google"] = "Google", ["youtube"] = "YouTube", ["googleapis"] = "Google APIs",
        ["microsoft"] = "Microsoft", ["azure"] = "Microsoft Azure", ["windows"] = "Microsoft",
        ["live.com"] = "Microsoft", ["office"] = "Microsoft Office",
        ["amazon"] = "Amazon/AWS", ["aws"] = "Amazon AWS",
        ["cloudflare"] = "Cloudflare", ["akamai"] = "Akamai CDN", ["fastly"] = "Fastly CDN",
        ["apple"] = "Apple", ["icloud"] = "Apple iCloud",
        ["meta"] = "Meta", ["facebook"] = "Facebook", ["instagram"] = "Instagram",
        ["whatsapp"] = "WhatsApp",
        ["valve"] = "Valve/Steam", ["steam"] = "Steam", ["discord"] = "Discord",
        ["telegram"] = "Telegram",
        ["mozilla"] = "Mozilla", ["firefox"] = "Mozilla Firefox",
        ["yandex"] = "Yandex", ["vk.com"] = "VK", ["vkontakte"] = "VK", ["mail.ru"] = "Mail.ru",
        ["twitch"] = "Twitch", ["github"] = "GitHub", ["gitlab"] = "GitLab",
        ["twitter"] = "X/Twitter",
        ["cloudfront"] = "AWS CloudFront", ["digitalocean"] = "DigitalOcean",
        ["hetzner"] = "Hetzner", ["ovh"] = "OVH",
        ["oracle"] = "Oracle Cloud", ["ibm"] = "IBM",
        ["alibaba"] = "Alibaba Cloud", ["tencent"] = "Tencent",
        ["netflix"] = "Netflix", ["spotify"] = "Spotify", ["zoom"] = "Zoom",
        ["slack"] = "Slack", ["dropbox"] = "Dropbox", ["adobe"] = "Adobe",
        ["samsung"] = "Samsung", ["nvidia"] = "NVIDIA",
        ["docker"] = "Docker Hub", ["ubuntu"] = "Ubuntu/Canonical",
        ["kaspersky"] = "Kaspersky", ["avast"] = "Avast", ["eset"] = "ESET",
        ["anthropic"] = "Anthropic", ["openai"] = "OpenAI", ["jetbrains"] = "JetBrains",
        ["stackoverflow"] = "Stack Overflow", ["cdn"] = "CDN",
        ["letsencrypt"] = "Let's Encrypt", ["total uptime"] = "ip-api.com (GeoIP)",
    };

    public static (RiskLevel risk, string service) Classify(string org, int port, bool isSigned)
    {
        if (string.IsNullOrEmpty(org)) return (RiskLevel.Unknown, "...");

        var orgLower = org.ToLowerInvariant();
        foreach (var (keyword, svcName) in KnownServices)
        {
            if (orgLower.Contains(keyword))
                return (RiskLevel.Safe, svcName);
        }

        if (org == "Local Network" || org == "LAN")
            return (RiskLevel.Safe, "LAN");

        if (org == "..." || org == "?")
            return (RiskLevel.Unknown, "...");

        if (port is 443 or 80 or 8080)
            return (RiskLevel.Unknown, org);

        // non-standard port + unknown org
        var risk = isSigned ? RiskLevel.Unknown : RiskLevel.Suspicious;
        return (risk, org);
    }
}
