package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	_ "modernc.org/sqlite"
)

// ── GeoIP ──

type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Org         string  `json:"org"`
	Flag        string  `json:"flag"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

var geoCache sync.Map
var httpGeo = &http.Client{Timeout: 3 * time.Second}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, p := range []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "0."} {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()
}

func countryFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	return string([]rune{rune(code[0]) - 'A' + 0x1F1E6, rune(code[1]) - 'A' + 0x1F1E6})
}

type ipAPIResp struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Org         string  `json:"org"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

func lookupGeo(ip string) GeoInfo {
	if v, ok := geoCache.Load(ip); ok {
		return v.(GeoInfo)
	}
	if isPrivateIP(ip) {
		info := GeoInfo{Country: "LAN", CountryCode: "LAN", Org: "Local Network", Flag: ""}
		geoCache.Store(ip, info)
		return info
	}
	go func() {
		resp, err := httpGeo.Get("http://ip-api.com/json/" + ip + "?fields=country,countryCode,org,lat,lon")
		if err != nil {
			geoCache.Store(ip, GeoInfo{Country: "?", CountryCode: "?", Org: "?", Flag: ""})
			return
		}
		defer resp.Body.Close()
		var raw ipAPIResp
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			geoCache.Store(ip, GeoInfo{Country: "?", CountryCode: "?", Org: "?", Flag: ""})
			return
		}
		geoCache.Store(ip, GeoInfo{
			Country: raw.Country, CountryCode: raw.CountryCode,
			Org: raw.Org, Flag: countryFlag(raw.CountryCode),
			Lat: raw.Lat, Lon: raw.Lon,
		})
	}()
	return GeoInfo{Country: "...", CountryCode: "...", Org: "...", Flag: ""}
}

// ── Traffic classification ──

var knownServices = map[string]string{
	"google": "Google", "youtube": "YouTube", "googleapis": "Google APIs",
	"microsoft": "Microsoft", "azure": "Microsoft Azure", "windows": "Microsoft",
	"live.com": "Microsoft", "office": "Microsoft Office",
	"amazon": "Amazon/AWS", "aws": "Amazon AWS",
	"cloudflare": "Cloudflare", "akamai": "Akamai CDN", "fastly": "Fastly CDN",
	"apple": "Apple", "icloud": "Apple iCloud",
	"meta": "Meta", "facebook": "Facebook", "instagram": "Instagram", "whatsapp": "WhatsApp",
	"valve": "Valve/Steam", "steam": "Steam", "discord": "Discord", "telegram": "Telegram",
	"mozilla": "Mozilla", "firefox": "Mozilla Firefox",
	"yandex": "Yandex", "vk.com": "VK", "vkontakte": "VK", "mail.ru": "Mail.ru",
	"twitch": "Twitch", "github": "GitHub", "gitlab": "GitLab", "twitter": "X/Twitter",
	"cloudfront": "AWS CloudFront", "digitalocean": "DigitalOcean", "hetzner": "Hetzner",
	"ovh": "OVH", "oracle": "Oracle Cloud", "ibm": "IBM",
	"alibaba": "Alibaba Cloud", "tencent": "Tencent",
	"netflix": "Netflix", "spotify": "Spotify", "zoom": "Zoom", "slack": "Slack",
	"dropbox": "Dropbox", "adobe": "Adobe", "samsung": "Samsung", "nvidia": "NVIDIA",
	"docker": "Docker Hub", "ubuntu": "Ubuntu/Canonical", "debian": "Debian", "redhat": "Red Hat",
	"kaspersky": "Kaspersky", "avast": "Avast", "eset": "ESET",
	"anthropic": "Anthropic", "openai": "OpenAI", "jetbrains": "JetBrains",
	"stackoverflow": "Stack Overflow", "cdn": "CDN", "letsencrypt": "Let's Encrypt",
	"total uptime": "ip-api.com (GeoIP)",
}

func classifyConn(org string, port uint32) (string, string) {
	orgLower := strings.ToLower(org)
	for keyword, svcName := range knownServices {
		if strings.Contains(orgLower, keyword) {
			return "green", svcName
		}
	}
	if org == "Local Network" || org == "LAN" {
		return "green", "LAN"
	}
	if org == "..." || org == "?" || org == "" {
		return "yellow", "..."
	}
	if port == 443 || port == 80 || port == 8080 {
		return "yellow", org
	}
	return "red", org
}

// ── Data ──

type ConnInfo struct {
	RemoteIP   string  `json:"remoteIP"`
	RemotePort uint32  `json:"remotePort"`
	Geo        GeoInfo `json:"geo"`
	Risk       string  `json:"risk"`
	Service    string  `json:"service"`
}

type ProcInfo struct {
	Name   string     `json:"name"`
	PID    int32      `json:"pid"`
	Conns  []ConnInfo `json:"conns"`
	Count  int        `json:"count"`
	Icon   string     `json:"icon"`
	Signed string     `json:"signed"` // "yes", "no", "unknown"
	Path   string     `json:"path"`
}

type Snapshot struct {
	Processes  []ProcInfo `json:"processes"`
	TotalConns int        `json:"totalConns"`
	TotalProcs int        `json:"totalProcs"`
	Error      string     `json:"error,omitempty"`
}

func procName(pid int32) string {
	if pid == 0 {
		return "System"
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return fmt.Sprintf("PID:%d", pid)
	}
	name, err := p.Name()
	if err != nil {
		return fmt.Sprintf("PID:%d", pid)
	}
	return name
}

// ── Process signature check ──

var signatureCache sync.Map // exe path -> "yes"/"no"/"unknown"

func hideCmd(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func checkSigned(pid int32) (signed string, exePath string) {
	if pid == 0 {
		return "yes", "System"
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return "unknown", ""
	}
	exe, err := p.Exe()
	if err != nil {
		return "unknown", ""
	}

	if v, ok := signatureCache.Load(exe); ok {
		return v.(string), exe
	}

	// async: verify digital signature via PowerShell for ALL processes
	signatureCache.Store(exe, "...") // temporary
	go func() {
		cmd := hideCmd(exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`(Get-AuthenticodeSignature '%s').Status`, exe)))
		out, err := cmd.Output()
		if err != nil {
			// fallback: trust Program Files / Windows paths
			exeLower := strings.ToLower(exe)
			if strings.HasPrefix(exeLower, "c:\\windows\\") ||
				strings.HasPrefix(exeLower, "c:\\program files\\") ||
				strings.HasPrefix(exeLower, "c:\\program files (x86)\\") {
				signatureCache.Store(exe, "yes")
			} else {
				signatureCache.Store(exe, "unknown")
			}
			return
		}
		status := strings.TrimSpace(string(out))
		if status == "Valid" {
			signatureCache.Store(exe, "yes")
		} else {
			signatureCache.Store(exe, "no")
		}
	}()
	return "...", exe
}

func collect() Snapshot {
	conns, err := psnet.ConnectionsWithContext(context.Background(), "tcp")
	if err != nil {
		return Snapshot{Error: "Запусти от администратора"}
	}
	byName := make(map[string]*ProcInfo)
	total := 0
	for _, c := range conns {
		if c.Status != "ESTABLISHED" || c.Raddr.IP == "" {
			continue
		}
		total++
		name := procName(c.Pid)
		pi, ok := byName[name]
		if !ok {
			icon := strings.ToUpper(name)
			if len(icon) > 2 {
				icon = icon[:2]
			}
			signed, exePath := checkSigned(c.Pid)
			pi = &ProcInfo{Name: name, PID: c.Pid, Icon: icon, Signed: signed, Path: exePath}
			byName[name] = pi
		}
		geo := lookupGeo(c.Raddr.IP)
		risk, service := classifyConn(geo.Org, c.Raddr.Port)
		// unsigned process with connections = boost risk
		if pi.Signed == "no" && risk == "yellow" {
			risk = "red"
		}
		pi.Conns = append(pi.Conns, ConnInfo{
			RemoteIP: c.Raddr.IP, RemotePort: c.Raddr.Port,
			Geo: geo, Risk: risk, Service: service,
		})
	}
	procs := make([]ProcInfo, 0, len(byName))
	for _, p := range byName {
		p.Count = len(p.Conns)
		procs = append(procs, *p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].Count > procs[j].Count })
	return Snapshot{Processes: procs, TotalConns: total, TotalProcs: len(procs)}
}

// ── SQLite History ──

var db *sql.DB

func initDB() {
	exePath, _ := os.Executable()
	dbPath := filepath.Join(filepath.Dir(exePath), "netwatch.db")
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts DATETIME DEFAULT (datetime('now','localtime')),
		process TEXT, remote_ip TEXT, remote_port INTEGER,
		country TEXT, org TEXT, service TEXT, risk TEXT, exe_path TEXT DEFAULT ''
	)`)
	// migrate old table: add exe_path if missing
	db.Exec(`ALTER TABLE connections ADD COLUMN exe_path TEXT DEFAULT ''`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_ts ON connections(ts)`)
	db.Exec(`DELETE FROM connections WHERE ts < datetime('now','localtime','-7 days')`)
}

var lastSeen sync.Map

func saveToHistory(snap Snapshot) {
	if db == nil {
		return
	}
	now := time.Now()
	tx, err := db.Begin()
	if err != nil {
		return
	}
	stmt, _ := tx.Prepare(`INSERT INTO connections(process,remote_ip,remote_port,country,org,service,risk,exe_path) VALUES(?,?,?,?,?,?,?,?)`)
	if stmt == nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()
	for _, p := range snap.Processes {
		for _, c := range p.Conns {
			key := p.Name + "|" + c.RemoteIP + "|" + fmt.Sprint(c.RemotePort)
			if v, ok := lastSeen.Load(key); ok {
				if now.Sub(v.(time.Time)) < 30*time.Second {
					continue
				}
			}
			lastSeen.Store(key, now)
			stmt.Exec(p.Name, c.RemoteIP, c.RemotePort, c.Geo.Country, c.Geo.Org, c.Service, c.Risk, p.Path)
		}
	}
	tx.Commit()
}

type HistoryPoint struct {
	Time  string `json:"time"`
	Total int    `json:"total"`
	Red   int    `json:"red"`
}

func getHistory(hours int) []HistoryPoint {
	if db == nil {
		return nil
	}
	rows, err := db.Query(`
		SELECT strftime('%Y-%m-%d %H:%M', ts) as bucket,
			COUNT(*) as total,
			SUM(CASE WHEN risk='red' THEN 1 ELSE 0 END) as red
		FROM connections
		WHERE ts > datetime('now','localtime','-'||?||' hours')
		GROUP BY bucket ORDER BY bucket`, hours)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var pts []HistoryPoint
	for rows.Next() {
		var p HistoryPoint
		rows.Scan(&p.Time, &p.Total, &p.Red)
		pts = append(pts, p)
	}
	return pts
}

// ── Alerts ──

type Alert struct {
	Time    string `json:"time"`
	Process string `json:"process"`
	IP      string `json:"ip"`
	Port    uint32 `json:"port"`
	Service string `json:"service"`
	Country string `json:"country"`
	Org     string `json:"org"`
	Reason  string `json:"reason"`
	ExePath string `json:"exePath"`
}

var (
	alertsMu   sync.Mutex
	alerts     []Alert
	alertsSeen sync.Map
)

func checkAlerts(snap Snapshot) {
	for _, p := range snap.Processes {
		for _, c := range p.Conns {
			if c.Risk != "red" {
				continue
			}
			key := p.Name + "|" + c.RemoteIP
			if _, seen := alertsSeen.LoadOrStore(key, true); seen {
				continue
			}
			reason := "Неизвестная организация, нестандартный порт"
			if p.Signed == "no" {
				reason = "Неподписанный процесс + подозрительное соединение"
			}
			alertsMu.Lock()
			alerts = append(alerts, Alert{
				Time: time.Now().Format("15:04:05"), Process: p.Name,
				IP: c.RemoteIP, Port: c.RemotePort, Service: c.Service,
				Country: c.Geo.Country, Org: c.Geo.Org, Reason: reason,
				ExePath: p.Path,
			})
			if len(alerts) > 100 {
				alerts = alerts[len(alerts)-100:]
			}
			alertsMu.Unlock()
		}
	}
}

func getAlerts() []Alert {
	alertsMu.Lock()
	defer alertsMu.Unlock()
	out := make([]Alert, len(alerts))
	copy(out, alerts)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func dismissAlerts() {
	alertsMu.Lock()
	alerts = nil
	alertsMu.Unlock()
}

// ── DNS Cache Monitor ──

type DNSEntry struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Record string `json:"record"`
}

var (
	dnsCache     []DNSEntry
	dnsCacheMu   sync.Mutex
	dnsCacheTime time.Time
)

var dnsNameRe = regexp.MustCompile(`(?m)^\s*Record Name[\s.]*:\s*(.+)$`)
var dnsTypeRe = regexp.MustCompile(`(?m)^\s*Record Type[\s.]*:\s*(.+)$`)
var dnsDataRe = regexp.MustCompile(`(?m)^\s*(?:A \(Host\)|AAAA|CNAME)[\s.]*:\s*(.+)$`)

func refreshDNSCache() {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if time.Since(dnsCacheTime) < 10*time.Second {
		return
	}
	cmd := hideCmd(exec.Command("ipconfig", "/displaydns"))
	out, err := cmd.Output()
	if err != nil {
		return
	}
	// parse sections separated by "---"
	sections := strings.Split(string(out), "----------------------------------------")
	var entries []DNSEntry
	seen := map[string]bool{}
	for _, sec := range sections {
		names := dnsNameRe.FindStringSubmatch(sec)
		if len(names) < 2 {
			continue
		}
		name := strings.TrimSpace(names[1])
		if seen[name] {
			continue
		}
		seen[name] = true

		rType := "A"
		if m := dnsTypeRe.FindStringSubmatch(sec); len(m) >= 2 {
			t := strings.TrimSpace(m[1])
			if strings.Contains(t, "28") {
				rType = "AAAA"
			} else if strings.Contains(t, "5") {
				rType = "CNAME"
			}
		}
		record := ""
		if m := dnsDataRe.FindStringSubmatch(sec); len(m) >= 2 {
			record = strings.TrimSpace(m[1])
		}
		entries = append(entries, DNSEntry{Name: name, Type: rType, Record: record})
	}
	dnsCache = entries
	dnsCacheTime = time.Now()
}

func getDNS() []DNSEntry {
	refreshDNSCache()
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	return dnsCache
}

// ── Bandwidth Tracking ──

type BandwidthPoint struct {
	Time    string  `json:"time"`
	InMbps  float64 `json:"inMbps"`
	OutMbps float64 `json:"outMbps"`
}

var (
	bwHistory   []BandwidthPoint
	bwMu        sync.Mutex
	prevBytesIn uint64
	prevBytesOut uint64
	prevBwTime  time.Time
)

func trackBandwidth() {
	counters, err := psnet.IOCountersWithContext(context.Background(), false)
	if err != nil || len(counters) == 0 {
		return
	}
	now := time.Now()
	totalIn := counters[0].BytesRecv
	totalOut := counters[0].BytesSent

	if prevBwTime.IsZero() {
		prevBytesIn = totalIn
		prevBytesOut = totalOut
		prevBwTime = now
		return
	}

	dt := now.Sub(prevBwTime).Seconds()
	if dt < 0.5 {
		return
	}
	inMbps := float64(totalIn-prevBytesIn) / dt * 8 / 1_000_000
	outMbps := float64(totalOut-prevBytesOut) / dt * 8 / 1_000_000

	prevBytesIn = totalIn
	prevBytesOut = totalOut
	prevBwTime = now

	bwMu.Lock()
	bwHistory = append(bwHistory, BandwidthPoint{
		Time: now.Format("15:04:05"), InMbps: inMbps, OutMbps: outMbps,
	})
	if len(bwHistory) > 200 {
		bwHistory = bwHistory[len(bwHistory)-200:]
	}
	bwMu.Unlock()
}

func getBandwidth() []BandwidthPoint {
	bwMu.Lock()
	defer bwMu.Unlock()
	out := make([]BandwidthPoint, len(bwHistory))
	copy(out, bwHistory)
	return out
}

// ── Server ──

func main() {
	initDB()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexHTML))
	})
	http.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(collect())
	})
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		hours := 1
		if h := r.URL.Query().Get("hours"); h == "6" {
			hours = 6
		} else if h == "24" {
			hours = 24
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getHistory(hours))
	})
	http.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getAlerts())
	})
	http.HandleFunc("/api/alerts/dismiss", func(w http.ResponseWriter, r *http.Request) {
		dismissAlerts()
		w.Write([]byte("ok"))
	})
	http.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getDNS())
	})
	http.HandleFunc("/api/bandwidth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getBandwidth())
	})
	http.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bye"))
		go func() { time.Sleep(200 * time.Millisecond); os.Exit(0) }()
	})

	// background loop
	go func() {
		for {
			snap := collect()
			saveToHistory(snap)
			checkAlerts(snap)
			trackBandwidth()
			time.Sleep(3 * time.Second)
		}
	}()

	addr := "127.0.0.1:8400"
	go func() {
		time.Sleep(400 * time.Millisecond)
		openBrowser("http://" + addr)
	}()
	fmt.Println("NetWatch -> http://" + addr)
	http.ListenAndServe(addr, nil)
}

func openBrowser(url string) {
	if runtime.GOOS == "windows" {
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	} else {
		exec.Command("xdg-open", url).Start()
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>NetWatch</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0b1120;color:#c9d1d9;display:flex;flex-direction:column;height:100vh;overflow:hidden}
#hdr{background:#151d2e;padding:8px 20px;border-bottom:1px solid #1e2d3d;display:flex;align-items:center;gap:14px;flex-shrink:0}
#hdr h1{font-size:15px;color:#7eb8f7;letter-spacing:1px}
.st{font-size:12px;color:#6b7b8d}
.dot{width:8px;height:8px;border-radius:50%;background:#34d058;display:inline-block;animation:pp 2s infinite}
@keyframes pp{0%,100%{opacity:1}50%{opacity:.3}}
.hdr-r{margin-left:auto;display:flex;gap:10px;align-items:center}
.lg{display:flex;gap:10px;font-size:11px;color:#6b7b8d;align-items:center}
.lg span{display:flex;align-items:center;gap:3px}
.ld{width:8px;height:8px;border-radius:50%;display:inline-block}
.btn{border-radius:4px;padding:4px 12px;font-size:11px;cursor:pointer;font-family:inherit;border:1px solid;transition:background .15s}
.btn-red{background:#2a1520;color:#f85149;border-color:#5a2020}.btn-red:hover{background:#3b1a1a}
.abadge{background:#f85149;color:#fff;border-radius:10px;padding:1px 7px;font-size:10px;font-weight:700;cursor:pointer;display:none}
.abadge:hover{background:#ff6b6b}
.apop{position:absolute;top:44px;right:20px;background:#1a2332;border:1px solid #2a3a4a;border-radius:8px;width:420px;max-height:320px;overflow-y:auto;z-index:200;display:none;box-shadow:0 8px 30px #0008}
.apop.show{display:block}
.ai{padding:8px 12px;border-bottom:1px solid #1e2d3d;font-size:11px}
.ai:last-child{border:none}
.ai-t{color:#5a6a7a;font-size:10px}.ai-p{color:#f07178;font-weight:600}.ai-d{color:#8b949e;margin-top:2px}
.ai-reason{color:#e3b341;font-size:10px;margin-top:2px}
.adismiss{padding:6px;text-align:center;cursor:pointer;color:#6b7b8d;font-size:11px;border-top:1px solid #1e2d3d}.adismiss:hover{color:#c9d1d9}
#wrap{display:flex;flex:1;min-height:0;overflow:hidden}
#side{width:210px;min-width:210px;background:#0d1525;border-right:1px solid #1e2d3d;overflow-y:auto;flex-shrink:0}
#side::-webkit-scrollbar{width:4px}
#side::-webkit-scrollbar-thumb{background:#1e2d3d;border-radius:2px}
.pi{display:flex;align-items:center;gap:8px;padding:8px 10px;cursor:pointer;border-bottom:1px solid #151d2e;transition:background .15s}
.pi:hover{background:#151d2e}
.pi.sel{background:#1f6feb15;border-left:3px solid #7eb8f7}
.pic{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:10px;flex-shrink:0}
.pin{font-size:11px;font-weight:600;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pis{font-size:10px;color:#6b7b8d}
.pi-signed{font-size:9px;margin-top:1px}
.pi-signed.yes{color:#34d058}.pi-signed.no{color:#f85149}.pi-signed.unknown{color:#6b7b8d}
.pir{display:flex;gap:2px;margin-top:2px}
.rp{width:7px;height:7px;border-radius:50%;display:inline-block}
#dash{flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px}
#dash::-webkit-scrollbar{width:5px}
#dash::-webkit-scrollbar-thumb{background:#1e2d3d;border-radius:3px}
.cards{display:flex;gap:10px;flex-wrap:wrap}
.card{background:#151d2e;border:1px solid #1e2d3d;border-radius:8px;padding:12px 16px;min-width:100px;flex:1}
.card-val{font-size:24px;font-weight:700;line-height:1}
.card-lbl{font-size:10px;color:#6b7b8d;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.sec{background:#151d2e;border:1px solid #1e2d3d;border-radius:8px;padding:14px 18px}
.sec-t{font-size:12px;font-weight:600;color:#8b9bab;margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px;display:flex;align-items:center;gap:8px}
.sec-t .tabs{margin-left:auto;display:flex;gap:4px}
.tab{padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;color:#6b7b8d;background:transparent;border:1px solid #1e2d3d;font-family:inherit}
.tab.active{background:#1f6feb20;color:#7eb8f7;border-color:#1f6feb40}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:12px}
.bar-label{width:130px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;text-align:right;color:#9ba8b8}
.bar-track{flex:1;height:18px;background:#0b1120;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .5s;display:flex;align-items:center;padding-left:6px;font-size:10px;font-weight:600;color:#fff;white-space:nowrap}
.fi{display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid #1a2435;font-size:12px}
.fi:last-child{border:none}
.fi-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.fi-proc{font-weight:600;width:90px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.fi-svc{color:#8bc48a;width:90px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.fi-ip{font-family:'Cascadia Code','Fira Code',monospace;color:#6b7b8d;font-size:11px}
.fi-geo{color:#5a6a7a;margin-left:auto;white-space:nowrap}
.dns-item{display:flex;gap:8px;padding:3px 0;border-bottom:1px solid #1a2435;font-size:11px}
.dns-name{color:#7eb8f7;flex:1;word-break:break-all}
.dns-type{color:#5a6a7a;width:45px;flex-shrink:0}
.dns-record{color:#8b949e;font-family:'Cascadia Code',monospace;font-size:10px;width:130px;flex-shrink:0;text-align:right}
canvas.chart{width:100%;height:80px;display:block;margin-top:6px}
.err{background:#3b1a1a;color:#f85149;padding:6px 20px;font-size:12px;border-bottom:1px solid #5a2020;flex-shrink:0}
</style></head><body>
<div id="hdr">
  <span class="dot"></span><h1>NETWATCH</h1><span class="st" id="stats">...</span>
  <div class="hdr-r">
    <div class="lg"><span><span class="ld" style="background:#34d058"></span>OK</span><span><span class="ld" style="background:#e3b341"></span>Неизв.</span><span><span class="ld" style="background:#f85149"></span>Подозр.</span></div>
    <span class="abadge" id="abadge" onclick="toggleA()">0</span>
    <button class="btn btn-red" onclick="if(confirm('Выключить?'))fetch('/api/shutdown').then(()=>window.close())">Выкл</button>
  </div>
</div>
<div class="apop" id="apop"></div>
<div id="err" class="err" style="display:none"></div>
<div id="wrap"><div id="side"></div><div id="dash"></div></div>
<script>
const RC={green:'#34d058',yellow:'#e3b341',red:'#f85149'};
let data=null,selProc=null,histH=1,prevAC=0;
const PC={},PAL=['#7eb8f7','#34d058','#c4a0f5','#e3964a','#f07178','#82cfc9','#9cd674','#d4a0e8','#e3b341','#61afef','#c678dd','#98c379'];
function hc(n){if(PC[n])return PC[n];let h=0;for(let i=0;i<n.length;i++)h=((h<<5)-h+n.charCodeAt(i))|0;return PC[n]=PAL[Math.abs(h)%PAL.length]}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}

if('Notification' in window) Notification.requestPermission();
const beepCtx=new (window.AudioContext||window.webkitAudioContext)();
function beep(){try{const o=beepCtx.createOscillator(),g=beepCtx.createGain();o.connect(g);g.connect(beepCtx.destination);o.frequency.value=800;g.gain.value=0.2;o.start();o.stop(beepCtx.currentTime+0.12)}catch(e){}}

function renderSide(){
  const sb=document.getElementById('side');
  const procs=data.processes||[];
  sb.innerHTML=procs.map(p=>{
    const col=hc(p.name);
    let rg=0,ry=0,rr=0;
    p.conns.forEach(c=>{if(c.risk==='green')rg++;else if(c.risk==='yellow')ry++;else rr++});
    let pips='';
    for(let i=0;i<Math.min(rg,6);i++) pips+='<span class="rp" style="background:#34d058"></span>';
    for(let i=0;i<Math.min(ry,4);i++) pips+='<span class="rp" style="background:#e3b341"></span>';
    for(let i=0;i<Math.min(rr,4);i++) pips+='<span class="rp" style="background:#f85149"></span>';
    const sel=selProc===p.name?' sel':'';
    const signedCls=p.signed||'unknown';
    const signedTxt=p.signed==='yes'?'✓ Подписан':p.signed==='no'?'✗ Не подписан!':'⏳ проверка...';
    const shortPath=p.path?p.path.length>30?'...'+p.path.slice(-30):p.path:'';
    return '<div class="pi'+sel+'" onclick="ck(\''+p.name.replace(/'/g,"\\'")+'\')" title="'+esc(p.path||'')+'">'+'<div class="pic" style="background:'+col+'20;color:'+col+'">'+esc(p.icon)+'</div>'+'<div><div class="pin">'+esc(p.name)+'</div><div class="pis">'+p.count+' conn</div><div class="pi-signed '+signedCls+'">'+signedTxt+'</div>'+(shortPath?'<div style="font-size:9px;color:#4a5a6a;margin-top:1px;word-break:break-all">'+esc(shortPath)+'</div>':'')+'<div class="pir">'+pips+'</div></div></div>';
  }).join('');
}
function ck(n){selProc=selProc===n?null:n;render()}

function renderDash(){
  const procs=data.processes||[];
  let allConns=[],riskG=0,riskY=0,riskR=0,svcMap={},countryMap={};
  let signedYes=0,signedNo=0;
  for(const p of procs){
    if(p.signed==='yes')signedYes++;else if(p.signed==='no')signedNo++;
    for(const c of p.conns){
      if(selProc&&selProc!==p.name) continue;
      allConns.push({proc:p.name,conn:c,signed:p.signed});
      if(c.risk==='green')riskG++;else if(c.risk==='yellow')riskY++;else riskR++;
      const sk=c.service||c.remoteIP;
      if(!svcMap[sk])svcMap[sk]={name:sk,count:0,risk:c.risk};svcMap[sk].count++;
      if(c.risk==='red')svcMap[sk].risk='red';
      const ck2=c.geo.country||'?';
      if(ck2!=='LAN'&&ck2!=='...'&&ck2!=='?'){if(!countryMap[ck2])countryMap[ck2]={name:ck2,count:0};countryMap[ck2].count++}
    }
  }
  const total=allConns.length;
  const topSvc=Object.values(svcMap).sort((a,b)=>b.count-a.count).slice(0,10);
  const topCountry=Object.values(countryMap).sort((a,b)=>b.count-a.count).slice(0,8);
  const maxSvc=topSvc[0]?topSvc[0].count:1;
  const maxCountry=topCountry[0]?topCountry[0].count:1;

  let h='';
  h+='<div class="cards">';
  h+='<div class="card"><div class="card-val" style="color:#7eb8f7">'+total+'</div><div class="card-lbl">Соединений</div></div>';
  h+='<div class="card"><div class="card-val" style="color:#34d058">'+riskG+'</div><div class="card-lbl">Известных</div></div>';
  h+='<div class="card"><div class="card-val" style="color:#e3b341">'+riskY+'</div><div class="card-lbl">Неизвестных</div></div>';
  h+='<div class="card"><div class="card-val" style="color:#f85149">'+riskR+'</div><div class="card-lbl">Подозрительных</div></div>';
  h+='<div class="card"><div class="card-val" style="color:#34d058">'+signedYes+'</div><div class="card-lbl">Подписанных</div></div>';
  if(signedNo>0) h+='<div class="card"><div class="card-val" style="color:#f85149">'+signedNo+'</div><div class="card-lbl">Не подписанных!</div></div>';
  h+='</div>';

  // bandwidth chart
  h+='<div class="sec"><div class="sec-t">Скорость сети (Mbps)</div><canvas class="chart" id="bwChart"></canvas></div>';

  // history chart
  h+='<div class="sec"><div class="sec-t">История соединений<div class="tabs">';
  h+='<button class="tab'+(histH===1?' active':'')+'" onclick="histH=1;loadHist()">1ч</button>';
  h+='<button class="tab'+(histH===6?' active':'')+'" onclick="histH=6;loadHist()">6ч</button>';
  h+='<button class="tab'+(histH===24?' active':'')+'" onclick="histH=24;loadHist()">24ч</button>';
  h+='</div></div><canvas class="chart" id="histChart"></canvas></div>';

  // top services
  h+='<div class="sec"><div class="sec-t">Топ сервисов'+(selProc?' ('+esc(selProc)+')':'')+'</div>';
  for(const s of topSvc){const pct=Math.round(s.count/maxSvc*100);const rc=RC[s.risk]||'#6b7b8d';h+='<div class="bar-row"><div class="bar-label">'+esc(s.name)+'</div><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+rc+'">'+s.count+'</div></div></div>'}
  h+='</div>';

  if(topCountry.length){
    h+='<div class="sec"><div class="sec-t">Топ стран</div>';
    for(const c of topCountry){const pct=Math.round(c.count/maxCountry*100);h+='<div class="bar-row"><div class="bar-label">'+esc(c.name)+'</div><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:#7eb8f7">'+c.count+'</div></div></div>'}
    h+='</div>';
  }

  // DNS cache
  h+='<div class="sec" id="dnsSec"><div class="sec-t">DNS кэш (последние запросы)</div><div id="dnsList">загрузка...</div></div>';

  // feed
  h+='<div class="sec"><div class="sec-t">Все соединения ('+total+')</div>';
  for(const{proc,conn:c,signed} of allConns){
    const rc=RC[c.risk]||'#6b7b8d';const col=hc(proc);
    const signIcon=signed==='no'?' <span style="color:#f85149" title="Не подписан">⚠</span>':'';
    h+='<div class="fi"><span class="fi-dot" style="background:'+rc+'"></span><span class="fi-proc" style="color:'+col+'">'+esc(proc)+signIcon+'</span><span class="fi-svc">'+esc(c.service)+'</span><span class="fi-ip">'+esc(c.remoteIP)+':'+c.remotePort+'</span><span class="fi-geo">'+esc(c.geo.country)+'</span></div>';
  }
  h+='</div>';

  document.getElementById('dash').innerHTML=h;
  loadHist();loadBW();loadDNS();
}

// ── Charts ──
async function loadHist(){try{const r=await fetch('/api/history?hours='+histH);drawLineChart('histChart',await r.json()||[],'total','red','#7eb8f7','#f85149')}catch(e){}}
async function loadBW(){try{const r=await fetch('/api/bandwidth');drawBWChart(await r.json()||[])}catch(e){}}

function drawLineChart(id,pts,k1,k2,c1,c2){
  const cv=document.getElementById(id);if(!cv)return;
  const W=cv.clientWidth,H=cv.clientHeight;cv.width=W*devicePixelRatio;cv.height=H*devicePixelRatio;
  const ctx=cv.getContext('2d');ctx.scale(devicePixelRatio,devicePixelRatio);ctx.clearRect(0,0,W,H);
  if(!pts.length){ctx.fillStyle='#3a4a5a';ctx.font='12px Segoe UI';ctx.textAlign='center';ctx.fillText('Нет данных',W/2,H/2);return}
  const maxV=Math.max(...pts.map(p=>p[k1]),1);
  const sx=W/(pts.length-1||1);
  // area
  ctx.beginPath();pts.forEach((p,i)=>{const x=i*sx,y=H-p[k1]/maxV*(H-12)-5;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});
  ctx.strokeStyle=c1+'90';ctx.lineWidth=2;ctx.stroke();
  ctx.lineTo((pts.length-1)*sx,H);ctx.lineTo(0,H);ctx.closePath();ctx.fillStyle=c1+'15';ctx.fill();
  // k2 line
  const maxR=Math.max(...pts.map(p=>p[k2]||0),0);
  if(maxR>0){ctx.beginPath();pts.forEach((p,i)=>{const x=i*sx,y=H-(p[k2]||0)/maxV*(H-12)-5;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.strokeStyle=c2+'70';ctx.lineWidth=1.5;ctx.stroke()}
  ctx.fillStyle='#4a5a6a';ctx.font='9px Segoe UI';ctx.textAlign='left';ctx.fillText(maxV+'',2,12);
}

function drawBWChart(pts){
  const cv=document.getElementById('bwChart');if(!cv)return;
  const W=cv.clientWidth,H=cv.clientHeight;cv.width=W*devicePixelRatio;cv.height=H*devicePixelRatio;
  const ctx=cv.getContext('2d');ctx.scale(devicePixelRatio,devicePixelRatio);ctx.clearRect(0,0,W,H);
  if(!pts.length){ctx.fillStyle='#3a4a5a';ctx.font='12px Segoe UI';ctx.textAlign='center';ctx.fillText('Собираю данные...',W/2,H/2);return}
  const maxV=Math.max(...pts.map(p=>Math.max(p.inMbps,p.outMbps)),0.01);
  const sx=W/(pts.length-1||1);
  // download
  ctx.beginPath();pts.forEach((p,i)=>{const x=i*sx,y=H-p.inMbps/maxV*(H-14)-5;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});
  ctx.strokeStyle='#34d058aa';ctx.lineWidth=2;ctx.stroke();
  // upload
  ctx.beginPath();pts.forEach((p,i)=>{const x=i*sx,y=H-p.outMbps/maxV*(H-14)-5;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});
  ctx.strokeStyle='#e3b341aa';ctx.lineWidth=1.5;ctx.stroke();
  // labels
  ctx.fillStyle='#34d058';ctx.font='9px Segoe UI';ctx.textAlign='left';ctx.fillText('↓ '+pts[pts.length-1].inMbps.toFixed(2)+' Mbps',4,12);
  ctx.fillStyle='#e3b341';ctx.textAlign='right';ctx.fillText('↑ '+pts[pts.length-1].outMbps.toFixed(2)+' Mbps',W-4,12);
  ctx.fillStyle='#4a5a6a';ctx.textAlign='left';ctx.fillText(maxV.toFixed(1),4,H-2);
}

// ── DNS ──
async function loadDNS(){
  try{
    const r=await fetch('/api/dns');
    const list=await r.json()||[];
    const el=document.getElementById('dnsList');if(!el)return;
    if(!list.length){el.innerHTML='<div style="color:#4a5a6a;font-size:12px">DNS кэш пуст</div>';return}
    el.innerHTML=list.slice(0,50).map(d=>'<div class="dns-item"><span class="dns-name">'+esc(d.name)+'</span><span class="dns-type">'+esc(d.type)+'</span><span class="dns-record">'+esc(d.record)+'</span></div>').join('');
  }catch(e){}
}

// ── Alerts ──
async function loadAlerts(){
  try{
    const r=await fetch('/api/alerts');const list=await r.json()||[];
    const b=document.getElementById('abadge');
    if(list.length>0){b.textContent=list.length;b.style.display='inline'}else{b.style.display='none'}
    if(list.length>prevAC&&prevAC>=0){
      const n=list[0];
      if(n){beep();if('Notification' in window&&Notification.permission==='granted')new Notification('NetWatch',{body:n.process+' → '+n.ip+':'+n.port+'\n'+n.reason})}
    }
    prevAC=list.length;
    const pop=document.getElementById('apop');
    if(!list.length){pop.innerHTML='<div style="padding:12px;color:#4a5a6a;text-align:center">Нет алертов</div>';return}
    pop.innerHTML=list.map(a=>'<div class="ai"><div><span class="ai-t">'+esc(a.time)+'</span> <span class="ai-p">'+esc(a.process)+'</span></div><div class="ai-d">'+esc(a.ip)+':'+a.port+' '+esc(a.org)+' ('+esc(a.country)+')</div>'+(a.exePath?'<div class="ai-d" style="color:#7eb8f7;font-size:10px">'+esc(a.exePath)+'</div>':'')+'<div class="ai-reason">'+esc(a.reason)+'</div></div>').join('')+'<div class="adismiss" onclick="dismissA()">Очистить</div>';
  }catch(e){}
}
function toggleA(){document.getElementById('apop').classList.toggle('show')}
async function dismissA(){await fetch('/api/alerts/dismiss',{method:'POST'});prevAC=0;document.getElementById('apop').classList.remove('show');document.getElementById('abadge').style.display='none'}
document.addEventListener('click',e=>{if(!e.target.closest('.abadge')&&!e.target.closest('.apop'))document.getElementById('apop').classList.remove('show')});

function render(){renderSide();renderDash()}
async function refresh(){
  try{
    const r=await fetch('/api/snapshot');data=await r.json();
    const e=document.getElementById('err');
    if(data.error){e.textContent=data.error;e.style.display=''}else{e.style.display='none'}
    document.getElementById('stats').textContent=data.totalProcs+' процессов, '+data.totalConns+' соединений';
    document.title='NetWatch — '+data.totalProcs+' проц., '+data.totalConns+' соед.';
    render();loadAlerts();
  }catch(e){document.getElementById('stats').textContent='ошибка'}
}
refresh();setInterval(refresh,3000);
</script></body></html>`
