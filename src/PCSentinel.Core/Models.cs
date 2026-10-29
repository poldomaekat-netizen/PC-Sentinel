using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Net;

namespace PCSentinel.Core;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    protected void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value; Changed(name); return true;
    }
}

public record MachineSample(DateTimeOffset TimestampUtc, double? CpuPct, double RamPct,
    ulong RamUsedBytes, ulong RamTotalBytes, ulong CommitBytes, ulong CommitLimitBytes,
    double? DiskActivePct, double? DiskReadBps, double? DiskWriteBps,
    double? DiskLatencyMs, double? DiskQueue, double? DiskFillPct,
    double? NetDownBps, double? NetUpBps, string NetworkName);
public record ProcessSample(DateTimeOffset TimestampUtc, int Pid, DateTimeOffset? StartTimeUtc,
    string Name, string? Path, double? CpuPct, long WorkingSetBytes, long? PrivateBytes = null,
    double? ReadBps = null, double? WriteBps = null, string Quality = "CPU/WorkingSet; I/O недоступен")
{
    public string InstanceId => $"{Pid}:{StartTimeUtc?.UtcTicks.ToString() ?? "unknown"}";
}
public record HardwareItem(string ComponentType, string Name, string Details);
public record AdapterInfo(string Id, string Name, string Description, int Index4, int Index6,
    bool Up, string Kind, string Gateway, bool HasIpv6, bool HasIp = true, bool? HardwareInterface = null, bool? FilterInterface = null, uint? NativeTunnelType = null)
{
    public override string ToString() => $"{Name} · {Kind}";
}
public enum VpnState { Protected, Unprotected, Unknown, Offline, Checking, Disconnected, Partial }
public record NetworkCheck(DateTimeOffset TimestampUtc, string? IpV4, string? IpV6,
    VpnState State, string Route, string Reason, string? AdapterId = null, bool RoutesVerified = false,
    bool TunnelVerified = false, bool Agree4 = false, bool Agree6 = false, bool HasIpv6 = false,
    bool Proxy = false, IReadOnlyList<SiteCheckResult>? Sites = null);
public record AlertEvent(DateTimeOffset TimestampUtc, string Type, string Severity, string Description);

public sealed class AppSettings
{
    public int ConfigVersion { get; set; } = 3;
    public int RefreshSeconds { get; set; } = 1;
    public bool MinimizeToTray { get; set; } = true;
    public bool AlwaysOnTop { get; set; }
    public bool AutoStart { get; set; }
    public bool EnableHardwareTemperatureHelper {get;set;}
    public bool EnablePublicIp { get; set; } = true;
    public string TrustedPublicIp { get; set; } = "";
    public string TrustedPublicIpv6 { get; set; } = "";
    public bool NetworkMegabits { get; set; }
    public AnomalySettings Anomalies { get; set; } = new();
    public bool ReadDefenderEvents { get; set; } = true;
    public bool ReadSysmonEvents { get; set; }
    public bool EnableNotifications { get; set; } = true;
    public string PreferredAdapterId { get; set; } = "";
    public string ApprovedIps { get; set; } = "";
    public string LegacyApprovedIps { get; set; } = "";
    public bool AutoDetectVpn { get; set; } = true;
    public VpnProfile? VpnProfile { get; set; }
    public int NetworkIntervalSeconds { get; set; } = 30;
    public List<SiteTarget> ControlSites { get; set; } = [new("https://google.com"), new("https://yandex.ru"), new("https://cloudflare.com")];
    public bool EnableSiteChecks { get; set; }
    public int BackgroundTransparency { get; set; } = 25;
    public WidgetSettings Widget { get; set; } = new();
    public double CpuTemperatureWarning { get; set; } = 85;
    public double CpuTemperatureCritical { get; set; } = 95;
    public double GpuTemperatureWarning { get; set; } = 80;
    public double GpuTemperatureCritical { get; set; } = 90;
    public double SsdTemperatureWarning { get; set; } = 60;
    public double SsdTemperatureCritical { get; set; } = 75;
    public int WarningThreshold { get; set; } = 60;
    public int CriticalThreshold { get; set; } = 85;
    public int AlertDurationSeconds { get; set; } = 15;
    public int AlertCooldownSeconds { get; set; } = 300;
    public int RawHistoryDays { get; set; } = 7;
    public int AggregateHistoryDays { get; set; } = 90;
    public int EventHistoryDays { get; set; } = 180;
    public void Validate()
    {
        if (BackgroundTransparency is < 0 or > 75 || Widget.BackgroundTransparency is < 0 or > 75) throw new ArgumentException("Прозрачность фона: 0–75%.");
        TrustedPublicIp=PublicAddress.Normalize(TrustedPublicIp, System.Net.Sockets.AddressFamily.InterNetwork);
        TrustedPublicIpv6=PublicAddress.Normalize(TrustedPublicIpv6, System.Net.Sockets.AddressFamily.InterNetworkV6);
        Anomalies.Validate();
        if (NetworkIntervalSeconds is < 15 or > 600) throw new ArgumentException("Проверка сети: 15–600 секунд.");
        if (Widget.Scale is < 0.75 or > 2 || !double.IsFinite(Widget.Scale)) throw new ArgumentException("Масштаб виджета: 0.75–2.");
        if (!double.IsFinite(Widget.Left) || !double.IsFinite(Widget.Top)) throw new ArgumentException("Некорректные координаты виджета.");
        foreach (var (warning, critical) in new[] { (CpuTemperatureWarning,CpuTemperatureCritical), (GpuTemperatureWarning,GpuTemperatureCritical), (SsdTemperatureWarning,SsdTemperatureCritical) })
            if (!double.IsFinite(warning) || !double.IsFinite(critical) || warning < 20 || critical <= warning || critical > 125) throw new ArgumentException("Температуры: 20 ≤ предупреждение < критический порог ≤ 125 °C.");
        if (ControlSites.Count > 12) throw new ArgumentException("Не более 12 контрольных сайтов.");
        foreach (var site in ControlSites) _ = SiteTarget.Normalize(site.Url);
        if (RefreshSeconds is < 1 or > 5) throw new ArgumentException("Обновление: от 1 до 5 секунд.");
        if (WarningThreshold < 1 || CriticalThreshold <= WarningThreshold || CriticalThreshold > 100)
            throw new ArgumentException("Пороги: 1 ≤ жёлтый < красный ≤ 100.");
        if (AlertDurationSeconds is < 5 or > 3600 || AlertCooldownSeconds is < 30 or > 86400)
            throw new ArgumentException("Задержка: 5–3600 с; повтор: 30–86400 с.");
        if (RawHistoryDays is < 1 or > 30 || AggregateHistoryDays is < 1 or > 365 || EventHistoryDays is < 1 or > 365)
            throw new ArgumentException("История: сырые данные 1–30, агрегаты/события 1–365 дней.");
        foreach (var entry in ApprovedIps.Split([',',';','\n','\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (!IpRange.IsValid(entry)) throw new ArgumentException($"Некорректный IP/диапазон: {entry}");
    }
}

public sealed record VpnProfile(string AdapterId, string AdapterDescription, string? BaselineIp4, string? BaselineIp6, DateTimeOffset CreatedUtc);
public sealed record SiteCheckResult(string Url, double? DnsMs, double? HttpsMs, int? HttpStatus, string Status, DateTimeOffset TimestampUtc);
public sealed class SiteTarget(string url = "https://example.com", bool enabled = true)
{
    public string Url { get; set; } = url;
    public bool Enabled { get; set; } = enabled;
    public static string Normalize(string text)
    {
        if (!Uri.TryCreate(text.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            string.IsNullOrWhiteSpace(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("Укажите HTTPS-адрес без логина, пароля, query и fragment.");
        return uri.AbsoluteUri;
    }
}
public sealed class WidgetSettings
{
    public bool VisibleOnStartup { get; set; }
    public bool Topmost { get; set; }
    public bool Locked { get; set; }
    public bool Compact { get; set; }
    public double Scale { get; set; } = 1;
    public int BackgroundTransparency { get; set; } = 30;
    public double Left { get; set; } = 40;
    public double Top { get; set; } = 80;
    public string MonitorDevice { get; set; } = "";
    public string Dock { get; set; } = "None";
    public bool ShowCpu { get; set; } = true;
    public bool ShowRam { get; set; } = true;
    public bool ShowGpu { get; set; } = true;
    public bool ShowDisk { get; set; } = true;
    public bool ShowNetwork { get; set; } = true;
    public bool ShowVpn { get; set; } = true;
}
public enum SensorKind { Temperature, Utilization, MemoryUsed, MemoryTotal, Clock, Power, Fan, Wear, ReadErrors, WriteErrors, PowerOnHours }
public enum SensorStatus { Available, Unsupported, AccessDenied, Unavailable, Error }
public record SensorReading(string HardwareId, string HardwareName, string DeviceType, SensorKind Kind, string Name,
    double? Value, string Unit, string Source, DateTimeOffset TimestampUtc, SensorStatus Status, string? Reason = null)
{
    public string Id => $"{HardwareId}|{Source}|{Name}";
}
public interface ISensorProvider : IDisposable
{
    string Name { get; }
    TimeSpan Interval { get; }
    IReadOnlyList<SensorReading> Read(CancellationToken token);
}
public static class SensorValues
{
    public static double? Validate(SensorKind kind, double? value) => value is null || !double.IsFinite(value.Value) ||
        kind == SensorKind.Temperature && (value < -20 || value > 150) ||
        kind == SensorKind.Utilization && (value < 0 || value > 100) || kind != SensorKind.Temperature && value < 0 ? null : value;
}

public static class IpRange
{
    public static bool IsValid(string range)
    {
        var p = range.Split('/');
        return p.Length <= 2 && IPAddress.TryParse(p[0], out var ip) &&
            (p.Length == 1 || int.TryParse(p[1], out var bits) && bits >= 0 && bits <= ip.GetAddressBytes().Length * 8);
    }
    public static bool Contains(string range, string value)
    {
        if (!IsValid(range) || !IPAddress.TryParse(value, out var valueIp)) return false;
        var p = range.Split('/'); var a = IPAddress.Parse(p[0]).GetAddressBytes(); var b = valueIp.GetAddressBytes();
        if (a.Length != b.Length) return false;
        var bits = p.Length == 1 ? a.Length * 8 : int.Parse(p[1]);
        for (var i = 0; i < a.Length; i++)
        {
            var mask = (byte)(0xff << (8 - Math.Clamp(bits - i * 8, 0, 8)));
            if ((a[i] & mask) != (b[i] & mask)) return false;
        }
        return true;
    }
    public static bool Approved(string rules, string ip) => rules.Split([',',';','\n','\r'],
        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(r => Contains(r, ip));
}

public static class MetricsMath
{
    public static double? Cpu(ulong previousIdle, ulong previousKernel, ulong previousUser, ulong idle, ulong kernel, ulong user)
    {
        if (idle < previousIdle || kernel < previousKernel || user < previousUser) return null;
        var total = kernel - previousKernel + user - previousUser;
        if (total == 0 || idle - previousIdle > total) return null;
        return Math.Clamp(100d * (total - (idle - previousIdle)) / total, 0, 100);
    }
    public static double? ProcessCpu(double deltaMilliseconds, double elapsedMilliseconds, int cores) =>
        elapsedMilliseconds <= 0 || cores <= 0 || deltaMilliseconds < 0 ? null :
            Math.Clamp(100 * deltaMilliseconds / elapsedMilliseconds / cores, 0, 100);
}
