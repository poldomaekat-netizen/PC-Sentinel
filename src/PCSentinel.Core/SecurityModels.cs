using System.Net;
using System.Net.Sockets;
namespace PCSentinel.Core;

public static class PublicAddress
{
    public static string Normalize(string text, AddressFamily family)
    {
        if (text.Length == 0) return "";
        if (text.Any(char.IsWhiteSpace) || text.Contains('%') || !IPAddress.TryParse(text,out var ip) || ip.AddressFamily!=family)
            throw new ArgumentException("Нужен IP-адрес указанного семейства без URL, домена, пробелов и CIDR.");
        var canonical=ip.ToString();
        // Reject legacy shortened/octal IPv4 notation accepted by IPAddress.TryParse.
        if (family==AddressFamily.InterNetwork && canonical!=text) throw new ArgumentException("IPv4: четыре десятичных числа без ведущих нулей.");
        var excluded=family==AddressFamily.InterNetwork
            ? new[]{"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.88.99.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/3"}
            : new[]{"::/96","::ffff:0:0/96","64:ff9b::/96","64:ff9b:1::/48","100::/64","2001::/23","2001:db8::/32","2002::/16","3fff::/20","fc00::/7","fe80::/10","fec0::/10","ff00::/8"};
        if(excluded.Any(r=>IpRange.Contains(r,canonical)) || family==AddressFamily.InterNetworkV6 && !IpRange.Contains("2000::/3",canonical))
            throw new ArgumentException("Это локальный, частный или зарезервированный адрес. Укажите публичный адрес выхода в интернет.");
        return canonical;
    }
}
public enum IpTrustState { Trusted, Changed, NotConfigured, Unknown }
public record IpObservation(DateTimeOffset TimestampUtc,string? Ipv4,string? Ipv6,bool Agree4,bool Agree6,string Source,string Reason,bool Online=true);
public record IpTrustResult(IpTrustState State,string Label,string Reason);
public static class IpTrustPolicy
{
    public static IpTrustResult Evaluate(string trusted,IpObservation? current,bool enabled,DateTimeOffset now,TimeSpan maxAge)
    {
        if(string.IsNullOrEmpty(trusted))return new(IpTrustState.NotConfigured,"Не настроен","Укажите доверенный публичный IPv4.");
        if(!enabled || current==null || !current.Online || !current.Agree4 || current.Ipv4==null || now-current.TimestampUtc>maxAge || current.TimestampUtc>now.AddSeconds(5))
            return new(IpTrustState.Unknown,"Не удалось проверить",current?.Reason??"Нет свежего согласованного измерения.");
        return current.Ipv4==trusted?new(IpTrustState.Trusted,"Доверенный IP","Совпадает IPv4 самого PC Sentinel; это не доказательство защиты VPN."):
            new(IpTrustState.Changed,"IP изменился","Подтверждённый IPv4 не совпадает с доверенным. Причина изменения не установлена.");
    }
}
public sealed class AnomalySettings
{
    public bool Enabled {get;set;}=true;
    public double CpuPct {get;set;}=90;
    public double RamPct {get;set;}=90;
    public double DiskPct {get;set;}=95;
    public double DiskLatencyMs {get;set;}=50;
    public int SustainedSeconds {get;set;}=60;
    public int ProcessSeconds {get;set;}=15;
    public int RecoverySeconds {get;set;}=20;
    public int CooldownSeconds {get;set;}=300;
    public double ProcessCpuPct {get;set;}=10;
    public int ProcessMemoryMb {get;set;}=512;
    public int MemoryGrowthMb {get;set;}=512;
    public double MemoryGrowthFactor {get;set;}=2;
    public double NetworkFactor {get;set;}=3;
    public double NetworkMinimumMbps {get;set;}=5;
    public List<string> IgnoredRules {get;set;}=[];
    public List<string> IgnoredPaths {get;set;}=[];
    public void Validate()
    {
        if(new[]{CpuPct,RamPct,DiskPct,ProcessCpuPct}.Any(x=>!double.IsFinite(x)||x<1||x>100) || !double.IsFinite(DiskLatencyMs)||DiskLatencyMs<1 || DiskLatencyMs>10000 ||
            SustainedSeconds is <5 or >3600 || ProcessSeconds is <5 or >3600 || RecoverySeconds is <5 or >600 || CooldownSeconds is <30 or >86400 ||
            ProcessMemoryMb is <16 or >65536 || MemoryGrowthMb is <16 or >65536 || !double.IsFinite(MemoryGrowthFactor)||MemoryGrowthFactor<1.1 ||MemoryGrowthFactor>100 ||
            !double.IsFinite(NetworkFactor)||NetworkFactor<1.1||NetworkFactor>100 || !double.IsFinite(NetworkMinimumMbps)||NetworkMinimumMbps<0.01||NetworkMinimumMbps>100000)
            throw new ArgumentException("Некорректные пороги анализа: проценты 1–100, выдержка 5–3600 с, восстановление 5–600 с, cooldown 30–86400 с.");
    }
}
public record BaselinePoint(DateTimeOffset TimestampUtc,double? Cpu,double Ram,double? Disk,double? Network);
public record BaselineStats(int Samples,double Median,double P95,double Mad);
public sealed record IncidentProcess(ProcessSample Sample,string? Publisher=null,string Signature="Не проверена",string? Sha256=null);
public sealed record Incident
{
    public string Id {get;init;}=Guid.NewGuid().ToString("N");
    public string Rule {get;init;}="";
    public string Group {get;init;}="Производительность";
    public string Severity {get;init;}="warning";
    public DateTimeOffset StartedUtc {get;init;}
    public DateTimeOffset UpdatedUtc {get;set;}
    public DateTimeOffset? EndedUtc {get;set;}
    public string Reason {get;set;}="";
    public string Source {get;init;}="Windows telemetry";
    public string Confidence {get;init;}="Измерение; причина требует проверки";
    public double? PeakCpu {get;set;}
    public double? PeakRam {get;set;}
    public double? PeakIo {get;set;}
    public double? PeakNetwork {get;set;}
    public double? PeakTemperature {get;set;}
    public bool Expected {get;set;}
    public List<IncidentProcess> Processes {get;set;}=[];
    public string State=>EndedUtc.HasValue?"Завершён":"Активен";
    public string ProcessNames=>string.Join(", ",Processes.Select(p=>$"{p.Sample.Name} ({p.Sample.Pid})"));
    public string Time=>StartedUtc.ToLocalTime().ToString("dd.MM HH:mm:ss");
    public string Duration=>((EndedUtc??UpdatedUtc)-StartedUtc).ToString(@"hh\:mm\:ss");
}
public record IncidentUpdate(Incident Incident,bool Notify);
public record SecurityEvent(string Channel,long RecordId,int EventId,DateTimeOffset TimestampUtc,string Summary,IReadOnlyDictionary<string,string> Fields);
public record StartupEntry(string Id,string Location,string Name,string Target);
