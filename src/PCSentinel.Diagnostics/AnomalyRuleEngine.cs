using PCSentinel.Core;
namespace PCSentinel.Diagnostics;

public sealed class BaselineService
{
    private readonly Queue<BaselinePoint> _points=[];
    public DateTimeOffset? FirstSeen {get;private set;}
    public void Add(BaselinePoint point)
    {
        FirstSeen=FirstSeen is null?point.TimestampUtc:FirstSeen<point.TimestampUtc?FirstSeen:point.TimestampUtc;
        _points.Enqueue(point);
        while(_points.Count>0 && point.TimestampUtc-_points.Peek().TimestampUtc>TimeSpan.FromDays(7))_points.Dequeue();
        while(_points.Count>10100)_points.Dequeue();
    }
    public bool Learning(DateTimeOffset now)=>FirstSeen==null || now-FirstSeen<TimeSpan.FromHours(24) || _points.Count<60;
    public BaselineStats? Network(DateTimeOffset now)
    {
        var available=_points.Where(x=>x.Network.HasValue && x.TimestampUtc<now.AddMinutes(-5)).ToArray();
        var hourly=available.Where(x=>Math.Min(Math.Abs(x.TimestampUtc.Hour-now.Hour),24-Math.Abs(x.TimestampUtc.Hour-now.Hour))<=1).ToArray();
        var values=(hourly.Length>=60?hourly:available).Select(x=>x.Network!.Value).ToArray();
        return values.Length>=30?Robust(values):null;
    }
    public static BaselineStats Robust(IEnumerable<double> source)
    {
        var values=source.Where(double.IsFinite).Order().ToArray();
        if(values.Length==0)return new(0,0,0,0);
        static double Quantile(double[] v,double q){var p=(v.Length-1)*q;var a=(int)p;return v[a]+(v[(int)Math.Ceiling(p)]-v[a])*(p-a);}
        var median=Quantile(values,.5);var deviations=values.Select(v=>Math.Abs(v-median)).Order().ToArray();
        return new(values.Length,median,Quantile(values,.95),Quantile(deviations,.5));
    }
}

/// <summary>One state per rule/device/process. Null metrics break pending runs and never create incidents.</summary>
public sealed class AnomalyRuleEngine
{
    private sealed class State{public DateTimeOffset? Since,Recovery,Last;public Incident? Active;public DateTimeOffset Notified=DateTimeOffset.MinValue;}
    private readonly Dictionary<string,State> _states=[];
    private readonly Dictionary<string,Queue<(DateTimeOffset At,long Bytes)>> _memory=[];
    private DateTimeOffset? _last;
    public IReadOnlyList<IncidentUpdate> Evaluate(MachineSample sample,IReadOnlyList<ProcessSample> processes,IReadOnlyList<SensorReading> sensors,
        AppSettings settings,BaselineService baseline,IReadOnlyDictionary<string,DateTimeOffset> knownPaths)
    {
        var now=sample.TimestampUtc;var s=settings.Anomalies;var result=new List<IncidentUpdate>();var touched=new HashSet<string>();
        var gap=_last.HasValue && now-_last>TimeSpan.FromSeconds(15);_last=now;
        void Rule(string key,string rule,bool? high,string reason,IEnumerable<ProcessSample> involved,int duration,string group="Производительность",double? temperature=null)
        {
            touched.Add(key);
            if(!_states.TryGetValue(key,out var state))_states[key]=state=new();
            var people=involved.Where(p=>p.StartTimeUtc.HasValue).Take(3).ToList();
            var processRule=rule is "Unexpected Process" or "Script Activity" or "Memory Growth";
            if(!s.Enabled || s.IgnoredRules.Contains(rule) || processRule && people.Any(p=>p.Path!=null && s.IgnoredPaths.Contains(p.Path,StringComparer.OrdinalIgnoreCase)))high=false;
            if(gap){state.Since=null;state.Recovery=null;}
            if(high==true)
            {
                state.Recovery=null;state.Since??=now;
                if(state.Active==null && now-state.Since>=TimeSpan.FromSeconds(duration))
                {
                    state.Active=new(){Rule=rule,Group=group,Severity=rule is "CPU Saturation" or "Thermal Incident"?"critical":"warning",StartedUtc=state.Since.Value,UpdatedUtc=now,Reason=reason,Processes=people.Select(p=>new IncidentProcess(p)).ToList()};
                    var notify=now-state.Notified>=TimeSpan.FromSeconds(s.CooldownSeconds);if(notify)state.Notified=now;
                    Update(state.Active,sample,temperature);result.Add(new(state.Active,notify));state.Last=now;
                }
                else if(state.Active!=null)
                {
                    Update(state.Active,sample,temperature);state.Active.Reason=reason;
                    foreach(var p in people)if(!state.Active.Processes.Any(x=>x.Sample.InstanceId==p.InstanceId) && state.Active.Processes.Count<12)state.Active.Processes.Add(new(p));
                    if(state.Last==null || now-state.Last>=TimeSpan.FromSeconds(10)){result.Add(new(state.Active,false));state.Last=now;}
                }
            }
            else
            {
                state.Since=null;
                if(state.Active!=null)
                {
                    state.Recovery??=now;
                    if(now-state.Recovery>=TimeSpan.FromSeconds(s.RecoverySeconds))
                    {state.Active.EndedUtc=now;state.Active.UpdatedUtc=now;if(high==null)state.Active.Reason+=" Источник недоступен; завершено наблюдение без подтверждения нормализации.";result.Add(new(state.Active,false));state.Active=null;state.Recovery=null;}
                }
            }
        }
        var cpu=processes.OrderByDescending(p=>p.CpuPct??-1);var ram=processes.OrderByDescending(p=>p.PrivateBytes??p.WorkingSetBytes);var io=processes.OrderByDescending(p=>(p.ReadBps??0)+(p.WriteBps??0));
        Rule("cpu","CPU Saturation",Over(sample.CpuPct,s.CpuPct,_states.GetValueOrDefault("cpu")?.Active!=null),$"CPU {sample.CpuPct:F1}% > {s.CpuPct}% ≥ {s.SustainedSeconds} с. CPU процессов нормализован на все потоки.",cpu,s.SustainedSeconds);
        Rule("ram","Memory Pressure",Over(sample.RamPct,s.RamPct,_states.GetValueOrDefault("ram")?.Active!=null),$"RAM {sample.RamPct:F1}% > {s.RamPct}% ≥ {s.SustainedSeconds} с.",ram,s.SustainedSeconds);
        var diskHigh=sample.DiskActivePct.HasValue?sample.DiskActivePct>s.DiskPct || _states.GetValueOrDefault("disk")?.Active!=null && sample.DiskActivePct>s.DiskPct-5 || sample.DiskLatencyMs>s.DiskLatencyMs && sample.DiskActivePct>70:(bool?)null;
        Rule("disk","Disk Overload",diskHigh,$"Физический диск {sample.DiskActivePct:F1}%, задержка {sample.DiskLatencyMs:F1} ms; R {sample.DiskReadBps:F0}, W {sample.DiskWriteBps:F0} B/s. I/O процессов — все операции, не точная привязка к этому диску.",io,s.SustainedSeconds);
        var normal=baseline.Network(now);var net=sample.NetDownBps.HasValue && sample.NetUpBps.HasValue?Math.Max(sample.NetDownBps.Value,sample.NetUpBps.Value):(double?)null;
        var networkThreshold=Math.Max(s.NetworkMinimumMbps*1048576,Math.Max((normal?.Median??0)*s.NetworkFactor,(normal?.Median??0)+6*(normal?.Mad??0)));
        Rule("net","Unusual Network Burst",!baseline.Learning(now) && normal!=null?Over(net,networkThreshold,_states.GetValueOrDefault("net")?.Active!=null):null,$"Трафик {net:F0} B/s > {networkThreshold:F0}; median {normal?.Median:F0}, MAD {normal?.Mad:F0}, ×{s.NetworkFactor}. Источник не установлен: per-process сетевые байты не измеряются.",[],s.SustainedSeconds);
        foreach(var sensor in sensors.Where(r=>r.Kind==SensorKind.Temperature))
        {
            var threshold=sensor.DeviceType switch{"CPU"=>settings.CpuTemperatureCritical,"GPU"=>settings.GpuTemperatureCritical,_=>settings.SsdTemperatureCritical};
            var key="temp:"+sensor.Id;var value=sensor.Status==SensorStatus.Available && now-sensor.TimestampUtc<TimeSpan.FromSeconds(125)?SensorValues.Validate(SensorKind.Temperature,sensor.Value):null;
            Rule(key,"Thermal Incident",Over(value,threshold,_states.GetValueOrDefault(key)?.Active!=null),$"{sensor.HardwareName}: {value:F1} °C > {threshold} °C; источник {sensor.Source}.",[],s.ProcessSeconds,temperature:value);
        }
        foreach(var p in processes.Where(p=>p.StartTimeUtc.HasValue))
        {
            var path=p.Path;var newPath=path!=null && (!knownPaths.TryGetValue(path,out var first) || now-first<TimeSpan.FromHours(24));
            var temp=path!=null && (path.Contains(@"\AppData\Local\Temp\",StringComparison.OrdinalIgnoreCase)||path.Contains(@"\Windows\Temp\",StringComparison.OrdinalIgnoreCase));
            var busy=p.CpuPct>s.ProcessCpuPct || (p.PrivateBytes??p.WorkingSetBytes)>s.ProcessMemoryMb*1048576L;
            if(newPath || temp)Rule("new:"+p.InstanceId,"Unexpected Process",busy || temp,$"{p.Name}: {(temp?"файл в Temp":"новый путь за последние 24 часа")}; CPU {p.CpuPct:F1}%, RAM {(p.PrivateBytes??p.WorkingSetBytes)/1048576} MiB. Само по себе не является признаком вредоносности.",[p],s.ProcessSeconds,"События безопасности");
            var script=new[]{"powershell","pwsh","cmd","wscript","cscript","python","pythonw"}.Any(n=>p.Name.Equals(n,StringComparison.OrdinalIgnoreCase)||p.Name.StartsWith(n+"3",StringComparison.OrdinalIgnoreCase));
            if(script)Rule("script:"+p.InstanceId,"Script Activity",busy && newPath,$"Ресурсоёмкий новый интерпретатор {p.Name}; требуется диагностическая проверка, вредоносность не установлена. Аргументы не собираются.",[p],s.ProcessSeconds,"События безопасности");
            if(!_memory.TryGetValue(p.InstanceId,out var history))_memory[p.InstanceId]=history=new();
            var bytes=p.PrivateBytes??p.WorkingSetBytes;
            if(history.Count==0 || now-history.Last().At>=TimeSpan.FromSeconds(15))history.Enqueue((now,bytes));
            while(history.Count>1 && now-history.Peek().At>TimeSpan.FromMinutes(10))history.Dequeue();
            var old=history.Peek();
            Rule("growth:"+p.InstanceId,"Memory Growth",now-old.At>=TimeSpan.FromMinutes(9) && bytes-old.Bytes>s.MemoryGrowthMb*1048576L && bytes>old.Bytes*s.MemoryGrowthFactor,$"{p.Name}: рост за {(now-old.At).TotalMinutes:F1} мин: {old.Bytes/1048576} → {bytes/1048576} MiB; Δ>{s.MemoryGrowthMb} MiB, ×{s.MemoryGrowthFactor}.",[p],s.ProcessSeconds);
        }
        foreach(var pair in _states.Where(x=>!touched.Contains(x.Key)).ToArray())Rule(pair.Key,pair.Value.Active?.Rule??"",false,"",[],s.ProcessSeconds);
        var alive=processes.Select(p=>p.InstanceId).ToHashSet();foreach(var key in _memory.Keys.Where(k=>!alive.Contains(k)).ToArray())_memory.Remove(key);
        foreach(var key in _states.Where(x=>x.Value.Active==null && x.Value.Since==null && now-x.Value.Notified>TimeSpan.FromSeconds(s.CooldownSeconds)).Select(x=>x.Key).ToArray())_states.Remove(key);
        return result;
    }
    private static bool? Over(double? value,double threshold,bool active)=>value.HasValue && double.IsFinite(value.Value)?value>(active?threshold*.95:threshold):null;
    private static void Update(Incident i,MachineSample s,double? temperature)
    {
        static double? Max(double? a,double? b)=>!a.HasValue?b:!b.HasValue?a:Math.Max(a.Value,b.Value);
        i.UpdatedUtc=s.TimestampUtc;i.PeakCpu=Max(i.PeakCpu,s.CpuPct);i.PeakRam=Max(i.PeakRam,s.RamPct);i.PeakIo=Max(i.PeakIo,s.DiskActivePct);i.PeakNetwork=Max(i.PeakNetwork,Max(s.NetDownBps,s.NetUpBps));i.PeakTemperature=Max(i.PeakTemperature,temperature);
    }
}
