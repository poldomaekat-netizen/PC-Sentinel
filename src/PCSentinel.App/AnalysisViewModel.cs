using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows.Media;
using PCSentinel.Collectors;
using PCSentinel.Core;
using PCSentinel.Diagnostics;
namespace PCSentinel.App;
public sealed partial class MainViewModel
{
    public event Action? AppearancePreview;
    public string AppearanceStatus {get;private set;}="Ожидание композиции";
    public void PreviewGlass()=>AppearancePreview?.Invoke();
    public void SetAppearanceStatus(string text){AppearanceStatus=text;Changed(nameof(AppearanceStatus));}
    public string IpStatus {get;private set;}="Не настроен";
    public string IpColor {get;private set;}="#F4B740";
    public string WidgetIp {get;private set;}="IP: —";
    public string IpTooltip {get;private set;}="Нет успешной проверки";
    public string CurrentIpDetails {get;private set;}="Нет успешной проверки";
    private IpObservation? _ipObservation,_lastSuccessfulIp;
    private DateTimeOffset? _ipMismatchAt;
    private string? _ipMismatchValue;
    private Incident? _ipIncident;
    private bool _ipRecheck;
    private DateTimeOffset _ipNotified=DateTimeOffset.MinValue;
    public string? CurrentConfirmedIpv4=>_ipObservation?.Agree4==true && DateTimeOffset.UtcNow-_ipObservation.TimestampUtc<TimeSpan.FromSeconds(Math.Max(90,_active.NetworkIntervalSeconds*2))?_ipObservation.Ipv4:null;
    public void RefreshIpTrust()
    {
        var result=IpTrustPolicy.Evaluate(_active.TrustedPublicIp,_ipObservation,(_active.EnablePublicIp||_ipWasManual) && (!_smoke || _liveNetwork),DateTimeOffset.UtcNow,TimeSpan.FromSeconds(Math.Max(90,_active.NetworkIntervalSeconds*2)));
        IpStatus=result.Label;IpColor=result.State switch{IpTrustState.Trusted=>"#24CDB4",IpTrustState.Changed=>"#EF6262",IpTrustState.NotConfigured=>"#F4B740",_=>"#93A9BC"};
        var fresh=CurrentConfirmedIpv4;WidgetIp="IP: "+(fresh??"—");TopIp=fresh??"IP: —";
        var last=_lastSuccessfulIp;var lastText=last==null?"Успешных измерений нет":$"Успешно: {last.TimestampUtc.ToLocalTime():dd.MM HH:mm:ss} · {last.Source}";
        var cached=fresh==null && last?.Ipv4!=null?$"\nПоследний достоверный IPv4: {last.Ipv4} (кеш, не текущий)":"";
        var six=_ipObservation?.Agree6==true?$"IPv6: {_ipObservation.Ipv6}" :"IPv6 не проверен";
        IpTooltip=$"{result.Reason}\n{lastText}{cached}\n{six}\nИзмеряется маршрут PC Sentinel. При split tunneling другие приложения могут выходить иначе.";
        var sixTrust=string.IsNullOrEmpty(_active.TrustedPublicIpv6)?"":_ipObservation?.Agree6==true?(_active.TrustedPublicIpv6==_ipObservation.Ipv6?" · доверенный IPv6 совпадает":" · доверенный IPv6 изменился"):" · доверенный IPv6 не удалось проверить";
        CurrentIpDetails=$"Текущий внешний IPv4: {fresh??"—"}\nВнешний {six}{sixTrust}\n{lastText}{cached}\n{result.Reason}";
        foreach(var name in new[]{nameof(IpStatus),nameof(IpColor),nameof(WidgetIp),nameof(TopIp),nameof(IpTooltip),nameof(CurrentIpDetails)})Changed(name);
    }
    private async Task ObserveIpAsync(NetworkCheck check,AppSettings settings)
    {
        _ipObservation=new(check.TimestampUtc,check.Agree4?check.IpV4:null,check.Agree6?check.IpV6:null,check.Agree4,check.Agree6,"ipify.org + icanhazip.com",check.Agree4?"Два источника согласованы":check.Reason,check.State!=VpnState.Offline);
        if(check.Agree4)_lastSuccessfulIp=_ipObservation;
        if(settings.EnablePublicIp && (!_smoke||_liveNetwork))await _store.SaveIpAsync(_ipObservation);
        var result=IpTrustPolicy.Evaluate(settings.TrustedPublicIp,_ipObservation,settings.EnablePublicIp,DateTimeOffset.UtcNow,TimeSpan.FromSeconds(Math.Max(90,settings.NetworkIntervalSeconds*2)));
        _ipRecheck=false;
        if(result.State==IpTrustState.Changed)
        {
            if(_ipMismatchValue!=check.IpV4){_ipMismatchValue=check.IpV4;_ipMismatchAt=check.TimestampUtc;}
            if(_ipMismatchAt.HasValue && check.TimestampUtc-_ipMismatchAt>=TimeSpan.FromSeconds(5))
            {
                _ipIncident??=new(){Rule="IP Change",Group="События безопасности",Source="HTTPS · два независимых IP-сервиса",StartedUtc=_ipMismatchAt.Value,UpdatedUtc=check.TimestampUtc,Reason=$"Доверенный IPv4 {settings.TrustedPublicIp}, подтверждённый текущий {check.IpV4}. Причина изменения не установлена. Это не доказательство отключения VPN или вредоносности."};
                _ipIncident.UpdatedUtc=check.TimestampUtc;_ipIncident.Reason=$"Доверенный IPv4 {settings.TrustedPublicIp}, подтверждённый текущий {check.IpV4}. Причина изменения не установлена; это не доказательство отключения VPN или вредоносности.";var notify=check.TimestampUtc-_ipNotified>=TimeSpan.FromSeconds(settings.Anomalies.CooldownSeconds) && _ipIncident.UpdatedUtc-_ipIncident.StartedUtc<TimeSpan.FromMinutes(2);
                if(notify)_ipNotified=check.TimestampUtc;
                if(!settings.Anomalies.IgnoredRules.Contains("IP Change"))await PublishIncidentAsync(_ipIncident,notify && settings.Anomalies.Enabled);
            }
            else _ipRecheck=true;
        }
        else
        {
            _ipMismatchAt=null;_ipMismatchValue=null;
            if(_ipIncident!=null && result.State is IpTrustState.Trusted or IpTrustState.NotConfigured){_ipIncident.EndedUtc=check.TimestampUtc;_ipIncident.UpdatedUtc=check.TimestampUtc;await PublishIncidentAsync(_ipIncident,false);_ipIncident=null;}
        }
        await Ui(RefreshIpTrust);
    }
    public ObservableCollection<Incident> Incidents {get;}=[];
    public string AnalysisSummary {get;private set;}="Изучение обычной нагрузки · фиксированные правила работают сразу";
    public string SecuritySources {get;private set;}="Чтение доступных журналов…";
    public string IncidentDetails {get;private set;}="Выберите инцидент. Красный уровень означает серьёзность события, а не диагноз вируса.";
    public PointCollection IncidentCpuPlot {get;private set;}=[];
    public PointCollection IncidentRamPlot {get;private set;}=[];
    public PointCollection IncidentDiskPlot {get;private set;}=[];
    public Incident? SelectedIncident {get;private set;}
    public string SelectedProcessStatus {get;private set;}="";
    private readonly BaselineService _baseline=new();
    private readonly AnomalyRuleEngine _anomalyEngine=new();
    private readonly FileIdentityInspector _fileInspector=new();
    private Dictionary<string,DateTimeOffset> _knownPaths=new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _baselineAt=DateTimeOffset.MinValue;
    private DateTimeOffset _processSavedAt=DateTimeOffset.MinValue;
    private int _dayWarnings,_dayCritical;
    private readonly HashSet<string> _seenInstances=[];
    private Task? _securityLoop;
    private readonly SemaphoreSlim _incidentPublishGate=new(1,1);
    private Dictionary<string,DateTimeOffset> _notificationByRule=[];
    private async Task InitializeAnalysisAsync()
    {
        var notifications=await _store.StateAsync("notification-cooldown");if(notifications!=null)_notificationByRule=JsonSerializer.Deserialize<Dictionary<string,DateTimeOffset>>(notifications)??[];
        foreach(var point in await _store.LoadBaselineAsync())_baseline.Add(point);
        _knownPaths=await _store.KnownPathsAsync();
        var incidents=await _store.LoadIncidentsAsync();
        foreach(var i in incidents.Where(i=>i.EndedUtc==null))
        {i.EndedUtc=i.UpdatedUtc;i.Reason+=" Наблюдение прервано остановкой приложения; нормализация не подтверждена.";await _store.SaveIncidentAsync(i);}
        foreach(var i in incidents)Incidents.Add(i);
    }
    private async Task AnalyzeAsync(MachineSample sample,IReadOnlyList<ProcessSample> processes,AppSettings settings)
    {
        var newIdentities=processes.Where(p=>!_seenInstances.Contains(p.InstanceId)).ToArray();
        if(newIdentities.Length>0)await _store.SaveIdentitiesAsync(newIdentities);
        var alive=processes.Select(p=>p.InstanceId).ToHashSet();_seenInstances.RemoveWhere(x=>!alive.Contains(x));foreach(var p in processes)_seenInstances.Add(p.InstanceId);
        var updates=_anomalyEngine.Evaluate(sample,processes,_latestSensors,settings,_baseline,_knownPaths);
        foreach(var update in updates)
        {
            // Inspect one leading file per incident, not every executable every polling cycle.
            if(update.Incident.Processes.Count>0 && update.Incident.Processes[0].Signature=="Не проверена")update.Incident.Processes[0]=_fileInspector.Inspect(update.Incident.Processes[0]);
            await PublishIncidentAsync(update.Incident,update.Notify);
        }
        BaselinePoint? point=null;
        if(sample.TimestampUtc-_baselineAt>=TimeSpan.FromMinutes(1))
        {point=new(sample.TimestampUtc,sample.CpuPct,sample.RamPct,sample.DiskActivePct,sample.NetDownBps.HasValue && sample.NetUpBps.HasValue?Math.Max(sample.NetDownBps.Value,sample.NetUpBps.Value):null);_baseline.Add(point);_baselineAt=sample.TimestampUtc;(_dayWarnings,_dayCritical)=await _store.DailyCountsAsync(sample.TimestampUtc.AddHours(-24));}
        if(sample.TimestampUtc-_processSavedAt>=TimeSpan.FromSeconds(15) || point!=null)
        {
            var interesting=processes.Where(p=>p.CpuPct>.2).OrderByDescending(p=>p.CpuPct).Take(5).Concat(processes.OrderByDescending(p=>p.PrivateBytes??p.WorkingSetBytes).Take(3)).Concat(processes.Where(p=>(p.ReadBps??0)+(p.WriteBps??0)>4096).OrderByDescending(p=>(p.ReadBps??0)+(p.WriteBps??0)).Take(3)).DistinctBy(p=>p.InstanceId).ToArray();
            await _store.SaveAnalyticsAsync(interesting,point,[]);_processSavedAt=sample.TimestampUtc;
        }
        foreach(var p in processes.Where(p=>p.Path!=null))if(!_knownPaths.ContainsKey(p.Path!))_knownPaths[p.Path!]=sample.TimestampUtc;
        if(_knownPaths.Count>20000)_knownPaths=_knownPaths.OrderByDescending(p=>p.Value).Take(18000).ToDictionary(p=>p.Key,p=>p.Value,StringComparer.OrdinalIgnoreCase);
        await Ui(()=>
        {
            AnalysisSummary=$"За 24 ч: предупреждений {_dayWarnings}, критических {_dayCritical}, новых путей {_knownPaths.Count(p=>p.Value>=sample.TimestampUtc.AddHours(-24))}. "+(_baseline.Learning(sample.TimestampUtc)?"Изучение обычной нагрузки (24 часа); фиксированные пороги включены.":"Baseline median/MAD · до 7 дней · время суток при достаточной истории.")+" Сводка из БД обновляется раз в минуту.";Changed(nameof(AnalysisSummary));
        });
    }
    private async Task PublishIncidentAsync(Incident incident,bool notify)
    {
        await _incidentPublishGate.WaitAsync();try
        {
        await _store.SaveIncidentAsync(incident);
        var snapshot=JsonSerializer.Deserialize<Incident>(JsonSerializer.Serialize(incident))!;
        var notificationAt=DateTimeOffset.UtcNow;
        var send=notify && !snapshot.Expected && _active.EnableNotifications && !_smoke && (!_notificationByRule.TryGetValue(snapshot.Rule,out var last) || notificationAt-last>=TimeSpan.FromSeconds(_active.Anomalies.CooldownSeconds));
        if(send){_notificationByRule[snapshot.Rule]=notificationAt;await _store.SaveStateAsync("notification-cooldown",JsonSerializer.Serialize(_notificationByRule));}
        await Ui(()=>
        {
            var selectedId=SelectedIncident?.Id;
            var old=Incidents.FirstOrDefault(i=>i.Id==snapshot.Id);if(old!=null){var index=Incidents.IndexOf(old);Incidents[index]=snapshot;}else Incidents.Insert(0,snapshot);
            if(selectedId==snapshot.Id){SelectedIncident=snapshot;Changed(nameof(SelectedIncident));}
            while(Incidents.Count>500)Incidents.RemoveAt(Incidents.Count-1);
            if(send)Notification?.Invoke(snapshot.Rule,snapshot.Reason);
        });
        }finally{_incidentPublishGate.Release();}
    }
    private async Task SecurityLoopAsync()
    {
        var startup=new StartupSnapshotCollector();var defender=new SecurityEventProvider();var sysmon=new SecurityEventProvider();
        var stored=await _store.StateAsync("startup");var previous=stored==null?null:JsonSerializer.Deserialize<List<StartupEntry>>(stored);
        var ids=new Dictionary<string,long>();foreach(var channel in new[]{SecurityEventProvider.Defender,SecurityEventProvider.Sysmon})ids[channel]=long.TryParse(await _store.StateAsync(channel),out var id)?id:0;
        while(!_stop.IsCancellationRequested)
        {
            try
            {
                var settings=_active;var current=startup.Read();
                // If a source was denied, preserve its previous snapshot to avoid false deletions.
                var usable=startup.AccessibleLocations;
                if(previous!=null)
                {
                    var changes=StartupSnapshotCollector.Changes(previous,current).Where(c=>!c.Target.StartsWith("Удалена:")||usable.Contains(c.Location)).ToArray();
                    if(changes.Length>0 && settings.Anomalies.Enabled && !settings.Anomalies.IgnoredRules.Contains("Startup Change"))
                        await PublishIncidentAsync(new(){Rule="Startup Change",Group="События безопасности",Source="Read-only Run / Startup",StartedUtc=DateTimeOffset.UtcNow,UpdatedUtc=DateTimeOffset.UtcNow,EndedUtc=DateTimeOffset.UtcNow,Reason=string.Join("\n",changes.Take(100).Select(c=>$"{c.Location} / {c.Name}: {c.Target}"))+"\nИзменение автозагрузки; вредоносность не установлена."},false);
                }
                previous=current.Concat(previous?.Where(x=>!usable.Contains(x.Location))??[]).DistinctBy(x=>x.Id).ToList();await _store.SaveStateAsync("startup",JsonSerializer.Serialize(previous));
                foreach(var channel in new[]{SecurityEventProvider.Defender,SecurityEventProvider.Sysmon})
                {
                    var enabled=channel==SecurityEventProvider.Defender?settings.ReadDefenderEvents:settings.ReadSysmonEvents;if(!enabled)continue;
                    var provider=channel==SecurityEventProvider.Defender?defender:sysmon;
                    foreach(var e in provider.Read(channel,ids[channel],_stop.Token))
                    {
                        await _store.SaveSecurityAsync(e);ids[channel]=Math.Max(ids[channel],e.RecordId);
                        if(settings.Anomalies.Enabled && (channel==SecurityEventProvider.Defender || e.EventId==1) && !settings.Anomalies.IgnoredRules.Contains(channel==SecurityEventProvider.Defender?"Defender Finding":"Sysmon Process"))
                            await PublishIncidentAsync(new(){Id=$"event:{channel}:{e.RecordId}",Rule=channel==SecurityEventProvider.Defender?"Defender Finding":"Sysmon Process",Group="События безопасности",Severity=e.EventId==1116?"critical":"info",Source=$"{channel} · EventID {e.EventId} · Record {e.RecordId}",StartedUtc=e.TimestampUtc,UpdatedUtc=e.TimestampUtc,EndedUtc=e.TimestampUtc,Reason=e.Summary+"\n"+string.Join("\n",e.Fields.Select(f=>f.Key+": "+f.Value)),Confidence="Событие источника; не независимый диагноз PC Sentinel"},false);
                    }
                    await _store.SaveStateAsync(channel,ids[channel].ToString());
                }
                await Ui(()=>{SecuritySources=startup.Status+"\n"+(settings.ReadDefenderEvents?defender.Status:"Defender: чтение выключено")+"\n"+(settings.ReadSysmonEvents?sysmon.Status:"Sysmon: выключен по умолчанию; установка/включение не выполняются");Changed(nameof(SecuritySources));});
                await Task.Delay(TimeSpan.FromSeconds(60),_stop.Token);
            }
            catch(OperationCanceledException)when(_stop.IsCancellationRequested){break;}
            catch(Exception e){_log.Write("security-source",e.GetType().Name);try{await Task.Delay(60000,_stop.Token);}catch(OperationCanceledException){break;}}
        }
    }
    public async Task SelectIncidentAsync(Incident? incident)
    {
        SelectedIncident=incident;Changed(nameof(SelectedIncident));if(incident==null)return;
        var context=await _store.IncidentContextAsync(incident);if(SelectedIncident?.Id!=incident.Id)return;
        var first=incident.StartedUtc.AddMinutes(-5);var last=(incident.EndedUtc??incident.UpdatedUtc).AddMinutes(5);var duration=Math.Max(1,(last-first).TotalSeconds);
        PointCollection Plot(Func<MachineSample,double?> pick)=>new(context.Where(x=>pick(x).HasValue).Select(x=>new System.Windows.Point(600*(x.TimestampUtc-first).TotalSeconds/duration,95-Math.Clamp(pick(x)!.Value,0,100)*.9)));
        IncidentCpuPlot=Plot(s=>s.CpuPct);IncidentRamPlot=Plot(s=>s.RamPct);IncidentDiskPlot=Plot(s=>s.DiskActivePct);
        var people=string.Join("\n\n",incident.Processes.Select(x=>$"{x.Sample.Name} · PID {x.Sample.Pid} · start {x.Sample.StartTimeUtc:O}\n{x.Sample.Path??"Путь недоступен"}\nCPU {x.Sample.CpuPct:F1}%, WS {x.Sample.WorkingSetBytes/1048576} MiB, Private {x.Sample.PrivateBytes/1048576} MiB, R {x.Sample.ReadBps:F0} / W {x.Sample.WriteBps:F0} B/s\n{x.Sample.Quality}\n{x.Signature}; издатель {x.Publisher??"—"}; SHA256 {x.Sha256??"не вычислялся"}"));
        IncidentDetails=$"{incident.Rule} · {incident.Group} · {incident.Severity} · {incident.State}\n{incident.StartedUtc.ToLocalTime():G} → {incident.EndedUtc?.ToLocalTime().ToString("G")??"продолжается"}; длительность {incident.Duration}\n{incident.Reason}\nИсточник: {incident.Source}\nУверенность: {incident.Confidence}\nПики: CPU {incident.PeakCpu:F1}% · RAM {incident.PeakRam:F1}% · диск {incident.PeakIo:F1}% · сеть {incident.PeakNetwork:F0} B/s · температура {incident.PeakTemperature:F1} °C\n{people}\nКонтекст ±5 мин: {context.Count} проб. Отсутствующие прошлые/будущие данные не достраиваются. Трафик может дублироваться на туннеле и физическом интерфейсе.";
        foreach(var name in new[]{nameof(IncidentDetails),nameof(IncidentCpuPlot),nameof(IncidentRamPlot),nameof(IncidentDiskPlot)})Changed(name);
    }
    public async Task ExpectedAsync(){if(SelectedIncident is {} i){await _store.MarkExpectedAsync(i.Id,true);i.Expected=true;await ReloadIncidentsAsync();}}
    public async Task ReloadIncidentsAsync(){var items=await _store.LoadIncidentsAsync();await Ui(()=>{Incidents.Clear();foreach(var i in items)Incidents.Add(i);});}
    public async Task IgnoreAsync(bool process)
    {
        if(SelectedIncident is not {} i)return;var next=Copy(_active);
        if(process){var path=i.Processes.FirstOrDefault()?.Sample.Path;if(path==null){SetMessage("Путь процесса недоступен");return;}if(!next.Anomalies.IgnoredPaths.Contains(path,StringComparer.OrdinalIgnoreCase))next.Anomalies.IgnoredPaths.Add(path);}
        else if(!next.Anomalies.IgnoredRules.Contains(i.Rule))next.Anomalies.IgnoredRules.Add(i.Rule);
        await _settingsGate.WaitAsync();try{await _store.SaveSettingsAsync(next);_active=next;Settings.Anomalies=Copy(next).Anomalies;Changed(nameof(Settings));}finally{_settingsGate.Release();}
    }
    public bool ProcessStillSame(ProcessSample sample)
    {
        try{using var p=System.Diagnostics.Process.GetProcessById(sample.Pid);return sample.StartTimeUtc.HasValue && Math.Abs((p.StartTime.ToUniversalTime()-sample.StartTimeUtc.Value.UtcDateTime).TotalMilliseconds)<1;}catch(Exception e)when(e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception){return false;}
    }
}
