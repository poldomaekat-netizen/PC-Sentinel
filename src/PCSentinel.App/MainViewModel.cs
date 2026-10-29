using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Windows.Media;
using Microsoft.Win32;
using PCSentinel.Core;
using PCSentinel.Collectors;
using PCSentinel.Diagnostics;
using PCSentinel.Network;
using PCSentinel.Storage;

namespace PCSentinel.App;

public sealed class MetricCard(string title, string tag, string detail) : Observable
{
    public string Tooltip => Title+"\n"+Detail;
    public string Title { get; } = title;
    public string Tag { get; } = tag;
    public string Detail { get; private set; } = detail;
    public string Label { get; private set; } = "N/A";
    public string Caption { get; private set; } = "НЕТ ДАННЫХ";
    public double Value { get; private set; } = double.NaN;
    public double Warning { get; private set; } = 60;
    public double Critical { get; private set; } = 85;
    public PointCollection Plot { get; private set; } = [];
    private readonly Queue<(DateTimeOffset At, double Value)> _points = [];
    public void Update(DateTimeOffset now, double? value, string label, string detail, AppSettings settings, double? traffic = null)
    {
        Value = value ?? double.NaN; Label = label; Detail = detail;
        Caption = traffic.HasValue ? "MB/s ↓" : value.HasValue ? "СЕЙЧАС" : "НЕТ ДАННЫХ";
        Warning = settings.WarningThreshold; Critical = settings.CriticalThreshold;
        _points.Enqueue((now, traffic ?? value ?? double.NaN));
        while (_points.Count > 0 && now - _points.Peek().At > TimeSpan.FromMinutes(5)) _points.Dequeue();
        var scale = traffic.HasValue ? Math.Max(1, _points.Where(p => !double.IsNaN(p.Value)).Select(p => p.Value).DefaultIfEmpty(1).Max()) : 100;
        Plot = new PointCollection(_points.Where(p => !double.IsNaN(p.Value)).Select(p =>
            new System.Windows.Point(215 * (1 - (now - p.At).TotalSeconds / 300), 29 - Math.Clamp(p.Value / scale, 0, 1) * 27)));
        Changed(nameof(Value)); Changed(nameof(Label)); Changed(nameof(Caption)); Changed(nameof(Detail)); Changed(nameof(Tooltip)); Changed(nameof(Plot)); Changed(nameof(Warning)); Changed(nameof(Critical));
    }
}

public sealed partial class MainViewModel : Observable
{
    public ObservableCollection<MetricCard> Cards { get; } = [
        new("Процессор", "CPU", "GetSystemTimes · ожидание пробы"),
        new("Память", "RAM", "Физическая память Windows"),
        new("Видеокарта", "GPU", "GPU/VRAM: недоступно в v0.1"),
        new("Активность диска", "I/O", "PDH · все физические диски"),
        new("Заполнение тома", "SYSTEM", "Системный том"),
        new("Сеть", "TRAFFIC", "Сумма активных адаптеров") ];
    public ObservableCollection<ProcessSample> Processes { get; } = [];
    public ObservableCollection<HardwareItem> Hardware { get; } = [];
    public ObservableCollection<AlertEvent> Events { get; } = [];
    public ObservableCollection<AdapterInfo> Adapters { get; } = [];
    public ObservableCollection<AdapterInfo> AllAdapters { get; }=[];
    public ObservableCollection<SensorDisplay> Sensors { get; }=[];
    public ObservableCollection<SiteCheckResult> Sites { get; }=[];
    public ObservableCollection<MetricCard> WidgetCards { get; }=[];
    public string AdapterSummary {get;private set;}="Поиск подключений…";
    public string ProfileSummary {get;private set;}="Профиль ещё не создан. Подключите VPN и запустите мастер.";
    public bool CanCaptureProfile {get;private set;}
    public string CpuTemperature {get;private set;}="CPU —";
    public string GpuTemperature {get;private set;}="GPU —";
    public string SsdTemperature {get;private set;}="SSD —";
    public string CpuTemperatureHint {get;private set;}="Поиск датчиков CPU…";
    public string GpuTemperatureHint {get;private set;}="Поиск датчиков GPU…";
    public string SsdTemperatureHint {get;private set;}="Поиск датчиков SSD…";
    public string SensorSummary {get;private set;}="Поиск датчиков…";
    public string CpuTemperatureColor {get;private set;}="#93A9BC";
    public string GpuTemperatureColor {get;private set;}="#93A9BC";
    public string SsdTemperatureColor {get;private set;}="#93A9BC";
    public string NetworkShort {get;private set;}="↓ —   ↑ —";
    public string TopIp {get;private set;}="IP не проверен";
    public event Action? SettingsApplied;
    public AppSettings Settings { get; private set; } = new();
    public string Updated { get; private set; } = "Подготовка…";
    public string VpnStatus { get; private set; } = "Unknown";
    public string VpnColor { get; private set; } = "#DCB66C";
    public string VpnReason { get; private set; } = "Проверки IP выключены по умолчанию. Включите их в настройках.";
    public string Ip4 { get; private set; } = "IPv4  —";
    public string Ip6 { get; private set; } = "IPv6  —";
    public string Route { get; private set; } = "Маршруты не проверены";
    public string Status { get; private set; } = "Подготовка локального хранилища…";
    public string SettingsMessage { get; private set; } = "";
    public string Report { get; private set; } = "Нажмите «Последние пробы» для просмотра сохранённой истории.";
    public string DataPath => $"Данные: {_store.Root}";
    public string CompactText { get; private set; } = "Ожидание данных…";
    public bool CanCheckIp { get; private set; } = true;
    public bool CanInventory { get; private set; } = true;
    public event Action<string, string>? Notification;
    private readonly LocalStore _store;
    private readonly LocalLogger _log;
    private readonly TemperatureHelper _temperatureHelper=new();
    public string HardwareTemperatureStatus=>_temperatureHelper.Status;
    private readonly bool _smoke;
    private readonly bool _liveNetwork;
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _networkRequested = new(0, 1);
    private readonly VpnMonitor _vpn = new();
    private readonly NetworkPollGate _pollGate=new(TimeSpan.FromSeconds(15));
    private readonly AlertRules _rules = new();
    private AppSettings _active = new();
    private Task? _sampling, _networkLoop, _inventory, _sensorLoop;
    private readonly SemaphoreSlim _settingsGate=new(1,1);
    private IReadOnlyList<SensorReading> _latestSensors=[];
    private readonly Dictionary<string,DateTimeOffset> _sensorSaved=[];
    private MachineSample? _latest;
    private NetworkCheck? _lastNetwork;
    private int _sampleCount;
    private int _networkGeneration;
    private int _manualNetworkRequested;
    private bool _ipWasManual;
    public MainViewModel(LocalStore store,LocalLogger log,bool smoke,bool liveNetwork=false){_store=store;_log=log;_smoke=smoke;_liveNetwork=liveNetwork;}
    private static Task Ui(Action action) => System.Windows.Application.Current.Dispatcher.InvokeAsync(action).Task;
    private static AppSettings Copy(AppSettings s) => JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(s))!;
    private void Refresh(string property) => Changed(property);
    public async Task StartAsync()
    {
        await _store.InitializeAsync();
        try { Settings = _store.LoadSettings(); }
        catch (Exception ex) { _log.Write("settings-invalid", ex.Message); SettingsMessage = "Не удалось прочитать настройки. Использованы значения по умолчанию, исходный файл сохранён."; Changed(nameof(SettingsMessage)); }
        _active = Copy(Settings); Changed(nameof(Settings));
        if(_store.SettingsMigrated)await _store.SaveSettingsAsync(Settings);
        if(_liveNetwork){Settings.EnablePublicIp=true;Settings.EnableSiteChecks=true;_active=Copy(Settings);}
        if(!_smoke && _active.AutoStart)
        {try{await Task.Run(()=>SetAutoStart(true));}catch(Exception e){_log.Write("autostart-update",e.Message);SetMessage("Не удалось обновить путь автозагрузки: "+e.Message);}}
        await RefreshAdaptersAsync();
        RebuildWidgetCards();RefreshProfileSummary();
        await InitializeAnalysisAsync();
        Status = "Glass & Security · локальная диагностика · служба датчиков по выбору"; Changed(nameof(Status));
        _sampling = Task.Run(SamplingLoopAsync); _networkLoop = Task.Run(NetworkLoopAsync); _inventory = RefreshInventoryAsync();_sensorLoop=Task.Run(SensorLoopAsync);_securityLoop=Task.Run(SecurityLoopAsync);
        NetworkChange.NetworkAddressChanged += NetworkChanged;
        _log.Write("start", "PC Sentinel 0.3.2; elevated="+TemperatureHelper.IsElevated+"; public IP enabled=" + _active.EnablePublicIp);
        if(!_smoke && _active.EnableHardwareTemperatureHelper && ProtectedInstall.CheckCurrent(out _))await EnableHardwareTemperaturesAsync();
    }
    private async Task SamplingLoopAsync()
    {
        using var collector = new NativeMetrics(); var processes = new ProcessCollector();
        var processClock = Stopwatch.StartNew(); var maintenance = DateTimeOffset.MinValue;
        var lastSample = Stopwatch.GetTimestamp();
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                var settings = _active;
                if (Stopwatch.GetElapsedTime(lastSample) > TimeSpan.FromSeconds(10)) lock (_rules) _rules.Reset();
                lastSample = Stopwatch.GetTimestamp();
                var sample = await Task.Run(collector.Collect, _stop.Token);
                IReadOnlyList<ProcessSample>? snapshot = null;
                if (processClock.Elapsed >= TimeSpan.FromSeconds(5)) { snapshot = await Task.Run(processes.Collect, _stop.Token); processClock.Restart(); }
                // v0.3 stores selected detailed process samples in process_samples; do not duplicate them into the legacy table.
                await _store.SaveSampleAsync(sample, null); _sampleCount++; _latest = sample;
                if(snapshot!=null)await AnalyzeAsync(sample,snapshot,settings);
                await Ui(() => ApplySample(sample, snapshot, settings));
                foreach (var pair in settings.Anomalies.Enabled ? Array.Empty<(string,double?)>() : new[] { ("CPU", sample.CpuPct), ("RAM", (double?)sample.RamPct), ("Диск", sample.DiskActivePct) })
                {
                    AlertEvent? alert;
                    lock (_rules) alert = _rules.Check(pair.Item1, pair.Item2, sample.TimestampUtc, settings);
                    if (alert != null) await AddEventAsync(alert, settings.EnableNotifications);
                }
                if (sample.TimestampUtc - maintenance > TimeSpan.FromHours(1)) { await _store.MaintainAsync(settings); maintenance = sample.TimestampUtc; }
                await Task.Delay(TimeSpan.FromSeconds(settings.RefreshSeconds), _stop.Token);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                _log.Write("sampling-error", e.ToString());
                await Ui(() => { Status = "Ошибка сбора/записи: " + e.Message; Changed(nameof(Status)); });
                try { await Task.Delay(3000, _stop.Token); } catch (OperationCanceledException) { break; }
            }
        }
    }
    private static string Pct(double? value) => value.HasValue ? $"{value:F0}%" : "N/A";
    private static string Rate(double? value) => value.HasValue ? value >= 1024 * 1024 ? $"{value / 1024 / 1024:F2} MB/s" : $"{value / 1024:F1} KB/s" : "N/A";
    private void ApplySample(MachineSample s, IReadOnlyList<ProcessSample>? processes, AppSettings settings)
    {
        Cards[0].Update(s.TimestampUtc, s.CpuPct, Pct(s.CpuPct), $"{Environment.ProcessorCount} потоков · {CpuTemperature}", settings);
        Cards[1].Update(s.TimestampUtc, s.RamPct, Pct(s.RamPct), $"{s.RamUsedBytes / 1073741824d:F1} / {s.RamTotalBytes / 1073741824d:F1} GB · commit {s.CommitBytes / 1073741824d:F1} GB", settings);
        var gpu=_latestSensors.Where(r=>r.Kind==SensorKind.Utilization && r.DeviceType=="GPU" && r.Value.HasValue && s.TimestampUtc-r.TimestampUtc<TimeSpan.FromSeconds(15)).OrderByDescending(r=>r.Value).FirstOrDefault();
        var vram=_latestSensors.Where(r=>r.Kind==SensorKind.MemoryUsed && r.DeviceType=="GPU" && r.Value.HasValue).OrderByDescending(r=>r.Value).FirstOrDefault();
        Cards[2].Update(s.TimestampUtc,gpu?.Value,Pct(gpu?.Value),$"{GpuTemperature} · VRAM {(vram?.Value/1073741824)?.ToString("F1")??"—"} GiB\n{gpu?.Source??"Нет совместимого источника"}",settings);
        Cards[3].Update(s.TimestampUtc, s.DiskActivePct, Pct(s.DiskActivePct), $"R {Rate(s.DiskReadBps)} · W {Rate(s.DiskWriteBps)}\nЗадержка {s.DiskLatencyMs?.ToString("F1") ?? "N/A"} ms · очередь {s.DiskQueue?.ToString("F1") ?? "N/A"}", settings);
        Cards[4].Update(s.TimestampUtc, s.DiskFillPct, Pct(s.DiskFillPct), $"{Path.GetPathRoot(Environment.SystemDirectory)} · занято места на томе", settings);
        // Throughput has no reliable percentage denominator across adapters; the ring stays N/A.
        Cards[5].Update(s.TimestampUtc, null, s.NetDownBps.HasValue ? $"{s.NetDownBps / 1048576:F1}" : "N/A", $"↓ {Rate(s.NetDownBps)} · ↑ {Rate(s.NetUpBps)}\nСумма адаптеров · график: автошкала", settings, s.NetDownBps);
        if (processes != null)
        {
            Processes.Clear();
            foreach (var p in processes.OrderByDescending(p => p.CpuPct ?? -1).ThenByDescending(p => p.WorkingSetBytes).Take(100)) Processes.Add(p);
        }
        Updated = DateTime.Now.ToString("HH:mm:ss") + "  ·  " + _active.RefreshSeconds + " с";
        CompactText = $"CPU {Pct(s.CpuPct)}   RAM {Pct(s.RamPct)}   Диск {Pct(s.DiskActivePct)}\n↓ {Rate(s.NetDownBps)}   ↑ {Rate(s.NetUpBps)}\nVPN {VpnStatus}";
        Changed(nameof(Updated)); Changed(nameof(CompactText));
        string NetworkRate(double? value)=>settings.NetworkMegabits?(value.HasValue?$"{value*8/1000000:F2} Мбит/с":"—"):Rate(value);
        NetworkShort=$"↓ {NetworkRate(s.NetDownBps)}   ↑ {NetworkRate(s.NetUpBps)}";Changed(nameof(NetworkShort));
        RefreshIpTrust();
    }
    private void NetworkChanged(object? sender, EventArgs args) => RequestNetworkCheck();
    public void RequestManualIpCheck(){Interlocked.Exchange(ref _manualNetworkRequested,1);RequestNetworkCheck();}
    public void RequestNetworkCheck()
    {
        if (_stop.IsCancellationRequested) return;
        Interlocked.Increment(ref _networkGeneration);
        _ipObservation=null;_ipWasManual=false;_ = Ui(RefreshIpTrust);
        _ = Ui(() => { VpnStatus = "Checking"; VpnColor = "#91B9D9";CanCaptureProfile=false;Changed(nameof(CanCaptureProfile)); Changed(nameof(VpnStatus)); Changed(nameof(VpnColor)); });
        try { if (_networkRequested.CurrentCount == 0) _networkRequested.Release(); } catch (SemaphoreFullException) { }
    }
    private async Task NetworkLoopAsync()
    {
        int failures = 0; var firstFailure = DateTimeOffset.MinValue; var lastNotification = DateTimeOffset.MinValue;
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                var activeSnapshot=_active;var manual=Interlocked.Exchange(ref _manualNetworkRequested,0)!=0;
                var settings = manual?Copy(activeSnapshot):activeSnapshot;if(manual)settings.EnablePublicIp=true;
                var generation = Volatile.Read(ref _networkGeneration);
                await Ui(() => { CanCheckIp = false;CanCaptureProfile=false;Changed(nameof(CanCaptureProfile)); VpnStatus = "Checking"; VpnColor = "#91B9D9"; Changed(nameof(CanCheckIp)); Changed(nameof(VpnStatus)); Changed(nameof(VpnColor)); });
                var check = _smoke && !_liveNetwork ? new NetworkCheck(DateTimeOffset.UtcNow, null, null, VpnState.Unknown, "—", "Smoke test: внешние IP-запросы отключены.") : await _pollGate.RunAsync(()=>_vpn.CheckAsync(settings, _stop.Token),_stop.Token);
                if (generation != Volatile.Read(ref _networkGeneration) || !ReferenceEquals(activeSnapshot, _active)) continue;
                if ((settings.EnablePublicIp || settings.EnableSiteChecks) && (!_smoke || _liveNetwork))
                {
                    await _store.SaveNetworkAsync(check);
                    if (_lastNetwork == null || check.State != _lastNetwork.State || check.IpV4 != _lastNetwork.IpV4 || check.IpV6 != _lastNetwork.IpV6)
                        await AddEventAsync(new(check.TimestampUtc, "VPN", "info", $"{_lastNetwork?.State.ToString() ?? "—"} → {check.State}; IPv4 {_lastNetwork?.IpV4 ?? "—"} → {check.IpV4 ?? "—"}; IPv6 {_lastNetwork?.IpV6 ?? "—"} → {check.IpV6 ?? "—"}. {check.Reason}"), false);
                    if (settings.VpnProfile!=null && check.State is VpnState.Disconnected or VpnState.Partial or VpnState.Offline)
                    {
                        if (failures++ == 0) firstFailure = check.TimestampUtc;
                        if (failures >= 2 && check.TimestampUtc - firstFailure >= TimeSpan.FromSeconds(5) && check.TimestampUtc - lastNotification >= TimeSpan.FromSeconds(settings.AlertCooldownSeconds))
                        {
                            await AddEventAsync(new(check.TimestampUtc, "VPN", "warning", $"{check.State}: {check.Reason}"), settings.EnableNotifications); lastNotification = check.TimestampUtc;
                        }
                    }
                    else { failures = 0; firstFailure = DateTimeOffset.MinValue; }
                }
                else { failures = 0; }
                if(generation!=Volatile.Read(ref _networkGeneration) || !ReferenceEquals(activeSnapshot,_active))continue;
                _lastNetwork = check;
                _ipWasManual=manual;
                await ObserveIpAsync(check,settings);
                if(generation!=Volatile.Read(ref _networkGeneration) || !ReferenceEquals(activeSnapshot,_active)){_ipObservation=null;await Ui(RefreshIpTrust);continue;}
                await Ui(()=>ApplyNetwork(check));
                await RefreshAdaptersAsync();
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.Write("vpn-error", ex.ToString());_ipObservation=null;await Ui(RefreshIpTrust);
                await Ui(() => { CanCaptureProfile=false;Changed(nameof(CanCaptureProfile));VpnStatus = "Unknown"; VpnColor = "#DCB66C"; VpnReason = "Ошибка проверки: " + ex.Message; Changed(nameof(VpnStatus)); Changed(nameof(VpnColor)); Changed(nameof(VpnReason)); });
            }
            finally { await Ui(() => { CanCheckIp = true; Changed(nameof(CanCheckIp)); }); }
            try
            {
                if(_ipRecheck && !_active.EnablePublicIp)Interlocked.Exchange(ref _manualNetworkRequested,1);
                var signaled = await _networkRequested.WaitAsync(TimeSpan.FromSeconds(_ipRecheck?15:_active.NetworkIntervalSeconds), _stop.Token);
                if (signaled) await Task.Delay(5000, _stop.Token);
            }
            catch (OperationCanceledException) { break; }
        }
    }
    private async Task RefreshAdaptersAsync()
    {
        var adapters = await Task.Run(VpnGuard.GetAdapters);
        await Ui(() =>
        {
            AllAdapters.Clear();foreach(var a in adapters)AllAdapters.Add(a);
            var visible=adapters.Where(AdapterClassifier.IsVisible).OrderByDescending(AdapterClassifier.IsTunnel).ThenByDescending(a=>a.Up).ToArray();
            if(!Adapters.SequenceEqual(visible)){Adapters.Clear();foreach(var a in visible)Adapters.Add(a);}
            var tunnels=visible.Where(a=>a.Up && AdapterClassifier.IsTunnel(a)).ToArray();
            AdapterSummary=tunnels.Length>0?"Найдены VPN-кандидаты: "+string.Join(", ",tunnels.Select(a=>a.Name))+". Маршруты подтверждаются в мастере.":"Активный VPN не найден однозначно. Подключите VPN или выберите подключение вручную.";Changed(nameof(AdapterSummary));
        });
    }
    public async Task RefreshInventoryAsync()
    {
        if (!CanInventory) return;
        CanInventory = false; Changed(nameof(CanInventory));
        try
        {
            var items = await Task.Run(() => HardwareInventory.Read(_stop.Token), _stop.Token);
            await _store.SaveInventoryAsync(items);
            await Ui(() => { Hardware.Clear(); foreach (var h in items) Hardware.Add(h); });
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.Write("inventory-error", ex.ToString()); }
        finally { await Ui(() => { CanInventory = true; Changed(nameof(CanInventory)); }); }
    }
    public async Task SaveSettingsAsync()
    {
        await _settingsGate.WaitAsync();
        try
        {
            var candidate = Copy(Settings); candidate.Validate();
            if (_smoke && candidate.AutoStart) throw new InvalidOperationException("Автозапуск запрещён в smoke test.");
            if (candidate.AutoStart != _active.AutoStart) await Task.Run(() => SetAutoStart(candidate.AutoStart));
            await _store.SaveSettingsAsync(candidate); _active = candidate; lock (_rules) _rules.Reset();
            SettingsMessage = "Настройки сохранены. Проверка сети запланирована через 5 секунд."; RequestNetworkCheck();
            RebuildWidgetCards();RefreshProfileSummary();SettingsApplied?.Invoke();
            Changed(nameof(Settings));RefreshIpTrust();
        }
        catch (Exception ex) { SettingsMessage = "Не удалось применить: " + ex.Message; _log.Write("settings-save-error", ex.Message); }
        finally{_settingsGate.Release();}
        Changed(nameof(SettingsMessage));
    }
    private static void SetAutoStart(bool enabled)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Путь EXE недоступен.");
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase) && enabled) throw new InvalidOperationException("Автозапуск доступен из опубликованной EXE.");
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
        if (enabled){var command=$"\"{exe}\"";if(!string.Equals(key.GetValue("PCSentinel") as string,command,StringComparison.OrdinalIgnoreCase))key.SetValue("PCSentinel",command,RegistryValueKind.String);}else key.DeleteValue("PCSentinel", false);
    }
    private async Task AddEventAsync(AlertEvent e, bool notify)
    {
        await _store.SaveAlertAsync(e); _log.Write(e.Type, e.Description);
        await Ui(() => { Events.Insert(0, e); while (Events.Count > 300) Events.RemoveAt(Events.Count - 1); if (notify) Notification?.Invoke(e.Type, e.Description); });
    }
    public async Task LoadReportAsync() { Report = await _store.RecentReportAsync(); Changed(nameof(Report)); }
    public Task ExportAsync(string path) => _store.ExportJsonAsync(path);
    public async Task WriteSmokeEvidenceAsync()
    {
        await _store.ExportJsonAsync(Path.Combine(_store.Root, "smoke-history.json"));
        await File.WriteAllTextAsync(Path.Combine(_store.Root, "smoke-result.json"), JsonSerializer.Serialize(new { samples = _sampleCount, latest = _latest, hardware = Hardware.ToArray(), sensors=_latestSensors, adapters=Adapters.ToArray(),allAdapterCount=AllAdapters.Count,vpn = _lastNetwork, processes = Processes.Count, incidents=Incidents.ToArray(),securitySources=SecuritySources,ipStatus=IpStatus, appVersion = "0.3.2", mainElevated=TemperatureHelper.IsElevated, hardwareHelper=new{Enabled=_active.EnableHardwareTemperatureHelper,Connected=_temperatureHelper.IsRunning,Pid=_temperatureHelper.HelperPid}, uiRendered = System.Windows.Application.Current.MainWindow.IsVisible }, LocalStore.Json));
        if (_sampleCount < 5 || _latest?.CpuPct is null || _latest.RamTotalBytes == 0) throw new InvalidOperationException("Smoke test: insufficient native metrics.");
    }
    public async Task StopAsync()
    {
        NetworkChange.NetworkAddressChanged -= NetworkChanged;
        await _stop.CancelAsync();
        await _temperatureHelper.StopAsync();
        await Task.WhenAll(new[] { _sampling, _networkLoop, _inventory,_sensorLoop,_securityLoop }.OfType<Task>());
        _vpn.Dispose(); _log.Write("stop", "Graceful shutdown");
    }
    public async Task EnableHardwareTemperaturesAsync()
    {
        var status=await _temperatureHelper.StartAsync();
        // Preserve the user's intent across service startup delays/restarts. Portable runs do not alter it.
        if(ProtectedInstall.CheckCurrent(out _))await SetHardwareHelperPreferenceAsync(true);
        Changed(nameof(HardwareTemperatureStatus));SetMessage(status);_log.Write("temperature-helper",status);
    }
    public async Task DisableHardwareTemperaturesAsync()
    {
        await _temperatureHelper.StopAsync();await SetHardwareHelperPreferenceAsync(false);
        Changed(nameof(HardwareTemperatureStatus));SetMessage("Подключение к службе датчиков выключено.");
    }
    private async Task SetHardwareHelperPreferenceAsync(bool enabled)
    {
        await _settingsGate.WaitAsync();
        try{var next=Copy(_active);next.EnableHardwareTemperatureHelper=enabled;await _store.SaveSettingsAsync(next);_active=next;Settings.EnableHardwareTemperatureHelper=enabled;}
        finally{_settingsGate.Release();}
    }
    public bool MinimizeToTray => _active.MinimizeToTray;
    public bool AlwaysOnTop => _active.AlwaysOnTop;
    public AppSettings ActiveSettings=>_active;
    public bool IsTestMode=>_smoke;
    public void TraceTestInput(string text){if(_smoke)_log.Write("test-input",text);}
    public async Task UpdateAutoStartAsync(bool enabled)
    {
        await _settingsGate.WaitAsync();
        try
        {
            if(_smoke)throw new InvalidOperationException("Автозапуск не меняется в тестовом режиме.");
            var next=Copy(_active);next.AutoStart=enabled;await Task.Run(()=>SetAutoStart(enabled));await _store.SaveSettingsAsync(next);_active=next;Settings.AutoStart=enabled;Changed(nameof(Settings));SettingsApplied?.Invoke();
        }
        catch(Exception ex){SetMessage(ex.Message);}
        finally{_settingsGate.Release();}
    }
    private void ApplyNetwork(NetworkCheck check)
    {
        VpnStatus=check.State.ToString();VpnReason=check.Reason;Route=check.Route;
        Ip4="IPv4: "+(check.IpV4??"—")+(check.Agree4?" · 2/2":" · нет согласования");
        Ip6="IPv6: "+(check.IpV6??"—")+(check.Agree6?" · 2/2":check.HasIpv6?" · не подтверждён":" · не обнаружен");
        VpnColor=System.Windows.SystemParameters.HighContrast?System.Windows.SystemColors.WindowTextColor.ToString():check.State==VpnState.Protected?"#24CDB4":check.State==VpnState.Disconnected?"#EF6262":"#F4B740";
        CanCaptureProfile=check.AdapterId!=null && check.RoutesVerified && check.TunnelVerified && check.Agree4 && !check.Proxy;
        Sites.Clear();foreach(var site in check.Sites??[])Sites.Add(site);
        foreach(var p in new[]{nameof(VpnStatus),nameof(VpnReason),nameof(Route),nameof(TopIp),nameof(Ip4),nameof(Ip6),nameof(VpnColor),nameof(CanCaptureProfile)})Changed(p);
    }
    private void RefreshProfileSummary()
    {
        var p=Settings.VpnProfile;
        ProfileSummary=p==null?"Профиль не настроен. 1. Подключите VPN. 2. Проверьте IP и маршруты. 3. Запомните соединение.":$"Профиль: {p.AdapterDescription}\nIPv4 {p.BaselineIp4??"—"} · IPv6 {p.BaselineIp6??"не подтверждён"}\nСоздан {p.CreatedUtc.ToLocalTime():g}. Изменение выходного IP подтверждается повторной проверкой.";
        if(p==null && !string.IsNullOrEmpty(Settings.LegacyApprovedIps))ProfileSummary+="\nСтарый список IP сохранён в legacy-конфигурации; пройдите мастер.";
        Changed(nameof(ProfileSummary));
    }
    public async Task CaptureVpnProfileAsync()
    {
        var n=_lastNetwork;
        if(Settings.AutoDetectVpn!=_active.AutoDetectVpn || Settings.PreferredAdapterId!=_active.PreferredAdapterId){SetMessage("После выбора подключения сначала сохраните настройки и повторите проверку.");return;}
        if(n==null || !CanCaptureProfile || DateTimeOffset.UtcNow-n.TimestampUtc>TimeSpan.FromSeconds(60)) {SetMessage("Нужна свежая согласованная проверка IP и маршрутов выбранного VPN. Нажмите «Проверить».");return;}
        var adapter=AllAdapters.FirstOrDefault(a=>a.Id==n.AdapterId);if(adapter==null){SetMessage("Адаптер исчез; повторите проверку.");return;}
        Settings.VpnProfile=new(adapter.Id,adapter.Description,n.IpV4,n.Agree6?n.IpV6:null,DateTimeOffset.UtcNow);
        await SaveSettingsAsync();
    }
    public void SetMessage(string message){SettingsMessage=message;Changed(nameof(SettingsMessage));}
    public void AddSite(string url){var normalized=SiteTarget.Normalize(url);if(Settings.ControlSites.Count>=12)throw new ArgumentException("Не более 12 сайтов.");if(!Settings.ControlSites.Any(s=>s.Url==normalized))Settings.ControlSites.Add(new(normalized));}
    public async Task UpdateWidgetAsync(Action<WidgetSettings> update)
    {
        await _settingsGate.WaitAsync();
        try
        {
            var next=Copy(_active);update(next.Widget);next.Validate();await _store.SaveSettingsAsync(next);_active=next;
            Settings.Widget=Copy(next).Widget;Changed(nameof(Settings));RebuildWidgetCards();SettingsApplied?.Invoke();
        }
        catch(Exception e){SetMessage("Не удалось сохранить виджет: "+e.Message);_log.Write("widget-settings",e.Message);}
        finally{_settingsGate.Release();}
    }
    private void RebuildWidgetCards()
    {
        WidgetCards.Clear();var w=_active.Widget;
        foreach(var i in new[]{(0,w.ShowCpu),(1,w.ShowRam),(2,w.ShowGpu),(3,w.ShowDisk)})if(i.Item2)WidgetCards.Add(Cards[i.Item1]);
    }
    private async Task SensorLoopAsync()
    {
        using var hub=new SensorHub([..SensorHub.DefaultProviders(),_temperatureHelper]);var rules=new TemperatureRules();
        while(!_stop.IsCancellationRequested)
        {
            try
            {
                var readings=await Task.Run(()=>hub.Poll(_stop.Token),_stop.Token);_latestSensors=readings;
                var fresh=readings.Where(r=>!_sensorSaved.TryGetValue(r.Id,out var at) || r.TimestampUtc>at).ToArray();
                if(fresh.Length>0){await _store.SaveSensorsAsync(fresh);foreach(var r in fresh)_sensorSaved[r.Id]=r.TimestampUtc;}
                await Ui(()=>
                {
                    foreach(var r in readings){var display=Sensors.FirstOrDefault(d=>d.Id==r.Id);if(display==null){display=new(r);Sensors.Add(display);}else display.Update(r);display.ApplyThresholds(_active);}
                    string Temp(string type){var r=readings.Where(x=>x.DeviceType==type && x.Kind==SensorKind.Temperature && x.Value.HasValue).OrderByDescending(x=>x.Value).FirstOrDefault();return type+" "+(r==null?"—":$"{r.Value:F0} °C");}
                    CpuTemperature=Temp("CPU");GpuTemperature=Temp("GPU");SsdTemperature=Temp("SSD");
                    string Hint(string type)=>string.Join("\n",readings.Where(r=>r.DeviceType==type && r.Kind==SensorKind.Temperature).Select(r=>$"{r.Source}: {(r.Value.HasValue?$"{r.Value:F1} °C · {r.HardwareName}":r.Reason??"Датчик недоступен")}").Distinct());
                    CpuTemperatureHint=Hint("CPU");GpuTemperatureHint=Hint("GPU");SsdTemperatureHint=Hint("SSD");
                    Changed(nameof(CpuTemperatureHint));Changed(nameof(GpuTemperatureHint));Changed(nameof(SsdTemperatureHint));
                    string Color(string type,double warning,double critical){if(System.Windows.SystemParameters.HighContrast)return System.Windows.SystemColors.WindowTextColor.ToString();var max=readings.Where(r=>r.DeviceType==type && r.Kind==SensorKind.Temperature && r.Value.HasValue).Select(r=>r.Value).DefaultIfEmpty(null).Max();return !max.HasValue?"#93A9BC":max>=critical?"#EF6262":max>=warning?"#F4B740":"#24CDB4";}
                    CpuTemperatureColor=Color("CPU",_active.CpuTemperatureWarning,_active.CpuTemperatureCritical);GpuTemperatureColor=Color("GPU",_active.GpuTemperatureWarning,_active.GpuTemperatureCritical);SsdTemperatureColor=Color("SSD",_active.SsdTemperatureWarning,_active.SsdTemperatureCritical);
                    SensorSummary=$"Доступно {readings.Count(r=>r.Value.HasValue)} из {readings.Count} показателей · подробности и источники в оборудовании";
                    Changed(nameof(CpuTemperature));Changed(nameof(GpuTemperature));Changed(nameof(SsdTemperature));Changed(nameof(SensorSummary));
                    Changed(nameof(CpuTemperatureColor));Changed(nameof(GpuTemperatureColor));Changed(nameof(SsdTemperatureColor));
                    Changed(nameof(HardwareTemperatureStatus));
                });
                if(!_active.Anomalies.Enabled)foreach(var r in fresh){var alert=rules.Check(r,_active);if(alert!=null)await AddEventAsync(alert,_active.EnableNotifications);}
                await Task.Delay(1000,_stop.Token);
            }
            catch(OperationCanceledException) when(_stop.IsCancellationRequested){break;}
            catch(Exception e){_log.Write("sensor-error",e.ToString());try{await Task.Delay(5000,_stop.Token);}catch(OperationCanceledException){break;}}
        }
    }
}

public sealed class SensorDisplay(SensorReading reading):Observable
{
    private SensorReading _reading=reading;private double? _maximum=reading.Value;
    private readonly Queue<(DateTimeOffset At,double Value)> _history=[];
    public string Id=>_reading.Id;
    public string Hardware=>_reading.HardwareName;
    public string Name=>_reading.Name;
    public string DeviceType=>_reading.DeviceType;
    public string Value=>_reading.Value.HasValue?$"{_reading.Value:F1} {_reading.Unit}":"Нет данных";
    public string Maximum=>_maximum.HasValue?$"{_maximum:F1} {_reading.Unit}":"—";
    public string Source=>_reading.Source;
    public string Status=>_reading.Status switch{SensorStatus.Available=>"Доступен",SensorStatus.AccessDenied=>"Нет доступа",SensorStatus.Unsupported=>"Не поддерживается",SensorStatus.Error=>"Ошибка",_=>"Недоступен"};
    public string Reason=>_reading.Reason??"";
    public string Timestamp=>_reading.TimestampUtc.ToLocalTime().ToString("HH:mm:ss");
    public string Color{get;private set;}="#93A9BC";
    public PointCollection Plot{get;private set;}=[];
    public void Update(SensorReading r)
    {
        var changed=r.TimestampUtc!=_reading.TimestampUtc;_reading=r;
        if(r.Value.HasValue){_maximum=_maximum.HasValue?Math.Max(_maximum.Value,r.Value.Value):r.Value;if(changed)_history.Enqueue((r.TimestampUtc,r.Value.Value));}
        while(_history.Count>0 && r.TimestampUtc-_history.Peek().At>TimeSpan.FromMinutes(5))_history.Dequeue();
        var maximum=Math.Max(1,_history.Select(x=>x.Value).DefaultIfEmpty(1).Max());
        Plot=new(_history.Select(x=>new System.Windows.Point(150*(1-(r.TimestampUtc-x.At).TotalSeconds/300),24-Math.Clamp(x.Value/maximum,0,1)*22)));
        foreach(var p in new[]{nameof(Value),nameof(Maximum),nameof(Status),nameof(Reason),nameof(Timestamp),nameof(Plot)})Changed(p);
    }
    public void ApplyThresholds(AppSettings s)
    {
        var (warning,critical)=_reading.DeviceType switch{"CPU"=>(s.CpuTemperatureWarning,s.CpuTemperatureCritical),"GPU"=>(s.GpuTemperatureWarning,s.GpuTemperatureCritical),_=>(s.SsdTemperatureWarning,s.SsdTemperatureCritical)};
        Color=_reading.Value==null?"#93A9BC":_reading.Kind!=SensorKind.Temperature?"#F1F5F9":_reading.Value>=critical?"#EF6262":_reading.Value>=warning?"#F4B740":"#24CDB4";Changed(nameof(Color));
    }
}
