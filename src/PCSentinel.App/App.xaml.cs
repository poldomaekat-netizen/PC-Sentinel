using System.IO;
using System.Windows;
using PCSentinel.Storage;

namespace PCSentinel.App;

public partial class App : System.Windows.Application
{
    private Mutex? _mutex;
    private EventWaitHandle? _quitEvent;private RegisteredWaitHandle? _quitWait;
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if(e.Args.Contains("--hardware-sensor-helper")){Shutdown(await PCSentinel.Collectors.TemperatureHelper.RunWorkerAsync(e.Args));return;}
        var interactive = e.Args.Contains("--interactive-test");
        var liveNetwork=e.Args.Contains("--network-test");
        var desktopTest=e.Args.Contains("--desktop-test");
        var smoke = e.Args.Contains("--smoke-test") || interactive || liveNetwork || desktopTest;
        _mutex = new Mutex(true, smoke ? "Local\\PCSentinel.Smoke" : "Local\\PCSentinel.Desktop", out var created);
        if (!created) { System.Windows.MessageBox.Show("PC Sentinel уже работает. Откройте окно через значок в трее.", "PC Sentinel"); Shutdown(); return; }
        string? root = null;
        if (smoke)
        {
            var index = Array.IndexOf(e.Args, "--data-dir");
            if (index < 0 || index + 1 >= e.Args.Length) { Shutdown(2); return; }
            root = Path.GetFullPath(e.Args[index + 1]);
        }
        var store = new LocalStore(root); var logger = new LocalLogger(store.Root);
        DispatcherUnhandledException += (_, args) => { logger.Write("ui-error", args.Exception.ToString()); args.Handled = true; if (smoke) Shutdown(1); else System.Windows.MessageBox.Show(args.Exception.Message, "PC Sentinel — ошибка"); };
        try
        {
            var vm = new MainViewModel(store,logger,smoke,liveNetwork);
            var window = new MainWindow(vm, smoke && !interactive); MainWindow = window; window.Show();
            await vm.StartAsync();
            if(e.Args.Contains("--enable-hardware-temperatures"))await vm.EnableHardwareTemperaturesAsync();
            window.AfterStart();
            if(!smoke)
            {
                var security=new System.Security.AccessControl.EventWaitHandleSecurity();
                using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
                foreach(var sid in new[]{identity.User!,new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid,null),new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,null)})
                    security.AddAccessRule(new(sid,System.Security.AccessControl.EventWaitHandleRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
                _quitEvent=EventWaitHandleAcl.Create(false,EventResetMode.AutoReset,"Local\\PCSentinel.RequestExit",out _,security);
                _quitWait=ThreadPool.RegisterWaitForSingleObject(_quitEvent,(_,_)=>{_=Dispatcher.InvokeAsync(async()=>await window.QuitAsync());},null,Timeout.Infinite,true);
            }
            if(interactive)
            {
                var lifetimeIndex=Array.IndexOf(e.Args,"--interactive-seconds");
                if(lifetimeIndex>=0 && lifetimeIndex+1<e.Args.Length && int.TryParse(e.Args[lifetimeIndex+1],out var lifetime))
                {_=Task.Run(async()=>{await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(lifetime,30,600)));await Dispatcher.InvokeAsync(async()=>await window.QuitAsync());});}
            }
            if (smoke && !interactive)
            {
                var seconds=15;var argIndex=Array.IndexOf(e.Args,"--smoke-seconds");
                if(argIndex>=0 && argIndex+1<e.Args.Length && int.TryParse(e.Args[argIndex+1],out var requested))seconds=Math.Clamp(requested,15,180);
                await Task.Delay(TimeSpan.FromSeconds(3));
                using var process=System.Diagnostics.Process.GetCurrentProcess();var cpuStart=process.TotalProcessorTime;var clock=System.Diagnostics.Stopwatch.StartNew();var memoryStart=process.WorkingSet64;
                var memorySamples=new List<object>();var finish=DateTimeOffset.UtcNow.AddSeconds(seconds);
                while(DateTimeOffset.UtcNow<finish)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Min(15,Math.Max(0.01,(finish-DateTimeOffset.UtcNow).TotalSeconds))));process.Refresh();
                    memorySamples.Add(new{Seconds=clock.Elapsed.TotalSeconds,WorkingSetBytes=process.WorkingSet64,PrivateBytes=process.PrivateMemorySize64,ManagedBytes=GC.GetTotalMemory(false),Gen0=GC.CollectionCount(0),Gen1=GC.CollectionCount(1),Gen2=GC.CollectionCount(2)});
                }
                process.Refresh();var cpu=100*(process.TotalProcessorTime-cpuStart).TotalMilliseconds/clock.Elapsed.TotalMilliseconds/Environment.ProcessorCount;
                await File.WriteAllTextAsync(Path.Combine(store.Root,"performance.json"),System.Text.Json.JsonSerializer.Serialize(new{DurationSeconds=clock.Elapsed.TotalSeconds,CpuPct=cpu,LogicalProcessors=Environment.ProcessorCount,MemoryStartBytes=memoryStart,MemoryEndBytes=process.WorkingSet64,MemorySamples=memorySamples},LocalStore.Json));
                if(desktopTest)await window.CaptureDesktopAcceptanceAsync(store.Root);
                await window.CaptureSmokeScreensAsync(store.Root);
                await vm.WriteSmokeEvidenceAsync();
                await window.QuitAsync();
            }
        }
        catch (Exception ex) { logger.Write("startup-error", ex.ToString()); if (!smoke) System.Windows.MessageBox.Show(ex.Message, "PC Sentinel — запуск не выполнен"); Shutdown(1); }
    }
    protected override void OnExit(ExitEventArgs e) { _quitWait?.Unregister(null);_quitEvent?.Dispose();_mutex?.Dispose(); base.OnExit(e); }
}

public sealed class LocalLogger
{
    private readonly string _root;
    private readonly object _gate = new();
    public LocalLogger(string root) => _root = Path.Combine(root, "logs");
    public void Write(string type, string message)
    {
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(_root); var path = Path.Combine(_root, "sentinel.jsonl");
                if (File.Exists(path) && new FileInfo(path).Length > 5 * 1024 * 1024) File.Move(path, path + ".1", true);
                File.AppendAllText(path, System.Text.Json.JsonSerializer.Serialize(new { timestampUtc = DateTimeOffset.UtcNow, type, message }) + Environment.NewLine);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
