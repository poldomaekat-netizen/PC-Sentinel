using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using PCSentinel.Core;
namespace PCSentinel.Collectors;

/// <summary>Unprivileged, read-only client of the installed sensor service. Never elevates or launches an EXE.</summary>
public sealed class TemperatureHelper:ISensorProvider
{
    public string Name=>"PC Sentinel sensor service";
    public TimeSpan Interval=>TimeSpan.FromSeconds(1);
    private readonly object _gate=new();private readonly SemaphoreSlim _lifecycle=new(1,1);
    private SensorReading[] _readings=[];private string _status="Служба датчиков не подключена.";
    private NamedPipeClientStream? _pipe;private CancellationTokenSource? _stop;private Task? _reader;
    private bool _connected,_requested;private int _reconnecting;private DateTimeOffset _retry;
    public int? HelperPid{get;private set;}
    public bool IsRunning{get{lock(_gate)return _connected;}}
    public string Status{get{lock(_gate)return _status;}}
    public static bool IsElevated{get{using var identity=WindowsIdentity.GetCurrent();return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);}}
    public static bool IsDriverInstalled{get{using var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO");return key!=null;}}
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    public static bool IsExpectedPeer(SafePipeHandle pipe,int expectedPid,bool serverSide)
    {uint pid;return(serverSide?GetNamedPipeClientProcessId(pipe,out pid):GetNamedPipeServerProcessId(pipe,out pid)) && pid==expectedPid;}
    public static NamedPipeClientStream CreateReader(string name)=>new(".",name,PipeAccessRights.ReadData|PipeAccessRights.ReadAttributes|PipeAccessRights.ReadPermissions|PipeAccessRights.Synchronize,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification,HandleInheritability.None);
    public async Task<string> StartAsync()
    {
        _requested=true;await _lifecycle.WaitAsync();
        try{return await ConnectCoreAsync();}finally{_lifecycle.Release();}
    }
    private async Task<string> ConnectCoreAsync()
    {
        if(IsRunning)return Status;await StopCoreAsync();
        if(!ProtectedInstall.CheckCurrent(out var reason)){lock(_gate)_status=reason;_requested=false;return Status;}
        try
        {
            var service=SensorServiceControl.GetRunning();
            if(service==null){lock(_gate)_status="Служба датчиков не установлена или не запущена. Используйте установщик.";return Status;}
            _stop=new();_pipe=CreateReader(SensorServiceControl.PipeName);
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));await _pipe.ConnectAsync(timeout.Token);
            if(!IsExpectedPeer(_pipe.SafePipeHandle,service.Pid,false) || SensorServiceControl.GetRunning()?.Pid!=service.Pid)throw new IOException("Подключение не принадлежит установленной службе датчиков.");
            HelperPid=service.Pid;lock(_gate){_connected=true;_status="Служба датчиков подключена · без UAC при запуске.";}
            _reader=ReceiveAsync(_pipe,_stop.Token);return Status;
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or OperationCanceledException or TimeoutException)
        {await StopCoreAsync();lock(_gate)_status="Служба датчиков недоступна: "+e.Message;return Status;}
    }
    private async Task ReceiveAsync(Stream pipe,CancellationToken token)
    {
        try
        {
            var header=new byte[4];
            while(!token.IsCancellationRequested)
            {
                await pipe.ReadExactlyAsync(header,token);var length=BitConverter.ToInt32(header);
                if(length is <=0 or >65536)throw new InvalidDataException("Неверный размер сообщения датчиков.");
                var data=new byte[length];await pipe.ReadExactlyAsync(data,token);
                var readings=JsonSerializer.Deserialize<SensorReading[]>(data)??[];
                lock(_gate)_readings=Validate(readings,DateTimeOffset.UtcNow).Select(r=>r with{Source=Name}).ToArray();
            }
        }
        catch(Exception e) when(e is IOException or OperationCanceledException or JsonException or ObjectDisposedException)
        {lock(_gate){_connected=false;_readings=[];_status="Связь со службой датчиков потеряна.";}}
    }
    public static IReadOnlyList<SensorReading> Validate(IEnumerable<SensorReading> readings,DateTimeOffset now)=>readings.Take(16)
        .Where(r=>r.DeviceType is "CPU" or "GPU" && r.Kind==SensorKind.Temperature && r.Unit=="°C" && now-r.TimestampUtc<=TimeSpan.FromSeconds(15) && r.TimestampUtc-now<=TimeSpan.FromSeconds(5))
        .Select(r=>r with{Value=r.Value is >0 and <=150 && double.IsFinite(r.Value.Value)?r.Value:null})
        .Select(r=>r with{Status=r.Value.HasValue?SensorStatus.Available:SensorStatus.Unavailable}).ToArray();
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(_requested && !IsRunning && DateTimeOffset.UtcNow>=_retry && Interlocked.CompareExchange(ref _reconnecting,1,0)==0)
        {_retry=DateTimeOffset.UtcNow.AddSeconds(10);_=ReconnectAsync();}
        lock(_gate){var fresh=Validate(_readings,DateTimeOffset.UtcNow);return new[]{"CPU","GPU"}.Select(type=>fresh.FirstOrDefault(r=>r.DeviceType==type)??new("Service:"+type,type,type,SensorKind.Temperature,type,null,"°C",Name,DateTimeOffset.UtcNow,SensorStatus.Unavailable,_status)).ToArray();}
    }
    private async Task ReconnectAsync()
    {try{await _lifecycle.WaitAsync();try{if(_requested)await ConnectCoreAsync();}finally{_lifecycle.Release();}}finally{Interlocked.Exchange(ref _reconnecting,0);}}
    public async Task StopAsync()
    {_requested=false;await _lifecycle.WaitAsync();try{await StopCoreAsync();}finally{_lifecycle.Release();}}
    private async Task StopCoreAsync()
    {
        if(_stop!=null)await _stop.CancelAsync();_pipe?.Dispose();if(_reader!=null)await _reader;
        _pipe=null;_reader=null;_stop?.Dispose();_stop=null;HelperPid=null;lock(_gate){_connected=false;_readings=[];_status="Подключение к службе датчиков выключено.";}
    }
    public void Dispose(){_requested=false;_stop?.Cancel();_pipe?.Dispose();}
    // Legacy command is deliberately rejected; no portable EXE can act as an elevated helper.
    public static Task<int> RunWorkerAsync(string[] arguments)=>Task.FromResult(2);
}
