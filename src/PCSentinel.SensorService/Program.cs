using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using PCSentinel.Collectors;
using PCSentinel.Core;

try
{
    if(args is ["--install"]){SensorServiceControl.Install();return 0;}
    if(args is ["--uninstall"])
    {
        SensorServiceControl.Uninstall();
        foreach(var hive in Microsoft.Win32.Registry.Users.GetSubKeyNames().Where(n=>n.StartsWith("S-1-5-21-",StringComparison.Ordinal) && !n.EndsWith("_Classes",StringComparison.Ordinal)))
        {
            try
            {
                using var run=Microsoft.Win32.Registry.Users.OpenSubKey(hive+@"\Software\Microsoft\Windows\CurrentVersion\Run",true);
                var command=run?.GetValue("PCSentinel") as string;
                if(string.Equals(command,$"\"{Path.Combine(ProtectedInstall.Root,"PCSentinel.exe")}\"",StringComparison.OrdinalIgnoreCase))run!.DeleteValue("PCSentinel",false);
            }
            catch(UnauthorizedAccessException){}
        }
        return 0;
    }
    if(args is ["--prune-backup",var backup])
    {
        backup=Path.GetFullPath(backup);
        if(!TemperatureHelper.IsElevated || !ProtectedInstall.CheckCurrent(out _) || !string.Equals(Path.GetDirectoryName(backup),Path.GetDirectoryName(ProtectedInstall.Root),StringComparison.OrdinalIgnoreCase) || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(backup),@"^PC Sentinel\.previous-\d{14}-[0-9A-Fa-f]{8}$") || !ProtectedInstall.CheckTree(backup,out _))return 2;
        Directory.Delete(backup,true);return 0;
    }
    if(args is not ["--service"] || !ProtectedInstall.CheckCurrent(out _) || !TemperatureHelper.IsElevated)return 2;
    return ServiceHost.Run();
}
catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}

internal static class ServiceHost
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]private delegate void MainCallback(uint count,IntPtr arguments);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]private delegate uint Handler(uint control,uint eventType,IntPtr eventData,IntPtr context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct Entry{[MarshalAs(UnmanagedType.LPWStr)]public string? Name;public MainCallback? Main;}
    [StructLayout(LayoutKind.Sequential)]private struct Status{public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool StartServiceCtrlDispatcher([In]Entry[] table);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr RegisterServiceCtrlHandlerEx(string name,Handler handler,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool SetServiceStatus(IntPtr service,ref Status status);
    private static readonly CancellationTokenSource Stop=new();private static IntPtr _handle;
    private static readonly MainCallback MainDelegate=ServiceMain;private static readonly Handler HandlerDelegate=Control;
    private static void Report(uint state,uint exit=0)
    {var status=new Status{Type=0x10,State=state,Controls=state==4?5u:0u,Win32Exit=exit,WaitHint=state is 2 or 3?30000u:0u,Checkpoint=state is 2 or 3?1u:0u};SetServiceStatus(_handle,ref status);}
    public static int Run()=>StartServiceCtrlDispatcher([new(){Name=SensorServiceControl.ServiceName,Main=MainDelegate},new()])?0:Marshal.GetLastWin32Error();
    private static uint Control(uint control,uint eventType,IntPtr eventData,IntPtr context)
    {if(control is 1 or 5){Report(3);Stop.Cancel();}else if(control==4)Report(Stop.IsCancellationRequested?3u:4u);return 0;}
    private static void ServiceMain(uint count,IntPtr arguments)
    {
        _handle=RegisterServiceCtrlHandlerEx(SensorServiceControl.ServiceName,HandlerDelegate,IntPtr.Zero);if(_handle==IntPtr.Zero)return;
        Report(2);
        try{Report(4);ServeAsync(Stop.Token).GetAwaiter().GetResult();Report(1);}
        catch(OperationCanceledException) when(Stop.IsCancellationRequested){Report(1);}
        catch{Report(1,1064);}
    }
    private static async Task ServeAsync(CancellationToken token)
    {
        // Outbound telemetry only. Clients have no pipe write permission and cannot submit commands.
        var security=new PipeSecurity();var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        security.SetOwner(system);security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
        security.AddAccessRule(new(system,PipeAccessRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid,null),PipeAccessRights.ReadData|PipeAccessRights.ReadAttributes|PipeAccessRights.ReadPermissions|PipeAccessRights.Synchronize,AccessControlType.Allow));
        using ISensorProvider provider=AmdTemperatureProvider.IsSupported?new AmdTemperatureProvider():new PawnIoTemperatureProvider();
        while(!token.IsCancellationRequested)
        {
            using var pipe=NamedPipeServerStreamAcl.Create(SensorServiceControl.PipeName,PipeDirection.Out,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.FirstPipeInstance,0,8192,security);
            await pipe.WaitForConnectionAsync(token);
            try
            {
                while(pipe.IsConnected && !token.IsCancellationRequested)
                {
                    IReadOnlyList<SensorReading> readings;
                    try{readings=provider.Read(token);}catch(Exception e) when(e is not OperationCanceledException)
                    {readings=[new("CPU","CPU","CPU",SensorKind.Temperature,"Temperature",null,"°C",provider.Name,DateTimeOffset.UtcNow,SensorStatus.Error,e.Message)];}
                    var data=JsonSerializer.SerializeToUtf8Bytes(readings);if(data.Length>65536)throw new InvalidDataException();
                    using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    await pipe.WriteAsync(BitConverter.GetBytes(data.Length),timeout.Token);await pipe.WriteAsync(data,timeout.Token);await pipe.FlushAsync(timeout.Token);
                    await Task.Delay(4000,token);
                }
            }
            catch(Exception e) when(e is IOException || e is OperationCanceledException && !token.IsCancellationRequested){}
        }
    }
}
