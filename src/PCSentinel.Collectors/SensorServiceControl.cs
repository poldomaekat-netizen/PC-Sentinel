using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace PCSentinel.Collectors;

public static class SensorServiceControl
{
    public const string ServiceName="PCSentinelSensors";
    public const string PipeName="PCSentinel.SensorService.v1";
    public static string Executable=>Path.Combine(ProtectedInstall.Root,"Service","PCSentinel.SensorService.exe");
    public sealed record Snapshot(int Pid,string BinaryPath,uint State);
    private sealed class Handle:SafeHandleZeroOrMinusOneIsInvalid
    {private Handle():base(true){}protected override bool ReleaseHandle()=>CloseServiceHandle(handle);}
    [StructLayout(LayoutKind.Sequential)]private struct Status{public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint,Pid,Flags;}
    [StructLayout(LayoutKind.Sequential)]private struct Config{public uint Type,Start,Error;public IntPtr Binary,Group;public uint Tag;public IntPtr Dependencies,Account,Display;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern Handle OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern Handle OpenService(Handle manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool QueryServiceStatusEx(Handle service,int level,out Status status,int size,out int needed);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool QueryServiceConfig(Handle service,IntPtr buffer,int size,out int needed);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern Handle CreateService(Handle manager,string name,string display,uint access,uint type,uint start,uint error,string binary,string? group,IntPtr tag,string? dependencies,string? account,string? password);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool ChangeServiceConfig(Handle service,uint type,uint start,uint error,string binary,string? group,IntPtr tag,string? dependencies,string? account,string? password,string display);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool StartService(Handle service,uint count,IntPtr arguments);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool ControlService(Handle service,uint control,out Status status);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool DeleteService(Handle service);
    private static void Require(bool success){if(!success)throw new Win32Exception(Marshal.GetLastWin32Error());}
    private static string ValidateConfig(Handle service)
    {
        QueryServiceConfig(service,IntPtr.Zero,0,out var size);if(size is <=0 or >65536)throw new IOException("Некорректная конфигурация службы.");
        var memory=Marshal.AllocHGlobal(size);
        try
        {
            Require(QueryServiceConfig(service,memory,size,out _));var c=Marshal.PtrToStructure<Config>(memory);
            var binary=Marshal.PtrToStringUni(c.Binary)??"";var account=Marshal.PtrToStringUni(c.Account)??"";
            if(!IsExpectedBinary(binary) || !account.Equals("LocalSystem",StringComparison.OrdinalIgnoreCase) || c.Type!=0x10)throw new IOException("Служба с этим именем имеет неожиданную конфигурацию.");
            return binary;
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
    public static bool IsExpectedBinary(string command)=>string.Equals(command,$"\"{Executable}\" --service",StringComparison.OrdinalIgnoreCase);
    public static Snapshot? GetRunning()
    {
        using var manager=OpenSCManager(null,null,1);if(manager.IsInvalid)return null;
        using var service=OpenService(manager,ServiceName,5);if(service.IsInvalid)return null;
        var binary=ValidateConfig(service);Require(QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<Status>(),out _));
        return status.State==4 && status.Pid>0?new((int)status.Pid,binary,status.State):null;
    }
    public static void Install()
    {
        if(!TemperatureHelper.IsElevated)throw new UnauthorizedAccessException("Нужны права администратора.");
        if(!ProtectedInstall.CheckCurrent(out var reason))throw new UnauthorizedAccessException("Нужна защищённая установка. "+reason);
        using var manager=OpenSCManager(null,null,3);if(manager.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
        var binary=$"\"{Executable}\" --service";
        using var existing=OpenService(manager,ServiceName,0xF01FF);
        if(!existing.IsInvalid)
        {
            ValidateConfig(existing);Stop(existing);
            Require(ChangeServiceConfig(existing,0x10,2,1,binary,null,IntPtr.Zero,"PawnIO\0",null,null,"PC Sentinel — аппаратные температуры"));
            Start(existing);return;
        }
        if(Marshal.GetLastWin32Error()!=1060)throw new Win32Exception(Marshal.GetLastWin32Error());
        using var created=CreateService(manager,ServiceName,"PC Sentinel — аппаратные температуры",0xF01FF,0x10,2,1,binary,null,IntPtr.Zero,"PawnIO\0",null,null);
        if(created.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());Start(created);
    }
    private static void Start(Handle service)
    {
        if(!StartService(service,0,IntPtr.Zero) && Marshal.GetLastWin32Error()!=1056)throw new Win32Exception(Marshal.GetLastWin32Error());
        var watch=System.Diagnostics.Stopwatch.StartNew();
        while(watch.Elapsed<TimeSpan.FromSeconds(30))
        {Require(QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<Status>(),out _));if(status.State==4)return;if(status.State==1)throw new IOException("Служба завершилась: "+status.Win32Exit);Thread.Sleep(150);}
        throw new TimeoutException("Служба не запустилась вовремя.");
    }
    private static void Stop(Handle service)
    {
        Require(QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<Status>(),out _));if(status.State==1)return;
        if(!ControlService(service,1,out _) && Marshal.GetLastWin32Error()!=1062)throw new Win32Exception(Marshal.GetLastWin32Error());
        var watch=System.Diagnostics.Stopwatch.StartNew();
        while(watch.Elapsed<TimeSpan.FromSeconds(30)){Require(QueryServiceStatusEx(service,0,out status,Marshal.SizeOf<Status>(),out _));if(status.State==1)return;Thread.Sleep(150);}throw new TimeoutException("Служба не остановилась вовремя.");
    }
    public static void Uninstall()
    {
        if(!TemperatureHelper.IsElevated)throw new UnauthorizedAccessException();
        using var manager=OpenSCManager(null,null,1);using var service=OpenService(manager,ServiceName,0xF01FF);
        if(service.IsInvalid){if(Marshal.GetLastWin32Error()==1060)return;throw new Win32Exception(Marshal.GetLastWin32Error());}
        ValidateConfig(service);Stop(service);Require(DeleteService(service));
    }
}
