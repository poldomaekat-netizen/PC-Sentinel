using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using PCSentinel.Core;

namespace PCSentinel.Collectors;

/// <summary>Optional read-only temperatures through an already installed official PawnIO driver.
/// Never installs, starts, configures or elevates anything. Only two MSRs and one documented GT register are read.</summary>
public sealed class PawnIoTemperatureProvider : ISensorProvider
{
    public string Name=>"Intel hardware / PawnIO";
    public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    private Module? _msr,_mch;private DateTimeOffset _retry;private string _reason="Для CPU требуется дополнительный источник датчиков PawnIO. Автоматической установки нет.";
    private readonly bool _intel=IsIntel();private readonly bool _gt=SupportsGtRegister();
    private static bool IsIntel()=>X86Base.IsSupported && X86Base.CpuId(0,0) is var id && id.Ebx==0x756e6547 && id.Edx==0x49656e69 && id.Ecx==0x6c65746e;
    private static bool SupportsGtRegister()
    {
        if(!IsIntel())return false;var eax=X86Base.CpuId(1,0).Eax;var family=(eax>>8)&15;var model=((eax>>4)&15)|((eax>>12)&240);
        // Raptor Lake only (Intel datasheet 767624/764981). Never interpret this MMIO offset on unrelated hardware.
        return family==6 && model is 0xB7 or 0xBA or 0xBF;
    }
    private void Connect()
    {
        if(!_intel){_reason="Этот источник поддерживает только Intel x64.";return;}
        using var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO");
        if(key==null)return;
        _msr=Module.Open("IntelMSR",out var error);
        if(_msr==null){_reason=$"PawnIO недоступен (Win32 {error}). Может потребоваться запуск с правами администратора.";return;}
        if(_gt)_mch=Module.Open("IntelMCHBAR",out _);
    }
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();var now=DateTimeOffset.UtcNow;
        if(_msr==null && now>=_retry){_retry=now.AddSeconds(60);Connect();}
        var result=new List<SensorReading>();double? cpu=null,gpu=null;
        if(_msr!=null)
        {
            var target=_msr.Read("ioctl_read_msr",0x1A2);var tj=target.HasValue?(int)((target.Value>>16)&255):0;
            if(tj is >=60 and <=125)
            {
                var package=_msr.Read("ioctl_read_msr",0x1B1);
                if(package.HasValue)cpu=Decode(package.Value,tj,127);
                if(_mch!=null){var gt=_mch.Read("ioctl_read_dword",0x59C0);if(gt.HasValue)gpu=Decode(gt.Value,tj,255);}
            }
        }
        result.Add(new("CPU:package","CPU Package","CPU",SensorKind.Temperature,"CPU Package",cpu,"°C",Name,now,cpu.HasValue?SensorStatus.Available:SensorStatus.Unavailable,cpu.HasValue?null:_msr==null?_reason:"Достоверное чтение MSR 0x1A2/0x1B1 не получено."));
        if(_gt)result.Add(new("Intel:GT","Intel integrated graphics (GT)","GPU",SensorKind.Temperature,"GPU GT",gpu,"°C",Name,now,gpu.HasValue?SensorStatus.Available:SensorStatus.Unavailable,gpu.HasValue?null:_msr==null?_reason:"GT thermal sensor 0x59C0 не выдал валидное значение."));
        return result;
    }
    public static double? Decode(ulong status,int tjMax,int distanceMask)
    {
        if((status&0x80000000)==0 || status==uint.MaxValue || tjMax is <60 or >125 || distanceMask is not (127 or 255))return null;
        var value=tjMax-(int)((status>>16)&(uint)distanceMask);
        return value is >0 and <=150?value:null;
    }
    public void Dispose(){_mch?.Dispose();_msr?.Dispose();_mch=null;_msr=null;}

    internal sealed class Module(SafeFileHandle handle,string moduleName):IDisposable
    {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)]private static extern bool DeviceIoControl(SafeFileHandle device,uint code,byte[] input,int inputLength,byte[] output,int outputLength,out int bytes,IntPtr overlapped);
        public static Module? Open(string name,out int error)
        {
            if(name is not ("IntelMSR" or "IntelMCHBAR" or "AMDFamily17"))throw new ArgumentOutOfRangeException(nameof(name));
            if(!ProtectedInstall.CheckCurrent(out _)){error=5;return null;}
            error=0;var handle=CreateFile(@"\\?\GLOBALROOT\Device\PawnIO",3,3,IntPtr.Zero,3,0,IntPtr.Zero);
            if(handle.IsInvalid){error=Marshal.GetLastWin32Error();handle.Dispose();return null;}
            try
            {
                // Replacement modules are permitted only in the validated, administrator-owned installation.
                var path=Path.Combine(AppContext.BaseDirectory,"SensorModules",name+".bin");byte[] data;
                if(File.Exists(path))data=File.ReadAllBytes(path);
                else{using var stream=typeof(Module).Assembly.GetManifestResourceStream("PCSentinel.SensorModules."+name+".bin")!;using var buffer=new MemoryStream();stream.CopyTo(buffer);data=buffer.ToArray();}
                if(DeviceIoControl(handle,0xA1B22084,data,data.Length,[],0,out _,IntPtr.Zero))return new(handle,name);
                error=Marshal.GetLastWin32Error();handle.Dispose();return null;
            }
            catch{handle.Dispose();throw;}
        }
        public ulong? Read(string function,ulong index)
        {
            // Restrict this client to temperature register reads. There is no register-write entry point.
            if(!(moduleName=="IntelMSR" && function=="ioctl_read_msr" && index is 0x1A2 or 0x1B1 || moduleName=="IntelMCHBAR" && function=="ioctl_read_dword" && index==0x59C0 || moduleName=="AMDFamily17" && function=="ioctl_read_smn" && index==0x59800))throw new ArgumentOutOfRangeException(nameof(index));
            var input=new byte[40];System.Text.Encoding.ASCII.GetBytes(function).CopyTo(input,0);BitConverter.GetBytes(index).CopyTo(input,32);var output=new byte[8];
            return DeviceIoControl(handle,0xA1B22104,input,input.Length,output,output.Length,out var bytes,IntPtr.Zero) && bytes==8?BitConverter.ToUInt64(output):null;
        }
        public void Dispose()=>handle.Dispose();
    }
}
