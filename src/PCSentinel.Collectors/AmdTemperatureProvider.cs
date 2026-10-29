using System.Runtime.Intrinsics.X86;
using PCSentinel.Core;
namespace PCSentinel.Collectors;

public sealed class AmdTemperatureProvider:ISensorProvider
{
    public string Name=>"AMD Tctl / PawnIO";
    public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    private PawnIoTemperatureProvider.Module? _module;private DateTimeOffset _retry;private string _reason="Датчик AMD недоступен.";
    public static bool IsSupported
    {
        get
        {
            if(!X86Base.IsSupported)return false;var vendor=X86Base.CpuId(0,0);
            if(vendor.Ebx!=0x68747541 || vendor.Edx!=0x69746E65 || vendor.Ecx!=0x444D4163)return false;
            var eax=X86Base.CpuId(1,0).Eax;var family=((eax>>8)&15)+((eax>>20)&255);
            return family is >=0x17 and <=0x1A;
        }
    }
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        if(!IsSupported)return [];token.ThrowIfCancellationRequested();var now=DateTimeOffset.UtcNow;
        if(_module==null && now>=_retry){_retry=now.AddMinutes(1);_module=PawnIoTemperatureProvider.Module.Open("AMDFamily17",out var error);_reason="AMDFamily17: Win32 "+error;}
        double? value=null;
        if(_module!=null)
        {
            // The shared PCI index/data pair must be serialized with other hardware monitors.
            using var mutex=new Mutex(false,@"Global\Access_PCI");var owned=false;
            try
            {
                try{owned=mutex.WaitOne(100);}catch(AbandonedMutexException){owned=true;}
                if(owned){var raw=_module.Read("ioctl_read_smn",0x59800);if(raw.HasValue)value=Decode((uint)raw.Value);}
            }
            finally{if(owned)mutex.ReleaseMutex();}
        }
        return [new("AMD:Tctl","AMD CPU · Tctl (control)","CPU",SensorKind.Temperature,"CPU Tctl (control temperature)",value,"°C",Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unavailable,value.HasValue?"Аппаратный Tctl; на некоторых AMD отличается от Tdie. Не выдаётся за Tdie.":_reason)];
    }
    public static double? Decode(uint raw)
    {
        if(raw is 0 or uint.MaxValue)return null;
        var value=((raw>>21)&0x7FF)*0.125;
        if((raw&(1u<<19))!=0 || (raw&(3u<<16))==(3u<<16))value-=49;
        return value is >0 and <=150?value:null;
    }
    public void Dispose()=>_module?.Dispose();
}
