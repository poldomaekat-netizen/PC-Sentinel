using System.Management;
using System.Runtime.InteropServices;
using PCSentinel.Core;

namespace PCSentinel.Collectors;

public sealed class SensorHub : IDisposable
{
    private readonly ISensorProvider[] _providers;
    private readonly Dictionary<string,DateTimeOffset> _due=[];
    private readonly Dictionary<string,SensorReading[]> _cache=[];
    public static ISensorProvider[] DefaultProviders()=>[new GpuPdhProvider(),new NvmlProvider(),new AdlxProvider(),new IgclProvider(),new WindowsGpuTemperatureProvider(),new DirectStorageTemperatureProvider(),new PresentMonSensorProvider(),new StorageSensorProvider(),new PawnIoTemperatureProvider()];
    public SensorHub(params ISensorProvider[] providers) => _providers=providers.Length>0?providers:DefaultProviders();
    // Called by one worker. Slow providers never spawn overlapping polls.
    public IReadOnlyList<SensorReading> Poll(CancellationToken token)
    {
        foreach(var p in _providers)
        {
            token.ThrowIfCancellationRequested(); var now=DateTimeOffset.UtcNow;
            if(_due.TryGetValue(p.Name,out var due) && now<due)continue;
            try
            {
                _cache[p.Name]=p.Read(token).Select(r=>
                {
                    var value=SensorValues.Validate(r.Kind,r.Value);
                    return r with { Value=value,Status=value.HasValue?SensorStatus.Available:r.Status==SensorStatus.Available?SensorStatus.Unavailable:r.Status };
                }).ToArray();
            }
            catch(OperationCanceledException){throw;}
            catch(Exception e){_cache[p.Name]=[new(p.Name,p.Name,"System",SensorKind.Temperature,p.Name,null,"°C",p.Name,now,SensorStatus.Error,e.Message)];}
            _due[p.Name]=DateTimeOffset.UtcNow+p.Interval;
        }
        return _cache.Values.SelectMany(x=>x).ToArray();
    }
    public void Dispose(){foreach(var p in _providers)p.Dispose();}
}

public sealed class StorageSensorProvider : ISensorProvider
{
    public string Name=>"Windows Storage CIM";
    public TimeSpan Interval=>TimeSpan.FromSeconds(60);
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        var result=new List<SensorReading>(); var now=DateTimeOffset.UtcNow;
        var values=new Dictionary<string,Dictionary<string,double?>>();Exception? counterError=null;
        try
        {
            using var counterSearch=new ManagementObjectSearcher("root\\Microsoft\\Windows\\Storage","SELECT * FROM MSFT_StorageReliabilityCounter",new System.Management.EnumerationOptions{Timeout=TimeSpan.FromSeconds(3),ReturnImmediately=false});
            using var counters=counterSearch.Get();
            foreach(ManagementObject counter in counters)using(counter)
            {
                var map=new Dictionary<string,double?>();foreach(var key in new[]{"Temperature","Wear","ReadErrorsTotal","WriteErrorsTotal","PowerOnHours"})
                {try{map[key]=counter[key]==null?null:Convert.ToDouble(counter[key]);}catch(ManagementException){map[key]=null;}}
                values[counter["DeviceId"]?.ToString()??""]=map;
            }
        }
        catch(Exception e) when(e is ManagementException or UnauthorizedAccessException or COMException){counterError=e;}
        try
        {
            using var search=new ManagementObjectSearcher("root\\Microsoft\\Windows\\Storage","SELECT * FROM MSFT_PhysicalDisk",new System.Management.EnumerationOptions { Timeout=TimeSpan.FromSeconds(3),ReturnImmediately=false });
            using var disks=search.Get();
            foreach(ManagementObject disk in disks)
            using(disk)
            {
                token.ThrowIfCancellationRequested(); var id=disk["UniqueId"]?.ToString()??disk["DeviceId"]?.ToString()??"unknown"; var name=disk["FriendlyName"]?.ToString()??"Накопитель";
                try
                {
                    if(counterError!=null)
                    {
                        var denied=counterError is UnauthorizedAccessException || counterError.Message.Contains("доступ",StringComparison.OrdinalIgnoreCase) || counterError is ManagementException{ErrorCode:ManagementStatus.AccessDenied};
                        result.Add(new("Disk:"+id,name,"SSD",SensorKind.Temperature,"Temperature",null,"°C",Name,now,denied?SensorStatus.AccessDenied:SensorStatus.Unavailable,"StorageReliabilityCounter: "+counterError.Message));continue;
                    }
                    var found=false;
                    if(values.TryGetValue(disk["DeviceId"]?.ToString()??"",out var counter))
                    {
                        found=true;
                        foreach(var (property,kind,unit) in new[]{("Temperature",SensorKind.Temperature,"°C"),("Wear",SensorKind.Wear,"%"),("ReadErrorsTotal",SensorKind.ReadErrors,""),("WriteErrorsTotal",SensorKind.WriteErrors,""),("PowerOnHours",SensorKind.PowerOnHours,"h")})
                        {
                            double? value=counter.GetValueOrDefault(property);
                            // Storage drivers commonly use zero as unavailable for temperature.
                            if(kind==SensorKind.Temperature && value<=0)value=null;
                            result.Add(new("Disk:"+id,name,"SSD",kind,property,value,unit,Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unsupported,value.HasValue?null:"Драйвер накопителя не раскрывает показатель."));
                        }
                    }
                    if(!found)result.Add(new("Disk:"+id,name,"SSD",SensorKind.Temperature,"Temperature",null,"°C",Name,now,SensorStatus.Unsupported,"MSFT_StorageReliabilityCounter недоступен для этого накопителя."));
                }
                catch(Exception e) when(e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
                {result.Add(new("Disk:"+id,name,"SSD",SensorKind.Temperature,"Temperature",null,"°C",Name,now,e is UnauthorizedAccessException?SensorStatus.AccessDenied:SensorStatus.Unavailable,e.Message));}
            }
        }
        catch(Exception e) when(e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {result.Add(new("Disk:storage","Накопители","SSD",SensorKind.Temperature,"Temperature",null,"°C",Name,now,e is UnauthorizedAccessException || e.Message.Contains("доступ",StringComparison.OrdinalIgnoreCase)?SensorStatus.AccessDenied:SensorStatus.Unavailable,"Windows Storage CIM: "+e.Message));}
        return result;
    }
    public void Dispose(){}
}

internal sealed class VendorLibrary : IDisposable
{
    private IntPtr _handle;
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr LoadLibraryEx(string file,IntPtr fileHandle,uint flags);
    public bool Load(string file,params string[] extraPaths)
    {
        foreach(var path in new[]{Path.Combine(Environment.SystemDirectory,file)}.Concat(extraPaths))
            if(Path.IsPathFullyQualified(path) && File.Exists(path) && (_handle=LoadLibraryEx(path,IntPtr.Zero,0x100|0x800))!=IntPtr.Zero)return true;
        return false;
    }
    public T Function<T>(string name) where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_handle,name));
    public bool Has(string name)=>_handle!=IntPtr.Zero && NativeLibrary.TryGetExport(_handle,name,out _);
    public void Dispose(){if(_handle!=IntPtr.Zero){NativeLibrary.Free(_handle);_handle=IntPtr.Zero;}}
}

public sealed class NvmlProvider : ISensorProvider
{
    public string Name=>"NVIDIA NVML";
    public TimeSpan Interval=>TimeSpan.FromSeconds(3);
    private readonly VendorLibrary _lib=new(); private bool _tried,_ready; private string _reason="NVML не установлена с драйвером NVIDIA.";
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Init();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Count(out uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Device(uint index,out IntPtr device);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Text(IntPtr device,[Out]byte[] text,uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int UIntValue(IntPtr device,out uint value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int EnumValue(IntPtr device,uint selector,out uint value);
    [StructLayout(LayoutKind.Sequential)]private struct Util{public uint Gpu,Memory;}
    [StructLayout(LayoutKind.Sequential)]private struct Memory{public ulong Total,Free,Used;}
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Utilization(IntPtr device,out Util value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int MemoryInfo(IntPtr device,out Memory value);
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        if(!_tried)
        {
            _tried=true;
            if(_lib.Load("nvml.dll",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"NVIDIA Corporation","NVSMI","nvml.dll")))
            {var code=_lib.Function<Init>("nvmlInit_v2")();_ready=code==0;_reason="nvmlInit_v2: "+code;}
        }
        var now=DateTimeOffset.UtcNow;
        if(!_ready)return [new("NVML","Источник NVIDIA","GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unavailable,_reason)];
        var result=new List<SensorReading>();
        if(_lib.Function<Count>("nvmlDeviceGetCount_v2")(out var count)!=0)return result;
        for(uint i=0;i<Math.Min(count,16);i++)
        {
            token.ThrowIfCancellationRequested(); if(_lib.Function<Device>("nvmlDeviceGetHandleByIndex_v2")(i,out var dev)!=0)continue;
            string GetText(string fn){var bytes=new byte[128];return _lib.Function<Text>(fn)(dev,bytes,128)==0?System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('\0'):"NVIDIA "+i;}
            var name=GetText("nvmlDeviceGetName");var id=GetText("nvmlDeviceGetUUID");
            void Add(SensorKind kind,string label,double? value,string unit)=>result.Add(new(id,name,"GPU",kind,label,value,unit,Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unsupported));
            Add(SensorKind.Temperature,"GPU",_lib.Function<EnumValue>("nvmlDeviceGetTemperature")(dev,0,out var temp)==0?temp:null,"°C");
            Add(SensorKind.Utilization,"GPU activity",_lib.Function<Utilization>("nvmlDeviceGetUtilizationRates")(dev,out var util)==0?util.Gpu:null,"%");
            if(_lib.Function<MemoryInfo>("nvmlDeviceGetMemoryInfo")(dev,out var mem)==0){Add(SensorKind.MemoryUsed,"VRAM used",mem.Used,"B");Add(SensorKind.MemoryTotal,"VRAM total",mem.Total,"B");}
            if(_lib.Has("nvmlDeviceGetPowerUsage"))Add(SensorKind.Power,"Board power",_lib.Function<UIntValue>("nvmlDeviceGetPowerUsage")(dev,out var power)==0?power/1000d:null,"W");
            if(_lib.Has("nvmlDeviceGetClockInfo"))Add(SensorKind.Clock,"Graphics clock",_lib.Function<EnumValue>("nvmlDeviceGetClockInfo")(dev,0,out var clock)==0?clock:null,"MHz");
            if(_lib.Has("nvmlDeviceGetFanSpeed"))Add(SensorKind.Fan,"Fan",_lib.Function<UIntValue>("nvmlDeviceGetFanSpeed")(dev,out var fan)==0?fan:null,"%");
        }
        return result;
    }
    public void Dispose(){if(_ready && _lib.Has("nvmlShutdown"))_lib.Function<Init>("nvmlShutdown")();_lib.Dispose();}
}

public sealed class IgclProvider : ISensorProvider
{
    public string Name=>"Intel IGCL";
    public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    private readonly VendorLibrary _lib=new();private bool _tried;private IntPtr _api;private string _reason="ControlLib.dll не установлена драйвером Intel.";
    [StructLayout(LayoutKind.Sequential)]private struct InitArgs{public uint Size;public byte Version;public uint AppVersion,Flags,SupportedVersion;public Guid ApplicationUid;}
    [StructLayout(LayoutKind.Sequential)]private struct TemperatureProperties{public uint Size;public byte Version;public int Type;public double Maximum;}
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Init(ref InitArgs args,out IntPtr api);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Close(IntPtr api);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Enumerate(IntPtr device,ref uint count,[Out]IntPtr[]? handles);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Temperature(IntPtr sensor,out double value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Properties(IntPtr sensor,ref TemperatureProperties properties);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int PowerTelemetry(IntPtr device,[In,Out]byte[] data);
    private IntPtr[] EnumerateHandles(string fn,IntPtr parent)
    {
        var function=_lib.Function<Enumerate>(fn);uint count=0;if(function(parent,ref count,null)!=0 || count==0 || count>64)return [];
        var handles=new IntPtr[count];return function(parent,ref count,handles)==0?handles.Take((int)Math.Min(count,(uint)handles.Length)).ToArray():[];
    }
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        if(!_tried)
        {
            _tried=true;
            if(_lib.Load("ControlLib.dll"))
            {
                var args=new InitArgs{Size=(uint)Marshal.SizeOf<InitArgs>(),AppVersion=0x10001,Flags=1};
                var code=_lib.Function<Init>("ctlInit")(ref args,out _api);if(code!=0)_api=IntPtr.Zero;_reason="ctlInit: 0x"+code.ToString("X");
            }
        }
        var now=DateTimeOffset.UtcNow;var result=new List<SensorReading>();
        if(_api==IntPtr.Zero)return [new("IGCL","Intel GPU","GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unavailable,_reason)];
        var devices=EnumerateHandles("ctlEnumerateDevices",_api);
        for(var i=0;i<devices.Length;i++)
        {
            token.ThrowIfCancellationRequested();var sensors=EnumerateHandles("ctlEnumTemperatureSensors",devices[i]);
            // The power telemetry API exposes temperature independently of ctlEnumTemperatureSensors.
            // IGCL C ABI v1: 1024 bytes, GPU temperature item at 104; C bool is one byte.
            if(_lib.Has("ctlPowerTelemetryGet"))
            {
                var data=new byte[1024];BitConverter.GetBytes(data.Length).CopyTo(data,0);data[4]=1;
                var code=_lib.Function<PowerTelemetry>("ctlPowerTelemetryGet")(devices[i],data);
                var value=code==0?IntelTelemetryTemperature.Parse(data.AsSpan(104,24)):null;
                result.Add(new("IGCL:"+i,"Intel GPU "+i,"GPU",SensorKind.Temperature,"GPU telemetry",value,"°C",Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unsupported,value.HasValue?null:$"ctlPowerTelemetryGet: 0x{code:X8}; supported={data[104]}."));
            }
            else if(sensors.Length==0)result.Add(new("IGCL:"+i,"Intel GPU "+i,"GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unsupported,"Драйвер не предоставляет температурные датчики этого GPU."));
            foreach(var sensor in sensors)
            {
                var properties=new TemperatureProperties{Size=(uint)Marshal.SizeOf<TemperatureProperties>()};
                if(_lib.Function<Properties>("ctlTemperatureGetProperties")(sensor,ref properties)!=0)continue;
                var code=_lib.Function<Temperature>("ctlTemperatureGetState")(sensor,out var value);
                var label=properties.Type switch{0=>"Device maximum",1=>"GPU",2=>"VRAM",_=>"Device sensor "+properties.Type};
                result.Add(new("IGCL:"+i,"Intel GPU "+i,"GPU",SensorKind.Temperature,label,code==0?value:null,"°C",Name,now,code==0?SensorStatus.Available:SensorStatus.Unsupported,code==0?null:"IGCL: 0x"+code.ToString("X")));
            }
        }
        if(result.Count==0)result.Add(new("IGCL","Intel GPU","GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unsupported,"IGCL не перечислила поддерживаемые устройства."));
        return result;
    }
    public void Dispose(){if(_api!=IntPtr.Zero)_lib.Function<Close>("ctlClose")(_api);_lib.Dispose();}
}

public sealed class AdlxProvider : ISensorProvider
{
    public string Name=>"AMD ADLX";public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    private readonly VendorLibrary _lib=new();private bool _tried;private IntPtr _system,_services;private string _reason="amdadlx64.dll отсутствует в установленном драйвере.";
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Initialize(ulong version,out IntPtr system);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Terminate();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int GetObject(IntPtr self,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int GetMetrics(IntPtr self,IntPtr gpu,out IntPtr metrics);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int At(IntPtr self,uint index,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate uint Size(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int Release(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int DoubleValue(IntPtr self,out double value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]private delegate int IntValue(IntPtr self,out int value);
    private static T Slot<T>(IntPtr obj,int index) where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj),index*IntPtr.Size));
    private static void Free(IntPtr obj){if(obj!=IntPtr.Zero)Slot<Release>(obj,1)(obj);}
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        if(!_tried)
        {
            _tried=true;
            if(_lib.Load("amdadlx64.dll"))
            {
                // Base interfaces from the documented ADLX C ABI, requesting API 1.0.
                var code=_lib.Function<Initialize>("ADLXInitialize")(1UL<<48,out _system);
                if(code==0 && _system!=IntPtr.Zero)code=Slot<GetObject>(_system,9)(_system,out _services);
                _reason="ADLX initialize/services: "+code;
            }
        }
        var now=DateTimeOffset.UtcNow;var result=new List<SensorReading>();
        if(_services==IntPtr.Zero)return [new("ADLX","Источник AMD","GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unavailable,_reason)];
        if(Slot<GetObject>(_system,1)(_system,out var list)!=0 || list==IntPtr.Zero)return result;
        try
        {
            var count=Math.Min(Slot<Size>(list,3)(list),16u);
            for(uint i=0;i<count;i++)
            {
                token.ThrowIfCancellationRequested();if(Slot<At>(list,11)(list,i,out var gpu)!=0 || gpu==IntPtr.Zero)continue;
                try
                {
                    var name=Slot<GetObject>(gpu,7)(gpu,out var namePtr)==0?Marshal.PtrToStringAnsi(namePtr)??"AMD GPU":"AMD GPU";
                    var id=Slot<GetObject>(gpu,9)(gpu,out var idPtr)==0?Marshal.PtrToStringAnsi(idPtr)??"ADLX:"+i:"ADLX:"+i;
                    if(Slot<GetMetrics>(_services,18)(_services,gpu,out var metrics)!=0 || metrics==IntPtr.Zero)continue;
                    try
                    {
                        void Add(SensorKind kind,string label,double? value,string unit)=>result.Add(new(id,name,"GPU",kind,label,value,unit,Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unsupported));
                        double? D(int slot)=>Slot<DoubleValue>(metrics,slot)(metrics,out var value)==0?value:null;
                        double? I(int slot)=>Slot<IntValue>(metrics,slot)(metrics,out var value)==0?value:null;
                        Add(SensorKind.Temperature,"GPU edge",D(7),"°C");Add(SensorKind.Utilization,"GPU activity",D(4),"%");
                        Add(SensorKind.Clock,"Graphics clock",I(5),"MHz");Add(SensorKind.Power,"GPU power",D(9),"W");Add(SensorKind.Fan,"Fan",I(11),"RPM");
                        Add(SensorKind.MemoryUsed,"VRAM used",I(12)*1048576,"B");
                        Add(SensorKind.MemoryTotal,"VRAM total",Slot<IntValue>(gpu,11)(gpu,out var total)==0?total*1048576d:null,"B");
                    }
                    finally{Free(metrics);}
                }
                finally{Free(gpu);}
            }
        }
        finally{Free(list);}
        return result;
    }
    public void Dispose(){Free(_services);if(_system!=IntPtr.Zero && _lib.Has("ADLXTerminate"))_lib.Function<Terminate>("ADLXTerminate")();_lib.Dispose();}
}

public sealed class GpuPdhProvider : ISensorProvider
{
    public string Name=>"Windows GPU PDH";public TimeSpan Interval=>TimeSpan.FromSeconds(2);
    private IntPtr _query,_activity,_memory;private bool _tried;
    [StructLayout(LayoutKind.Sequential)]private struct Item{public IntPtr Name;public Native.CounterValue Value;}
    [DllImport("pdh.dll",CharSet=CharSet.Unicode)]private static extern uint PdhGetFormattedCounterArray(IntPtr counter,uint format,ref uint size,out uint count,IntPtr buffer);
    private static IEnumerable<(string Name,double Value)> Values(IntPtr counter)
    {
        if(counter==IntPtr.Zero)return [];uint size=0;PdhGetFormattedCounterArray(counter,0x200,ref size,out _,IntPtr.Zero);
        if(size==0 || size>4*1024*1024)return [];
        var buffer=Marshal.AllocHGlobal((int)size);
        try
        {
            if(PdhGetFormattedCounterArray(counter,0x200,ref size,out var count,buffer)!=0 || count>50000)return [];
            var result=new List<(string,double)>();
            for(var i=0;i<count;i++){var item=Marshal.PtrToStructure<Item>(buffer+i*Marshal.SizeOf<Item>());if(item.Value.Status<=1 && double.IsFinite(item.Value.Value))result.Add((Marshal.PtrToStringUni(item.Name)??"",item.Value.Value));}
            return result;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        if(!_tried)
        {
            _tried=true;
            if(Native.PdhOpenQuery(null,UIntPtr.Zero,out _query)==0)
            {Native.PdhAddEnglishCounter(_query,@"\GPU Engine(*)\Utilization Percentage",UIntPtr.Zero,out _activity);Native.PdhAddEnglishCounter(_query,@"\GPU Adapter Memory(*)\Dedicated Usage",UIntPtr.Zero,out _memory);Native.PdhCollectQueryData(_query);}
            return [];
        }
        var now=DateTimeOffset.UtcNow;
        if(_query==IntPtr.Zero || Native.PdhCollectQueryData(_query)!=0)return [new("PDH GPU","GPU","GPU",SensorKind.Utilization,"GPU activity",null,"%",Name,now,SensorStatus.Unavailable,"GPU counters недоступны.")];
        var result=new List<SensorReading>();
        var engines=Values(_activity).Where(x=>x.Name.Contains("_luid_")).GroupBy(x=>x.Name[(x.Name.IndexOf("_luid_",StringComparison.Ordinal)+1)..]);
        var grouped=engines.Select(g=>(Key:g.Key,Load:Math.Clamp(g.Sum(x=>x.Value),0,100))).GroupBy(x=>x.Key.Contains("_eng_")?x.Key[..x.Key.IndexOf("_eng_",StringComparison.Ordinal)]:x.Key);
        foreach(var g in grouped)result.Add(new("PDH:"+g.Key,"GPU "+g.Key,"GPU",SensorKind.Utilization,"Busiest engine",g.Max(x=>x.Load),"%",Name,now,SensorStatus.Available));
        foreach(var m in Values(_memory))result.Add(new("PDH:"+m.Name,"GPU "+m.Name,"GPU",SensorKind.MemoryUsed,"Dedicated memory",m.Value,"B",Name,now,SensorStatus.Available));
        return result;
    }
    public void Dispose(){if(_query!=IntPtr.Zero)Native.PdhCloseQuery(_query);}
}
