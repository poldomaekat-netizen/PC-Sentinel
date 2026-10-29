using System.Runtime.InteropServices;
using PCSentinel.Core;
namespace PCSentinel.Collectors;
/// <summary>Read-only client of an already running Intel PresentMon service. Does not start/install/configure it.</summary>
public sealed class PresentMonSensorProvider:ISensorProvider
{
    public string Name=>"Intel PresentMon service";
    public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    private readonly VendorLibrary _library=new();private IntPtr _session;private bool _loaded;private DateTimeOffset _retry;private string _reason="PresentMon service не найден";
    private readonly List<MetricQuery> _queries=[];
    public IReadOnlyList<string> Capabilities=>_capabilities;private readonly List<string> _capabilities=[];
    private sealed record MetricQuery(IntPtr Handle,QueryElement Element,string Device,string Name,string Type,int DataType);
    [StructLayout(LayoutKind.Sequential)]private struct QueryElement{public int Metric,Stat;public uint DeviceId,ArrayIndex;public ulong Offset,Size;}
    [StructLayout(LayoutKind.Sequential)]private struct ArrayNative{public IntPtr Data;public nuint Count;}
    [StructLayout(LayoutKind.Sequential)]private struct MetricNative{public int Id,Type,Unit,PreferredUnit;public IntPtr TypeInfo,Stats,Devices;}
    [StructLayout(LayoutKind.Sequential)]private struct DeviceNative{public uint Id;public int Type,Vendor;public IntPtr Name;}
    [StructLayout(LayoutKind.Sequential)]private struct DeviceMetric{public uint Id;public int Availability;public uint ArraySize;}
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Open(out IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int GetRoot(IntPtr session,out IntPtr root);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Free(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Register(IntPtr session,out IntPtr query,[In,Out]QueryElement[] elements,ulong count,double windowMs,double offsetMs);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate int Poll(IntPtr query,uint processId,[Out]byte[] blob,ref uint swapChains);
    private static IEnumerable<IntPtr> Elements(IntPtr array)
    {if(array==IntPtr.Zero)yield break;var a=Marshal.PtrToStructure<ArrayNative>(array);if(a.Count>1024 || a.Data==IntPtr.Zero)yield break;for(var i=0;i<(int)a.Count;i++)yield return Marshal.ReadIntPtr(a.Data,i*IntPtr.Size);}
    private static string Text(IntPtr value)=>value==IntPtr.Zero?"":Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(value))??"";
    private void Initialize()
    {
        if(!_loaded)
        {
            _loaded=_library.Load("PresentMonAPI2.dll",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Intel","PresentMonSharedService","PresentMonAPI2.dll"),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Intel","PresentMon","PresentMonAPI2.dll"));
            if(!_loaded)return;
        }
        var status=_library.Function<Open>("pmOpenSession")(out _session);if(status!=0){_session=IntPtr.Zero;_reason="pmOpenSession: "+status;return;}
        status=_library.Function<GetRoot>("pmGetIntrospectionRoot")(_session,out var root);if(status!=0 || root==IntPtr.Zero){_reason="pmGetIntrospectionRoot: "+status;ResetSession();return;}
        try
        {
            var devices=Elements(Marshal.ReadIntPtr(root,16)).Select(p=>Marshal.PtrToStructure<DeviceNative>(p)).ToDictionary(d=>d.Id,d=>Text(d.Name));
            foreach(var pointer in Elements(Marshal.ReadIntPtr(root)))
            {
                var metric=Marshal.PtrToStructure<MetricNative>(pointer);
                // Numeric metric IDs are from the official PresentMon v2.4.1 SDK (API 3.2).
                if(metric.Id is not (30 or 59))continue;
                if(metric.TypeInfo==IntPtr.Zero)continue;
                var type=metric.Id==59?"CPU":"GPU";var dataType=Marshal.ReadInt32(metric.TypeInfo);var stats=Elements(metric.Stats).Select(p=>Marshal.ReadInt32(p)).ToArray();
                foreach(var devicePointer in Elements(metric.Devices))
                {
                    var device=Marshal.PtrToStructure<DeviceMetric>(devicePointer);_capabilities.Add($"{type}: device {device.Id}, {devices.GetValueOrDefault(device.Id)}, availability={device.Availability}, type={dataType}, stats={string.Join(',',stats)}");
                    if(device.Availability!=0 || device.ArraySize==0 || stats.Length==0 || dataType!=0 || metric.Unit!=20)continue;
                    var stat=stats.Contains(12)?12:stats.Contains(1)?1:stats[0];
                    var element=new QueryElement{Metric=metric.Id,Stat=stat,DeviceId=device.Id};var elements=new[]{element};status=_library.Function<Register>("pmRegisterDynamicQuery")(_session,out var query,elements,1,1000,0);
                    if(status==0 && query!=IntPtr.Zero && elements[0].Size==8 && elements[0].Offset<=4088)_queries.Add(new(query,elements[0],devices.GetValueOrDefault(device.Id)??type,type+" temperature",type,dataType));
                    else{if(query!=IntPtr.Zero)_library.Function<Free>("pmFreeDynamicQuery")(query);_capabilities.Add($"register {type}: {status}");}
                }
            }
            _reason="Сервис не объявил доступные температурные метрики. "+string.Join("; ",_capabilities);
        }
        finally{_library.Function<Free>("pmFreeIntrospectionRoot")(root);}
    }
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        var now=DateTimeOffset.UtcNow;if((_session==IntPtr.Zero || _queries.Count==0) && now>=_retry){_retry=now.AddSeconds(60);ResetSession();_capabilities.Clear();try{Initialize();}catch{ResetSession();throw;}}
        var result=new List<SensorReading>();
        foreach(var query in _queries)
        {
            token.ThrowIfCancellationRequested();var bytes=new byte[4096];Array.Fill(bytes,(byte)0xFF);uint count=1;
            var status=_library.Function<Poll>("pmPollDynamicQuery")(query.Handle,0,bytes,ref count);
            double? value=status==0 && count>0 && query.Element.Size==8?BitConverter.ToDouble(bytes,(int)query.Element.Offset):null;
            if(value is <=0 or >150 || value.HasValue && !double.IsFinite(value.Value))value=null;
            result.Add(new("PresentMon:"+query.Type,query.Device,query.Type,SensorKind.Temperature,query.Name,value,"°C",Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unavailable,value.HasValue?null:$"pmPollDynamicQuery: {status}, count={count}"));
        }
        foreach(var type in new[]{"CPU","GPU"})if(!result.Any(r=>r.DeviceType==type))result.Add(new("PresentMon:"+type,type,type,SensorKind.Temperature,type+" temperature",null,"°C",Name,now,SensorStatus.Unavailable,_reason));
        return result;
    }
    private void ResetSession(){foreach(var q in _queries)_library.Function<Free>("pmFreeDynamicQuery")(q.Handle);_queries.Clear();if(_session!=IntPtr.Zero)_library.Function<Free>("pmCloseSession")(_session);_session=IntPtr.Zero;}
    public void Dispose(){ResetSession();_library.Dispose();}
}
