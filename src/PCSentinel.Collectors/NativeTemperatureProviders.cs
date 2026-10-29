using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PCSentinel.Core;
namespace PCSentinel.Collectors;

public sealed class WindowsGpuTemperatureProvider:ISensorProvider
{
    public string Name=>"Windows WDDM temperature";
    public TimeSpan Interval=>TimeSpan.FromSeconds(4);
    [StructLayout(LayoutKind.Sequential)]private struct EnumAdapters{public uint Count;public IntPtr Adapters;}
    [StructLayout(LayoutKind.Sequential)]private struct AdapterInfo{public uint Handle,LuidLow;public int LuidHigh;public uint Sources;public int Precise;}
    [StructLayout(LayoutKind.Sequential)]private struct Query{public uint Handle,Type;public IntPtr Data;public uint Size;}
    [StructLayout(LayoutKind.Sequential)]private struct PerfData{public uint PhysicalIndex;public ulong MemoryFrequency,MaxMemoryFrequency,MaxMemoryFrequencyOC,MemoryBandwidth,PcieBandwidth;public uint FanRpm,Power,Temperature;public byte PowerStateOverride;}
    [DllImport("gdi32.dll")]private static extern int D3DKMTEnumAdapters2(ref EnumAdapters adapters);
    [DllImport("gdi32.dll")]private static extern int D3DKMTQueryAdapterInfo(ref Query query);
    [DllImport("gdi32.dll")]private static extern int D3DKMTCloseAdapter(ref uint handle);
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        var now=DateTimeOffset.UtcNow;var result=new List<SensorReading>();var adapters=Marshal.AllocHGlobal(20*32);var data=Marshal.AllocHGlobal(Marshal.SizeOf<PerfData>());
        var opened=new List<AdapterInfo>();
        try
        {
            var enumeration=new EnumAdapters{Count=32,Adapters=adapters};var status=D3DKMTEnumAdapters2(ref enumeration);
            if(status!=0)return [Missing("WDDM","GPU",now,$"EnumAdapters2: 0x{status:X8}")];
            for(var n=0;n<Math.Min(enumeration.Count,32);n++)opened.Add(Marshal.PtrToStructure<AdapterInfo>(adapters+n*20));
            foreach(var adapter in opened)
            {
                    token.ThrowIfCancellationRequested();Marshal.StructureToPtr(new PerfData(),data,false);
                    var query=new Query{Handle=adapter.Handle,Type=62,Data=data,Size=(uint)Marshal.SizeOf<PerfData>()};status=D3DKMTQueryAdapterInfo(ref query);
                    var perf=Marshal.PtrToStructure<PerfData>(data);var id=$"WDDM:{adapter.LuidHigh:X8}:{adapter.LuidLow:X8}";
                    var value=status==0 && perf.Temperature is >0 and <=1500?perf.Temperature/10d:(double?)null;
                    result.Add(new(id,"GPU "+id,"GPU",SensorKind.Temperature,"GPU",value,"°C",Name,now,value.HasValue?SensorStatus.Available:SensorStatus.Unsupported,value.HasValue?null:$"Драйвер не выдал температуру: NTSTATUS 0x{status:X8}, raw={perf.Temperature}."));
            }
        }
        finally{foreach(var adapter in opened){var handle=adapter.Handle;if(handle!=0)D3DKMTCloseAdapter(ref handle);}Marshal.FreeHGlobal(data);Marshal.FreeHGlobal(adapters);}
        return result;
    }
    private SensorReading Missing(string id,string hardware,DateTimeOffset now,string reason)=>new(id,hardware,"GPU",SensorKind.Temperature,"GPU",null,"°C",Name,now,SensorStatus.Unavailable,reason);
    public void Dispose(){}
}

public sealed class DirectStorageTemperatureProvider:ISensorProvider
{
    public string Name=>"Windows Storage IOCTL";
    public TimeSpan Interval=>TimeSpan.FromSeconds(15);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,int inputLength,byte[] output,int outputLength,out int bytes,IntPtr overlapped);
    public IReadOnlyList<SensorReading> Read(CancellationToken token)
    {
        var result=new List<SensorReading>();var now=DateTimeOffset.UtcNow;
        // Opening with access=0 permits only metadata queries; no raw reads or writes.
        for(var index=0;index<16;index++)
        {
            token.ThrowIfCancellationRequested();using var handle=CreateFile(@"\\.\PhysicalDrive"+index,0,3,IntPtr.Zero,3,0,IntPtr.Zero);
            if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();if(error==2 || error==3)continue;result.Add(Missing(index,now,error==5?SensorStatus.AccessDenied:SensorStatus.Unavailable,"CreateFile(metadata): Win32 "+error));continue;}
            var model=Model(handle,index);
            var input=new byte[12];BitConverter.GetBytes(52).CopyTo(input,0);var output=new byte[4096];
            if(!DeviceIoControl(handle,0x2D1400,input,input.Length,output,output.Length,out var count,IntPtr.Zero)){result.Add(Missing(index,now,SensorStatus.Unavailable,"StorageDeviceTemperatureProperty: Win32 "+Marshal.GetLastWin32Error()));continue;}
            var values=Parse(output.AsSpan(0,Math.Clamp(count,0,output.Length)));
            if(values.Count==0)result.Add(Missing(index,now,SensorStatus.Unsupported,"Драйвер не выдал допустимые температуры накопителя."));
            foreach(var item in values)result.Add(new("PhysicalDrive:"+index,model,"SSD",SensorKind.Temperature,"Sensor "+item.Index,item.Celsius,"°C",Name,now,SensorStatus.Available));
        }
        return result;
    }
    private static string Model(SafeFileHandle handle,int index)
    {
        var query=new byte[12];var data=new byte[4096];
        if(DeviceIoControl(handle,0x2D1400,query,query.Length,data,data.Length,out var length,IntPtr.Zero) && length>=36 && length<=data.Length)
        {
            var offset=BitConverter.ToUInt32(data,16);
            if(offset>=36 && offset<length)
            {
                var end=Array.IndexOf(data,(byte)0,(int)offset,length-(int)offset);
                if(end>(int)offset){var name=System.Text.Encoding.ASCII.GetString(data,(int)offset,end-(int)offset).Trim();if(name.Length>0)return name;}
            }
        }
        return "PhysicalDrive"+index;
    }
    public static IReadOnlyList<(int Index,double Celsius)> Parse(ReadOnlySpan<byte> data)
    {
        var result=new List<(int,double)>();if(data.Length<24)return result;
        var size=BitConverter.ToUInt32(data[4..]);if(size>data.Length || size<24)return result;
        var count=BitConverter.ToUInt16(data[12..]);if(count>64 || 24L+count*16L>size)return result;
        for(var n=0;n<count;n++){var at=24+n*16;var index=BitConverter.ToUInt16(data[at..]);var temp=BitConverter.ToInt16(data[(at+2)..]);if(temp is >0 and <=150)result.Add((index,temp));}
        return result;
    }
    private SensorReading Missing(int index,DateTimeOffset now,SensorStatus status,string reason)=>new("PhysicalDrive:"+index,"PhysicalDrive"+index,"SSD",SensorKind.Temperature,"Temperature",null,"°C",Name,now,status,reason);
    public void Dispose(){}
}
