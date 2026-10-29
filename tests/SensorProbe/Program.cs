using PCSentinel.Collectors;
using System.Text.Json;
if(args.Length>0 && args[0]=="--audit-service")
{
    var service=SensorServiceControl.GetRunning();
    var report=new Dictionary<string,object?>{{"Elevated",TemperatureHelper.IsElevated},{"Service",service},{"ProtectedTree",ProtectedInstall.CheckTree(ProtectedInstall.Root,out var protectionReason)},{"ProtectionReason",protectionReason}};
    if(service!=null)
    {
        using(var write=AuditNative.CreateFile(@"\\.\pipe\"+SensorServiceControl.PipeName,0x40000000,0,IntPtr.Zero,3,0x40000000,IntPtr.Zero))
        {var error=System.Runtime.InteropServices.Marshal.GetLastWin32Error();report["PipeWriteDenied"]=write.IsInvalid && error==5;report["PipeWriteError"]=error;}
        var probe=Path.Combine(ProtectedInstall.Root,"Service","write-test-"+Guid.NewGuid().ToString("N")+".tmp");
        try{using(var file=File.Create(probe)){}File.Delete(probe);report["InstallWriteDenied"]=false;}
        catch(UnauthorizedAccessException){report["InstallWriteDenied"]=true;}
        using var reader=TemperatureHelper.CreateReader(SensorServiceControl.PipeName);using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await reader.ConnectAsync(timeout.Token);report["ServerPidVerified"]=TemperatureHelper.IsExpectedPeer(reader.SafePipeHandle,service.Pid,false);
        var header=new byte[4];await reader.ReadExactlyAsync(header,timeout.Token);var length=BitConverter.ToInt32(header);if(length is <=0 or >65536)throw new InvalidDataException();
        var bytes=new byte[length];await reader.ReadExactlyAsync(bytes,timeout.Token);report["Readings"]=JsonSerializer.Deserialize<PCSentinel.Core.SensorReading[]>(bytes);
    }
    var json=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});Console.WriteLine(json);if(args.Length==2)File.WriteAllText(args[1],json);return;
}
if(args.Length==3 && args[0]=="--extract-msr")
{
    using var stream=File.OpenRead(args[1]);using var pe=new System.Reflection.PortableExecutable.PEReader(stream);
    var metadata=System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
    foreach(var handle in metadata.ManifestResources)
    {
        var resource=metadata.GetManifestResource(handle);var name=metadata.GetString(resource.Name);
        if(!name.EndsWith(".PawnIo.IntelMSR.bin",StringComparison.Ordinal))continue;
        var data=pe.GetSectionData(pe.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress+(int)resource.Offset).GetContent();
        var length=BitConverter.ToInt32(data.AsSpan()[..4]);File.WriteAllBytes(args[2],data.AsSpan().Slice(4,length).ToArray());Console.WriteLine(name+" "+length);return;
    }
    throw new InvalidDataException("IntelMSR module missing");
}
using var gpu=new WindowsGpuTemperatureProvider();using var disk=new DirectStorageTemperatureProvider();
Console.WriteLine(JsonSerializer.Serialize(gpu.Read(CancellationToken.None).Concat(disk.Read(CancellationToken.None)),new JsonSerializerOptions{WriteIndented=true}));
using var presentMon=new PresentMonSensorProvider();Console.WriteLine(JsonSerializer.Serialize(presentMon.Read(CancellationToken.None),new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(string.Join("\n",presentMon.Capabilities));
using var intel=new IgclProvider();Console.WriteLine(JsonSerializer.Serialize(intel.Read(CancellationToken.None),new JsonSerializerOptions{WriteIndented=true}));
using var pawn=new PawnIoTemperatureProvider();Console.WriteLine(JsonSerializer.Serialize(pawn.Read(CancellationToken.None),new JsonSerializerOptions{WriteIndented=true}));
internal static class AuditNative
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)]
    internal static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
}
