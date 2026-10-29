using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using PCSentinel.Core;

namespace PCSentinel.Collectors;

internal static class Native
{
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetSystemTimes(out ulong idle, out ulong kernel, out ulong user);
    [StructLayout(LayoutKind.Sequential)] internal struct Memory
    {
        public uint Length, Load;
        public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual;
    }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GlobalMemoryStatusEx(ref Memory memory);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] internal static extern uint PdhOpenQuery(string? source, UIntPtr user, out IntPtr query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] internal static extern uint PdhAddEnglishCounter(IntPtr query, string path, UIntPtr user, out IntPtr counter);
    [DllImport("pdh.dll")] internal static extern uint PdhCollectQueryData(IntPtr query);
    [StructLayout(LayoutKind.Explicit)] internal struct CounterValue
    {
        [FieldOffset(0)] public uint Status;
        [FieldOffset(8)] public double Value;
    }
    [DllImport("pdh.dll")] internal static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint type, out CounterValue value);
    [DllImport("pdh.dll")] internal static extern uint PdhCloseQuery(IntPtr query);
}

public sealed class NativeMetrics : IDisposable
{
    private ulong _idle, _kernel, _user;
    private bool _primed;
    private readonly IntPtr _query;
    private readonly Dictionary<string, IntPtr> _counters = [];
    private readonly Dictionary<string, (long Down, long Up)> _network = [];
    private long _lastTicks;
    public NativeMetrics()
    {
        if (Native.PdhOpenQuery(null, UIntPtr.Zero, out _query) == 0)
        {
            Add("idle", @"\PhysicalDisk(_Total)\% Idle Time");
            Add("read", @"\PhysicalDisk(_Total)\Disk Read Bytes/sec");
            Add("write", @"\PhysicalDisk(_Total)\Disk Write Bytes/sec");
            Add("latency", @"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer");
            Add("queue", @"\PhysicalDisk(_Total)\Current Disk Queue Length");
            Native.PdhCollectQueryData(_query);
        }
    }
    private void Add(string key, string path)
    {
        if (Native.PdhAddEnglishCounter(_query, path, UIntPtr.Zero, out var counter) == 0) _counters[key] = counter;
    }
    private double? Read(string key)
    {
        if (!_counters.TryGetValue(key, out var counter)) return null;
        return Native.PdhGetFormattedCounterValue(counter, 0x00000200, out _, out var value) == 0 &&
            value.Status <= 1 && double.IsFinite(value.Value) ? Math.Max(0, value.Value) : null;
    }
    public MachineSample Collect()
    {
        var nowTicks = Stopwatch.GetTimestamp();
        var seconds = _lastTicks == 0 ? 0 : (nowTicks - _lastTicks) / (double)Stopwatch.Frequency;
        _lastTicks = nowTicks;
        double? cpu = null;
        if (Native.GetSystemTimes(out var idle, out var kernel, out var user))
        {
            if (_primed) cpu = MetricsMath.Cpu(_idle, _kernel, _user, idle, kernel, user);
            (_idle, _kernel, _user, _primed) = (idle, kernel, user, true);
        }
        var mem = new Native.Memory { Length = (uint)Marshal.SizeOf<Native.Memory>() };
        if (!Native.GlobalMemoryStatusEx(ref mem)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var collected = _query != IntPtr.Zero && Native.PdhCollectQueryData(_query) == 0;
        var diskIdle = collected ? Read("idle") : null;
        double? fill = null;
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory)!; var drive = new DriveInfo(root);
            fill = 100d * (drive.TotalSize - drive.TotalFreeSpace) / drive.TotalSize;
        }
        catch (IOException) { }
        long down = 0, up = 0; var names = new List<string>(); var seen = new HashSet<string>(); var usable = false;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            seen.Add(nic.Id);
            try
            {
                if (nic.GetIPProperties().UnicastAddresses.Count == 0) continue;
                var stats = nic.GetIPStatistics();
                if (_network.TryGetValue(nic.Id, out var old) && stats.BytesReceived >= old.Down && stats.BytesSent >= old.Up)
                { down += stats.BytesReceived - old.Down; up += stats.BytesSent - old.Up; usable = true; }
                _network[nic.Id] = (stats.BytesReceived, stats.BytesSent); names.Add(nic.Name);
            }
            catch (NetworkInformationException) { }
        }
        foreach (var id in _network.Keys.Where(k => !seen.Contains(k)).ToArray()) _network.Remove(id);
        return new(DateTimeOffset.UtcNow, cpu, 100d * (mem.TotalPhys - mem.AvailPhys) / mem.TotalPhys,
            mem.TotalPhys - mem.AvailPhys, mem.TotalPhys, mem.TotalPageFile - mem.AvailPageFile, mem.TotalPageFile,
            diskIdle.HasValue ? Math.Clamp(100 - diskIdle.Value, 0, 100) : null,
            collected ? Read("read") : null, collected ? Read("write") : null,
            collected ? Read("latency") * 1000 : null, collected ? Read("queue") : null, fill,
            seconds > 0 && usable ? down / seconds : null, seconds > 0 && usable ? up / seconds : null,
            string.Join(", ", names));
    }
    public void Dispose() { if (_query != IntPtr.Zero) Native.PdhCloseQuery(_query); }
}

public sealed class ProcessCollector
{
    private Dictionary<(int, long), double> _previous = [];
    private readonly Dictionary<(int,long),string?> _paths=[];
    private long _last;
    [StructLayout(LayoutKind.Sequential)]private struct IoCounters{public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes;}
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetProcessIoCounters(IntPtr handle,out IoCounters counters);
    private Dictionary<(int,long),(ulong Read,ulong Write)> _io=[];
    public IReadOnlyList<ProcessSample> Collect()
    {
        var timestamp = DateTimeOffset.UtcNow; var tick = Stopwatch.GetTimestamp();
        var elapsed = _last == 0 ? 0 : (tick - _last) * 1000d / Stopwatch.Frequency;
        _last = tick;
        var current = new Dictionary<(int, long), double>(); var nextIo=new Dictionary<(int,long),(ulong Read,ulong Write)>(); var result = new List<ProcessSample>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var start = process.StartTime.ToUniversalTime(); var key = (process.Id, start.Ticks);
                    var cpuTime = process.TotalProcessorTime.TotalMilliseconds; current[key] = cpuTime;
                    var cpu = _previous.TryGetValue(key, out var previous) ? MetricsMath.ProcessCpu(cpuTime - previous, elapsed, Environment.ProcessorCount) : null;
                    if(!_paths.TryGetValue(key,out var path))
                    {
                        try { path=process.MainModule?.FileName; } catch(Exception e) when(e is System.ComponentModel.Win32Exception or InvalidOperationException){}
                        _paths[key]=path;
                    }
                    double? read=null,write=null;long? privateBytes=null;
                    try{privateBytes=process.PrivateMemorySize64;}catch(System.ComponentModel.Win32Exception){}
                    try
                    {
                        if(GetProcessIoCounters(process.Handle,out var counters))
                        {
                            nextIo[key]=(counters.ReadBytes,counters.WriteBytes);
                            if(_io.TryGetValue(key,out var old) && elapsed>0 && counters.ReadBytes>=old.Read && counters.WriteBytes>=old.Write)
                            {read=(counters.ReadBytes-old.Read)*1000d/elapsed;write=(counters.WriteBytes-old.Write)*1000d/elapsed;}
                        }
                    }catch(Exception e) when(e is System.ComponentModel.Win32Exception or InvalidOperationException){}
                    result.Add(new(timestamp, process.Id, new DateTimeOffset(start), process.ProcessName, path, cpu, process.WorkingSet64,privateBytes,read,write,
                        "GetProcessTimes / WorkingSet / PrivateBytes; "+(read.HasValue?"GetProcessIoCounters (all I/O, не только диск)":"I/O недоступен / первая проба")));
                }
                catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
        foreach(var key in _paths.Keys.Where(k=>!current.ContainsKey(k)).ToArray())_paths.Remove(key);
        _previous = current;_io=nextIo; return result;
    }
}
