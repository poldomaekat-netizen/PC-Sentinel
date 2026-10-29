using System.Management;
using PCSentinel.Core;

namespace PCSentinel.Collectors;

public static class HardwareInventory
{
    public static IReadOnlyList<HardwareItem> Read(CancellationToken token)
    {
        var result = new List<HardwareItem>();
        var queries = new (string Type, string Class, string Name, string[] Fields)[]
        {
            ("CPU", "Win32_Processor", "Name", ["NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed"]),
            ("RAM", "Win32_PhysicalMemory", "DeviceLocator", ["Manufacturer", "Capacity", "SMBIOSMemoryType", "Speed", "ConfiguredClockSpeed"]),
            ("GPU", "Win32_VideoController", "Name", ["DriverVersion", "VideoProcessor"]),
            ("Диск", "Win32_DiskDrive", "Model", ["InterfaceType", "MediaType", "Size"]),
            ("Том", "Win32_LogicalDisk", "DeviceID", ["VolumeName", "FileSystem", "Size", "FreeSpace"]),
            ("ОС", "Win32_OperatingSystem", "Caption", ["Version", "BuildNumber", "OSArchitecture"])
        };
        foreach (var q in queries)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var options = new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(3), ReturnImmediately = false };
                using var search = new ManagementObjectSearcher("root\\CIMV2", $"SELECT {q.Name},{string.Join(',', q.Fields)} FROM {q.Class}", options);
                using var items = search.Get();
                foreach (ManagementObject item in items)
                using (item)
                    result.Add(new(q.Type, item[q.Name]?.ToString()?.Trim() ?? "Нет данных",
                        string.Join("  ·  ", q.Fields.Select(f => $"{f}: {item[f] ?? "нет данных"}"))));
            }
            catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            { result.Add(new(q.Type, "Нет данных", $"{e.GetType().Name}: {e.Message}")); }
        }
        return result;
    }
}
