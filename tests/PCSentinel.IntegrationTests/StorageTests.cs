using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCSentinel.Collectors;
using PCSentinel.Core;
using PCSentinel.Storage;
using Xunit;

namespace PCSentinel.IntegrationTests;

public sealed class StorageTests
{
    [Fact]public async Task HistoryExportRedactsUncInsideStoredJsonMetadata()
    {
        var root=Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));var store=new LocalStore(root);await store.InitializeAsync();
        await store.SaveInventoryAsync([new("Disk","Disk",@"\\server\private\inventory.txt")]);
        var output=Path.Combine(root,"history.json");await store.ExportJsonAsync(output);using var json=JsonDocument.Parse(await File.ReadAllTextAsync(output));
        using var metadata=JsonDocument.Parse(json.RootElement.GetProperty("HardwareInventory")[0].GetProperty("detailsJson").GetString()!);
        Assert.Equal("[путь скрыт]",metadata.RootElement.GetProperty("Details").GetString());
    }
    private static MachineSample Sample(DateTimeOffset at) => new(at, 45, 63, 1000, 2000, 3000, 4000, 70, 123, 456, 2, 1, 66, 1000, 2000, "adapter");
    [Fact] public async Task StorageRoundtripAndParameterizedProcessName()
    {
        var root = Path.Combine(Path.GetTempPath(), "PCSentinel.Tests", Guid.NewGuid().ToString("N")); var store = new LocalStore(root);
        await store.InitializeAsync(); await store.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        await store.SaveSampleAsync(Sample(now), [new(now,123,now,"name'); DROP TABLE ProcessSample;--",null,10,2048)]);
        await store.SaveNetworkAsync(new(now,"203.0.113.1",null,VpnState.Unknown,"route","reason"));
        await store.SaveSettingsAsync(new() { RefreshSeconds = 3 }); Assert.Equal(3, store.LoadSettings().RefreshSeconds);
        var export = Path.Combine(root,"export.json"); await store.ExportJsonAsync(export);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(export));
        Assert.Single(json.RootElement.GetProperty("MachineSnapshot").EnumerateArray());
        Assert.Contains("DROP TABLE",json.RootElement.GetProperty("ProcessSample")[0].GetProperty("name").GetString());
    }
    [Fact] public async Task RetentionAggregatesBeforeRemovingRawData()
    {
        var root = Path.Combine(Path.GetTempPath(), "PCSentinel.Tests", Guid.NewGuid().ToString("N")); var store = new LocalStore(root);
        await store.InitializeAsync(); await store.SaveSampleAsync(Sample(DateTimeOffset.UtcNow.AddDays(-8)), null);
        await store.MaintainAsync(new()); await store.MaintainAsync(new());
        var export = Path.Combine(root,"retention.json"); await store.ExportJsonAsync(export);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(export));
        Assert.Empty(json.RootElement.GetProperty("MachineSnapshot").EnumerateArray());
        Assert.Single(json.RootElement.GetProperty("MinuteAggregate").EnumerateArray());
        Assert.Equal(45, json.RootElement.GetProperty("MinuteAggregate")[0].GetProperty("cpuMax").GetDouble());
    }
    [Fact] public async Task NativeMetricsProduceBoundedCpuAndRealMemory()
    {
        using var collector = new NativeMetrics(); collector.Collect(); await Task.Delay(1100); var sample = collector.Collect();
        Assert.NotNull(sample.CpuPct); Assert.InRange(sample.CpuPct.Value, 0, 100);
        Assert.True(sample.RamTotalBytes > 0); Assert.InRange(sample.RamPct, 0, 100);
        if (sample.DiskActivePct.HasValue) Assert.InRange(sample.DiskActivePct.Value, 0, 100);
    }
}
