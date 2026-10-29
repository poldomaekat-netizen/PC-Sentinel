using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCSentinel.Core;
using PCSentinel.Storage;
using PCSentinel.Collectors;
using Xunit;
namespace PCSentinel.IntegrationTests;
public sealed class MigrationTests
{
    [Fact]public async Task WidgetLayoutAndVisibilitySurviveRestart()
    {
        var root=Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));var store=new LocalStore(root);
        var s=new AppSettings{Widget=new(){Left=-1500,Top=225,MonitorDevice="secondary",Dock="TopRight",Compact=true,Scale=1.35,Topmost=false,Locked=true,ShowGpu=false,VisibleOnStartup=true}};
        await store.SaveSettingsAsync(s);var restored=new LocalStore(root).LoadSettings().Widget;
        Assert.Equal(-1500,restored.Left);Assert.Equal(225,restored.Top);Assert.Equal(1.35,restored.Scale);Assert.Equal("secondary",restored.MonitorDevice);Assert.Equal("TopRight",restored.Dock);Assert.True(restored.Compact);Assert.True(restored.Locked);Assert.True(restored.VisibleOnStartup);Assert.False(restored.Topmost);Assert.False(restored.ShowGpu);
    }
    [Fact]public async Task V1DatabaseIsBackedUpAndHistorySurvives()
    {
        var root=Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var store=new LocalStore(root); // Initializes the Windows SQLite provider.
        using(var c=new SqliteConnection("Data Source="+store.DatabasePath))
        {c.Open();using var cmd=c.CreateCommand();cmd.CommandText="CREATE TABLE SchemaVersion(version INTEGER); INSERT INTO SchemaVersion VALUES(1);CREATE TABLE MachineSnapshot(timestampUtc TEXT PRIMARY KEY,cpuPct REAL,ramPct REAL,diskActivePct REAL,netDownBps REAL,netUpBps REAL,detailsJson TEXT);INSERT INTO MachineSnapshot VALUES('2026-10-25T00:00:00.0000000+00:00',42,55,12,100,200,'{}');";cmd.ExecuteNonQuery();}
        await store.InitializeAsync();await store.InitializeAsync();
        Assert.Single(Directory.GetFiles(Path.Combine(root,"backups"),"*.db"));
        using(var c=new SqliteConnection("Data Source="+store.DatabasePath))
        {c.Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT cpuPct FROM MachineSnapshot";Assert.Equal(42d,Convert.ToDouble(cmd.ExecuteScalar()));cmd.CommandText="SELECT version FROM SchemaVersion";Assert.Equal(3,Convert.ToInt32(cmd.ExecuteScalar()));}
        var backup=Directory.GetFiles(Path.Combine(root,"backups"),"*.db")[0];using var b=new SqliteConnection("Data Source="+backup);b.Open();using var query=b.CreateCommand();query.CommandText="SELECT version FROM SchemaVersion";Assert.Equal(1,Convert.ToInt32(query.ExecuteScalar()));
    }
    [Fact]public void SettingsPreserveLegacyAndThresholds()
    {
        var root=Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var original="{\"RefreshSeconds\":3,\"ApprovedIps\":\"203.0.113.0/24\",\"WarningThreshold\":62,\"CriticalThreshold\":88,\"PreferredAdapterId\":\"old\"}";
        File.WriteAllText(Path.Combine(root,"settings.json"),original);var s=new LocalStore(root).LoadSettings();
        Assert.Equal(3,s.ConfigVersion);Assert.Equal("203.0.113.0/24",s.LegacyApprovedIps);Assert.Equal(62,s.WarningThreshold);Assert.Equal(3,s.RefreshSeconds);Assert.Null(s.VpnProfile);Assert.True(s.AutoDetectVpn);
        Assert.Equal(original,File.ReadAllText(Path.Combine(root,"settings.json.v0.1.backup")));Assert.Equal(original,File.ReadAllText(Path.Combine(root,"settings.json")));
    }
    [Fact]public async Task MissingSensorsStoreNullAndPreserveSource()
    {
        var root=Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));var store=new LocalStore(root);await store.InitializeAsync();
        var r=new SensorReading("cpu","CPU","CPU",SensorKind.Temperature,"Package",null,"°C","safe test",DateTimeOffset.UtcNow,SensorStatus.Unsupported,"No source");
        await store.SaveSensorsAsync([r]);await store.SaveSensorsAsync([r]);var path=Path.Combine(root,"export.json");await store.ExportJsonAsync(path);using var json=JsonDocument.Parse(File.ReadAllText(path));var rows=json.RootElement.GetProperty("SensorSample");Assert.Single(rows.EnumerateArray());Assert.Equal(JsonValueKind.Null,rows[0].GetProperty("value").ValueKind);Assert.Equal("safe test",rows[0].GetProperty("source").GetString());
    }
    [Fact]public void SensorHubUsesProviderAndNeverInventsTemperature()
    {using var hub=new SensorHub(new FakeProvider());var a=hub.Poll(CancellationToken.None);var b=hub.Poll(CancellationToken.None);Assert.Null(a[0].Value);Assert.Equal(a[0].TimestampUtc,b[0].TimestampUtc);}
    private sealed class FakeProvider:ISensorProvider
    {public string Name=>"fake";public TimeSpan Interval=>TimeSpan.FromHours(1);public IReadOnlyList<SensorReading> Read(CancellationToken ct)=>[new("test","test","CPU",SensorKind.Temperature,"CPU",double.NaN,"°C",Name,DateTimeOffset.UtcNow,SensorStatus.Available)];public void Dispose(){}}
}
