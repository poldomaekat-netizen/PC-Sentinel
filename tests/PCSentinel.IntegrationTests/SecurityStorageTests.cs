using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCSentinel.Core;
using PCSentinel.Collectors;
using PCSentinel.Storage;
using Xunit;
namespace PCSentinel.IntegrationTests;
public sealed class SecurityStorageTests
{
    private static string Root()=>Path.Combine(Path.GetTempPath(),"PCSentinel.Tests",Guid.NewGuid().ToString("N"));
    [Fact]public async Task UpgradeV2PreservesHistorySettingsAndOnlineBackup()
    {
        var root=Root();var store=new LocalStore(root);await store.InitializeAsync();
        var now=DateTimeOffset.UtcNow;await store.SaveSampleAsync(new(now,42,70,100,200,100,200,1,2,3,4,5,6,7,8,"test"),null);
        var config=new AppSettings{ConfigVersion=2,EnablePublicIp=false,BackgroundTransparency=42,Widget=new(){Topmost=true,Left=-1234},ApprovedIps="203.0.113.0/24"};await store.SaveSettingsAsync(config);
        using(var c=new SqliteConnection("Data Source="+store.DatabasePath)){c.Open();using var q=c.CreateCommand();q.CommandText="UPDATE SchemaVersion SET version=2";q.ExecuteNonQuery();}
        await store.InitializeAsync();var settings=store.LoadSettings();Assert.Equal(3,settings.ConfigVersion);Assert.False(settings.EnablePublicIp);Assert.Equal(42,settings.BackgroundTransparency);Assert.Equal(-1234,settings.Widget.Left);Assert.True(settings.Widget.Topmost);Assert.Equal(config.ApprovedIps,settings.ApprovedIps);
        Assert.True(File.Exists(Path.Combine(root,"settings.json.v0.2.backup")));var backup=Assert.Single(Directory.GetFiles(Path.Combine(root,"backups"),"*.db"));
        using(var c=new SqliteConnection("Data Source="+backup)){c.Open();using var q=c.CreateCommand();q.CommandText="SELECT version FROM SchemaVersion";Assert.Equal(2L,q.ExecuteScalar());q.CommandText="SELECT cpuPct FROM MachineSnapshot";Assert.Equal(42d,q.ExecuteScalar());}
    }
    [Fact]public async Task IncidentIdentityAndExpectedAnnotationSurviveRestart()
    {
        var root=Root();var store=new LocalStore(root);await store.InitializeAsync();var now=DateTimeOffset.UtcNow;var p=new ProcessSample(now,123,now.AddMinutes(-5),"test","C:\\Apps\\test.exe",90,100,200,10,20);
        var i=new Incident{Rule="CPU Saturation",StartedUtc=now,UpdatedUtc=now,Processes=[new(p)]};await store.SaveIncidentAsync(i);await store.MarkExpectedAsync(i.Id,true);i.PeakCpu=99;i.UpdatedUtc=now.AddSeconds(10);await store.SaveIncidentAsync(i);
        var reloaded=Assert.Single(await new LocalStore(root).LoadIncidentsAsync());Assert.True(reloaded.Expected);Assert.Equal(p.InstanceId,reloaded.Processes[0].Sample.InstanceId);Assert.Equal(99,reloaded.PeakCpu);
    }
    [Fact]public async Task ProcessReuseSeparatesRowsAndNullIoStaysNull()
    {
        var store=new LocalStore(Root());await store.InitializeAsync();var now=DateTimeOffset.UtcNow;var a=new ProcessSample(now,2,now.AddMinutes(-5),"old",null,3,100);var b=a with{StartTimeUtc=now,Name="new"};
        await store.SaveAnalyticsAsync([a,b],null,[]);using var c=new SqliteConnection("Data Source="+store.DatabasePath);c.Open();using var q=c.CreateCommand();q.CommandText="SELECT COUNT(*) FROM process_samples WHERE readBps IS NULL";Assert.Equal(2L,q.ExecuteScalar());q.CommandText="SELECT COUNT(*) FROM process_identity";Assert.Equal(2L,q.ExecuteScalar());
    }
    [Fact]public async Task BaselinePersists(){var root=Root();var store=new LocalStore(root);await store.InitializeAsync();var point=new BaselinePoint(DateTimeOffset.UtcNow,2,30,1,200);await store.SaveAnalyticsAsync([],point,[]);Assert.Equal(point,Assert.Single(await new LocalStore(root).LoadBaselineAsync()));}
    [Fact]public async Task DailySummaryIncludesEventsOutsideTheVisible500Rows()
    {
        var store=new LocalStore(Root());await store.InitializeAsync();var now=DateTimeOffset.UtcNow;
        var items=Enumerable.Range(0,501).Select(n=>new Incident{Rule="test",Severity=n==0?"warning":"info",StartedUtc=now.AddMinutes(-n),UpdatedUtc=now}).ToArray();
        items[0]=items[0] with{StartedUtc=now.AddHours(-23)};await store.SaveAnalyticsAsync([],null,items);
        Assert.DoesNotContain(await store.LoadIncidentsAsync(),i=>i.Id==items[0].Id);var counts=await store.DailyCountsAsync(now.AddDays(-1));Assert.Equal(1,counts.Warnings);Assert.Equal(0,counts.Critical);
    }
    [Fact]public void StartupSnapshotDiffIsReadOnly(){var a=new StartupEntry("id","run","test","C:\\a.exe");Assert.Empty(StartupSnapshotCollector.Changes([a],[a]));Assert.Equal("C:\\b.exe",Assert.Single(StartupSnapshotCollector.Changes([a],[a with{Target="C:\\b.exe"}])).Target);Assert.StartsWith("Удалена:",Assert.Single(StartupSnapshotCollector.Changes([a],[])).Target);}
    [Theory][InlineData("\"C:\\Apps\\app.exe\" --token=secret","C:\\Apps\\app.exe")][InlineData("C:\\Program Files\\app.exe -Password=secret","C:\\Program Files\\app.exe")]
    public void StartupArgumentsAreNotCollected(string raw,string expected)=>Assert.Equal(expected,StartupSnapshotCollector.TargetOnly(raw));
}
