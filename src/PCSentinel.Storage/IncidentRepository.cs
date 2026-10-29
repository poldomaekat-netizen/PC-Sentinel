using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCSentinel.Core;
namespace PCSentinel.Storage;
public sealed partial class LocalStore
{
    private static void CreateV3(SqliteConnection c,SqliteTransaction tx)=>Exec(c,tx,"""
        CREATE TABLE IF NOT EXISTS process_identity(instanceId TEXT PRIMARY KEY,pid INTEGER,startTimeUtc TEXT,path TEXT,name TEXT,firstSeenUtc TEXT,detailsJson TEXT);
        CREATE INDEX IF NOT EXISTS IX_identity_path ON process_identity(path);
        CREATE TABLE IF NOT EXISTS process_samples(timestampUtc TEXT,instanceId TEXT,cpu REAL,workingSet INTEGER,privateBytes INTEGER,readBps REAL,writeBps REAL,detailsJson TEXT,PRIMARY KEY(timestampUtc,instanceId));
        CREATE INDEX IF NOT EXISTS IX_ps_instance ON process_samples(instanceId,timestampUtc);
        CREATE TABLE IF NOT EXISTS baseline_profiles(timestampUtc TEXT PRIMARY KEY,detailsJson TEXT);
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,startedUtc TEXT,updatedUtc TEXT,endedUtc TEXT,rule TEXT,severity TEXT,expected INTEGER,detailsJson TEXT);
        CREATE INDEX IF NOT EXISTS IX_incident_time ON incidents(startedUtc);
        CREATE INDEX IF NOT EXISTS IX_incident_rule ON incidents(rule,severity);
        CREATE TABLE IF NOT EXISTS incident_processes(incidentId TEXT,instanceId TEXT,detailsJson TEXT,PRIMARY KEY(incidentId,instanceId));
        CREATE INDEX IF NOT EXISTS IX_ip_instance ON incident_processes(instanceId);
        CREATE TABLE IF NOT EXISTS security_events(channel TEXT,recordId INTEGER,eventId INTEGER,timestampUtc TEXT,detailsJson TEXT,PRIMARY KEY(channel,recordId));
        CREATE INDEX IF NOT EXISTS IX_security_time ON security_events(timestampUtc);
        CREATE TABLE IF NOT EXISTS ip_check_history(timestampUtc TEXT PRIMARY KEY,detailsJson TEXT);
        CREATE TABLE IF NOT EXISTS analytics_state(key TEXT PRIMARY KEY,value TEXT);
        UPDATE SchemaVersion SET version=3;
        """);
    public Task SaveAnalyticsAsync(IReadOnlyList<ProcessSample> processes,BaselinePoint? baseline,IReadOnlyList<Incident> incidents)=>Locked(()=>
    {
        using var c=Open();using var tx=c.BeginTransaction();
        foreach(var p in processes.Where(p=>p.StartTimeUtc.HasValue))
        {
            Exec(c,tx,"INSERT OR IGNORE INTO process_identity VALUES($i,$p,$s,$f,$n,$t,$j)",("$i",p.InstanceId),("$p",p.Pid),("$s",p.StartTimeUtc?.ToString("O")),("$f",p.Path),("$n",p.Name),("$t",p.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(p)));
            Exec(c,tx,"INSERT OR IGNORE INTO process_samples VALUES($t,$i,$c,$w,$p,$r,$v,$j)",("$t",p.TimestampUtc.ToString("O")),("$i",p.InstanceId),("$c",p.CpuPct),("$w",p.WorkingSetBytes),("$p",p.PrivateBytes),("$r",p.ReadBps),("$v",p.WriteBps),("$j",JsonSerializer.Serialize(p)));
        }
        if(baseline!=null)Exec(c,tx,"INSERT OR REPLACE INTO baseline_profiles VALUES($t,$j)",("$t",baseline.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(baseline)));
        foreach(var incident in incidents)SaveIncident(c,tx,incident);tx.Commit();
    });
    public Task SaveIdentitiesAsync(IReadOnlyList<ProcessSample> processes)=>Locked(()=>
    {
        using var c=Open();using var tx=c.BeginTransaction();
        foreach(var p in processes.Where(p=>p.StartTimeUtc.HasValue))Exec(c,tx,"INSERT OR IGNORE INTO process_identity VALUES($i,$p,$s,$f,$n,$t,$j)",("$i",p.InstanceId),("$p",p.Pid),("$s",p.StartTimeUtc?.ToString("O")),("$f",p.Path),("$n",p.Name),("$t",p.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(p)));
        tx.Commit();
    });
    private static void SaveIncident(SqliteConnection c,SqliteTransaction? tx,Incident i)
    {
        // User annotations survive subsequent peak/time updates from the rule engine.
        using(var annotation=c.CreateCommand())
        {annotation.Transaction=tx;annotation.CommandText="SELECT expected FROM incidents WHERE id=$id";annotation.Parameters.AddWithValue("$id",i.Id);if(annotation.ExecuteScalar() is long value)i.Expected=value!=0;}
        Exec(c,tx,"INSERT OR REPLACE INTO incidents VALUES($id,$s,$u,$e,$r,$v,$x,$j)",("$id",i.Id),("$s",i.StartedUtc.ToString("O")),("$u",i.UpdatedUtc.ToString("O")),("$e",i.EndedUtc?.ToString("O")),("$r",i.Rule),("$v",i.Severity),("$x",i.Expected?1:0),("$j",JsonSerializer.Serialize(i)));
        foreach(var p in i.Processes)Exec(c,tx,"INSERT OR REPLACE INTO incident_processes VALUES($i,$p,$j)",("$i",i.Id),("$p",p.Sample.InstanceId),("$j",JsonSerializer.Serialize(p)));
    }
    public Task SaveIncidentAsync(Incident i)=>Locked(()=>{using var c=Open();using var tx=c.BeginTransaction();SaveIncident(c,tx,i);tx.Commit();});
    public async Task<List<Incident>> LoadIncidentsAsync()
    {var list=new List<Incident>();await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT detailsJson FROM incidents ORDER BY startedUtc DESC LIMIT 500";using var r=cmd.ExecuteReader();while(r.Read())if(JsonSerializer.Deserialize<Incident>(r.GetString(0)) is {} item)list.Add(item);});return list;}
    public async Task<(int Warnings,int Critical)> DailyCountsAsync(DateTimeOffset since)
    {
        var warnings=0;var critical=0;
        await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT severity,COUNT(*) FROM incidents WHERE startedUtc >= $t GROUP BY severity";cmd.Parameters.AddWithValue("$t",since.ToString("O"));using var r=cmd.ExecuteReader();while(r.Read()){if(r.GetString(0)=="warning")warnings=r.GetInt32(1);if(r.GetString(0)=="critical")critical=r.GetInt32(1);}});
        return(warnings,critical);
    }
    public async Task<List<BaselinePoint>> LoadBaselineAsync()
    {var list=new List<BaselinePoint>();await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT detailsJson FROM baseline_profiles WHERE timestampUtc >= $t ORDER BY timestampUtc LIMIT 10080";cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.AddDays(-7).ToString("O"));using var r=cmd.ExecuteReader();while(r.Read())if(JsonSerializer.Deserialize<BaselinePoint>(r.GetString(0)) is {} item)list.Add(item);});return list;}
    public async Task<Dictionary<string,DateTimeOffset>> KnownPathsAsync()
    {var result=new Dictionary<string,DateTimeOffset>(StringComparer.OrdinalIgnoreCase);await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT path,MIN(firstSeenUtc) FROM process_identity WHERE path IS NOT NULL GROUP BY path ORDER BY MIN(firstSeenUtc) DESC LIMIT 20000";using var r=cmd.ExecuteReader();while(r.Read())result[r.GetString(0)]=DateTimeOffset.Parse(r.GetString(1));});return result;}
    public Task MarkExpectedAsync(string id,bool expected)=>Locked(()=>
    {using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT detailsJson FROM incidents WHERE id=$i";cmd.Parameters.AddWithValue("$i",id);if(cmd.ExecuteScalar() is string json && JsonSerializer.Deserialize<Incident>(json) is {} i){i.Expected=expected;Exec(c,null,"UPDATE incidents SET expected=$x,detailsJson=$j WHERE id=$i",("$x",expected?1:0),("$j",JsonSerializer.Serialize(i)),("$i",id));}});
    public Task SaveIpAsync(IpObservation observation)=>Locked(()=>{using var c=Open();Exec(c,null,"INSERT OR REPLACE INTO ip_check_history VALUES($t,$j)",("$t",observation.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(observation)));});
    public async Task<string?> StateAsync(string key){string? value=null;await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT value FROM analytics_state WHERE key=$k";cmd.Parameters.AddWithValue("$k",key);value=cmd.ExecuteScalar() as string;});return value;}
    public Task SaveStateAsync(string key,string value)=>Locked(()=>{using var c=Open();Exec(c,null,"INSERT OR REPLACE INTO analytics_state VALUES($k,$v)",("$k",key),("$v",value));});
    public Task SaveSecurityAsync(SecurityEvent e)=>Locked(()=>{using var c=Open();Exec(c,null,"INSERT OR IGNORE INTO security_events VALUES($c,$r,$e,$t,$j)",("$c",e.Channel),("$r",e.RecordId),("$e",e.EventId),("$t",e.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(e)));});
    public async Task<List<MachineSample>> IncidentContextAsync(Incident incident)
    {var list=new List<MachineSample>();await Locked(()=>{using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT detailsJson FROM MachineSnapshot WHERE timestampUtc BETWEEN $a AND $b ORDER BY timestampUtc LIMIT 900";cmd.Parameters.AddWithValue("$a",incident.StartedUtc.AddMinutes(-5).ToString("O"));cmd.Parameters.AddWithValue("$b",(incident.EndedUtc??incident.UpdatedUtc).AddMinutes(5).ToString("O"));using var r=cmd.ExecuteReader();while(r.Read())if(JsonSerializer.Deserialize<MachineSample>(r.GetString(0)) is {} item)list.Add(item);});return list;}
    private static void MaintainV3(SqliteConnection c,SqliteTransaction tx,AppSettings s)
    {
        Exec(c,tx,"DELETE FROM process_samples WHERE timestampUtc<$t",("$t",DateTimeOffset.UtcNow.AddDays(-s.RawHistoryDays).ToString("O")));
        Exec(c,tx,"DELETE FROM baseline_profiles WHERE timestampUtc<$t",("$t",DateTimeOffset.UtcNow.AddDays(-7).ToString("O")));
        Exec(c,tx,"DELETE FROM incidents WHERE updatedUtc<$t; DELETE FROM security_events WHERE timestampUtc<$t; DELETE FROM ip_check_history WHERE timestampUtc<$t;",("$t",DateTimeOffset.UtcNow.AddDays(-s.EventHistoryDays).ToString("O")));
        Exec(c,tx,"DELETE FROM incident_processes WHERE incidentId NOT IN (SELECT id FROM incidents); DELETE FROM process_identity WHERE firstSeenUtc<$t AND instanceId NOT IN (SELECT instanceId FROM process_samples) AND instanceId NOT IN (SELECT instanceId FROM incident_processes)",("$t",DateTimeOffset.UtcNow.AddDays(-s.EventHistoryDays).ToString("O")));
    }
}
