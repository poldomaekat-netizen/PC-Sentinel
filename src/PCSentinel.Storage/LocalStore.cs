using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCSentinel.Core;

namespace PCSentinel.Storage;

public sealed partial class LocalStore
{
    static LocalStore() => SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_winsqlite3());
    public static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    public string Root { get; }
    public string DatabasePath => Path.Combine(Root, "sentinel.db");
    public bool SettingsMigrated {get;private set;}
    private readonly SemaphoreSlim _gate = new(1, 1);
    public LocalStore(string? root = null) => Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCSentinel");
    public AppSettings LoadSettings()
    {
        var path = Path.Combine(Root, "settings.json");
        if (!File.Exists(path)) return new();
        var content=File.ReadAllText(path);
        var settings=JsonSerializer.Deserialize<AppSettings>(content)??new();
        using var document=JsonDocument.Parse(content);
        var oldVersion=document.RootElement.TryGetProperty(nameof(AppSettings.ConfigVersion),out var old)?old.GetInt32():1;
        if(oldVersion>3)throw new InvalidOperationException("Настройки созданы более новой версией.");
        if(oldVersion<3)
        {
            var migrationBackup=path+$".v0.{(oldVersion<2?1:2)}.backup";
            if(!File.Exists(migrationBackup))File.Copy(path,migrationBackup);
            // Preserve an explicit opt-out; new installs default to automatic checks.
            if(!document.RootElement.TryGetProperty(nameof(AppSettings.EnablePublicIp),out _))settings.EnablePublicIp=false;
            settings.ConfigVersion=3;
        }
        if(!document.RootElement.TryGetProperty(nameof(AppSettings.ConfigVersion),out var v) || v.GetInt32()<2)
        {
            var backup=path+".v0.1.backup";
            if(!File.Exists(backup))File.Copy(path,backup);
            settings.LegacyApprovedIps=settings.ApprovedIps;
            settings.ConfigVersion=3;settings.AutoDetectVpn=true;
            // Keep the original IP criteria as legacy data; a user-confirmed profile is required.
        }
        settings.Validate();SettingsMigrated=oldVersion<3;return settings;
    }
    public async Task SaveSettingsAsync(AppSettings settings)
    {
        settings.Validate(); Directory.CreateDirectory(Root); var path = Path.Combine(Root, "settings.json");
        await File.WriteAllTextAsync(path + ".tmp", JsonSerializer.Serialize(settings, Json)); File.Move(path + ".tmp", path, true);
    }
    private SqliteConnection Open()
    {
        Directory.CreateDirectory(Root);
        var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DatabasePath, DefaultTimeout = 5 }.ToString()); c.Open(); return c;
    }
    public async Task InitializeAsync() => await Locked(() =>
    {
        var existed=File.Exists(DatabasePath);
        using var c = Open();
        int version=0;
        using(var probe=c.CreateCommand())
        {
            probe.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='SchemaVersion'";
            if(Convert.ToInt32(probe.ExecuteScalar())>0){probe.CommandText="SELECT MAX(version) FROM SchemaVersion";version=Convert.ToInt32(probe.ExecuteScalar());}
        }
        if(version>3)throw new InvalidOperationException("База создана более новой версией PC Sentinel.");
        if(existed && version<3)
        {
            var config=Path.Combine(Root,"settings.json");var configBackup=config+$".v0.{(version<2?1:2)}.backup";
            if(File.Exists(config) && !File.Exists(configBackup))File.Copy(config,configBackup);
            var backupDir=Path.Combine(Root,"backups");Directory.CreateDirectory(backupDir);
            using var backup=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(backupDir,$"sentinel-before-v{(version<2?2:3)}-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}.db")}.ToString());
            backup.Open();c.BackupDatabase(backup);
        }
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS SchemaVersion(version INTEGER NOT NULL);
            INSERT INTO SchemaVersion SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM SchemaVersion);
            CREATE TABLE IF NOT EXISTS MachineSnapshot(timestampUtc TEXT PRIMARY KEY,cpuPct REAL,ramPct REAL,diskActivePct REAL,netDownBps REAL,netUpBps REAL,detailsJson TEXT);
            CREATE TABLE IF NOT EXISTS MinuteAggregate(minuteUtc TEXT PRIMARY KEY,samples INTEGER,cpuAvg REAL,cpuMax REAL,ramAvg REAL,ramMax REAL,diskMax REAL,netDownAvg REAL,netUpAvg REAL);
            CREATE TABLE IF NOT EXISTS ProcessSample(timestampUtc TEXT,pid INTEGER,startTimeUtc TEXT,name TEXT,path TEXT,cpuPct REAL,workingSetBytes INTEGER,PRIMARY KEY(timestampUtc,pid));
            CREATE INDEX IF NOT EXISTS IX_Process_Time ON ProcessSample(timestampUtc);
            CREATE TABLE IF NOT EXISTS HardwareInventory(componentType TEXT,name TEXT,detailsJson TEXT,seenAtUtc TEXT);
            CREATE TABLE IF NOT EXISTS NetworkCheck(timestampUtc TEXT PRIMARY KEY,ipV4 TEXT,ipV6 TEXT,route TEXT,vpnState TEXT,reason TEXT);
            CREATE TABLE IF NOT EXISTS AlertEvent(timestampUtc TEXT,type TEXT,severity TEXT,description TEXT);
            """;
        cmd.ExecuteNonQuery();
        using var tx=c.BeginTransaction();
        Exec(c,tx,"""
            CREATE TABLE IF NOT EXISTS SensorSample(timestampUtc TEXT,sensorId TEXT,hardwareId TEXT,deviceType TEXT,kind TEXT,value REAL,unit TEXT,source TEXT,status TEXT,detailsJson TEXT,PRIMARY KEY(timestampUtc,sensorId));
            CREATE INDEX IF NOT EXISTS IX_Sensor_Time ON SensorSample(timestampUtc);
            CREATE TABLE IF NOT EXISTS SensorMinute(minuteUtc TEXT,sensorId TEXT,samples INTEGER,average REAL,maximum REAL,PRIMARY KEY(minuteUtc,sensorId));
            CREATE TABLE IF NOT EXISTS NetworkObservation(timestampUtc TEXT PRIMARY KEY,detailsJson TEXT);
            """);
        CreateV3(c,tx);
        tx.Commit();
    });
    private async Task Locked(Action action)
    {
        await _gate.WaitAsync();
        try { await Task.Run(action); } finally { _gate.Release(); }
    }
    private static void Exec(SqliteConnection c, SqliteTransaction? tx, string sql, params (string Key, object? Value)[] values)
    {
        using var cmd = c.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = sql;
        foreach (var v in values) cmd.Parameters.AddWithValue(v.Key, v.Value ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
    public async Task SaveSampleAsync(MachineSample s, IReadOnlyList<ProcessSample>? processes) => await Locked(() =>
    {
        using var c = Open(); using var tx = c.BeginTransaction();
        Exec(c, tx, "INSERT OR REPLACE INTO MachineSnapshot VALUES($t,$c,$r,$d,$n,$u,$j)",
            ("$t", s.TimestampUtc.ToString("O")), ("$c", s.CpuPct), ("$r", s.RamPct), ("$d", s.DiskActivePct), ("$n", s.NetDownBps), ("$u", s.NetUpBps), ("$j", JsonSerializer.Serialize(s)));
        if (processes != null) foreach (var p in processes)
            Exec(c, tx, "INSERT OR REPLACE INTO ProcessSample VALUES($t,$p,$s,$n,$f,$c,$w)",
                ("$t", p.TimestampUtc.ToString("O")), ("$p", p.Pid), ("$s", p.StartTimeUtc?.ToString("O")), ("$n", p.Name), ("$f", p.Path), ("$c", p.CpuPct), ("$w", p.WorkingSetBytes));
        tx.Commit();
    });
    public async Task SaveNetworkAsync(NetworkCheck n) => await Locked(() =>
    {
        using var c = Open(); using var tx=c.BeginTransaction();Exec(c, tx, "INSERT OR REPLACE INTO NetworkCheck VALUES($t,$4,$6,$r,$s,$d)",
            ("$t", n.TimestampUtc.ToString("O")), ("$4", n.IpV4), ("$6", n.IpV6), ("$r", n.Route), ("$s", n.State.ToString()), ("$d", n.Reason));
        Exec(c,tx,"INSERT OR REPLACE INTO NetworkObservation VALUES($t,$j)",("$t",n.TimestampUtc.ToString("O")),("$j",JsonSerializer.Serialize(n)));tx.Commit();
    });
    public async Task SaveSensorsAsync(IReadOnlyList<SensorReading> readings)=>await Locked(()=>
    {
        using var c=Open();using var tx=c.BeginTransaction();
        foreach(var r in readings)Exec(c,tx,"INSERT OR IGNORE INTO SensorSample VALUES($t,$id,$h,$d,$k,$v,$u,$s,$a,$j)",
            ("$t",r.TimestampUtc.ToString("O")),("$id",r.Id),("$h",r.HardwareId),("$d",r.DeviceType),("$k",r.Kind.ToString()),("$v",r.Value),("$u",r.Unit),("$s",r.Source),("$a",r.Status.ToString()),("$j",JsonSerializer.Serialize(r)));
        tx.Commit();
    });
    public async Task SaveInventoryAsync(IReadOnlyList<HardwareItem> items) => await Locked(() =>
    {
        using var c = Open(); using var tx = c.BeginTransaction();
        foreach (var h in items) Exec(c, tx, "INSERT INTO HardwareInventory VALUES($t,$n,$d,$s)", ("$t", h.ComponentType), ("$n", h.Name), ("$d", JsonSerializer.Serialize(new { h.Details })), ("$s", DateTimeOffset.UtcNow.ToString("O")));
        tx.Commit();
    });
    public async Task SaveAlertAsync(AlertEvent e) => await Locked(() =>
    {
        using var c = Open(); Exec(c, null, "INSERT INTO AlertEvent VALUES($t,$y,$s,$d)", ("$t", e.TimestampUtc.ToString("O")), ("$y", e.Type), ("$s", e.Severity), ("$d", e.Description));
    });
    public async Task MaintainAsync(AppSettings settings) => await Locked(() =>
    {
        using var c = Open(); using var tx = c.BeginTransaction();
        Exec(c, tx, """
            INSERT OR REPLACE INTO MinuteAggregate
            SELECT substr(timestampUtc,1,16),COUNT(*),AVG(cpuPct),MAX(cpuPct),AVG(ramPct),MAX(ramPct),MAX(diskActivePct),AVG(netDownBps),AVG(netUpBps)
            FROM MachineSnapshot WHERE timestampUtc < $minute GROUP BY substr(timestampUtc,1,16);
            """, ("$minute", DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm")));
        var raw = DateTimeOffset.UtcNow.AddDays(-settings.RawHistoryDays).ToString("O");
        Exec(c,tx,"""
            INSERT OR REPLACE INTO SensorMinute SELECT substr(timestampUtc,1,16),sensorId,COUNT(value),AVG(value),MAX(value)
            FROM SensorSample WHERE timestampUtc < $minute GROUP BY substr(timestampUtc,1,16),sensorId;
            """,("$minute",DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm")));
        Exec(c,tx,"DELETE FROM SensorSample WHERE timestampUtc < $t",("$t",raw));
        Exec(c,tx,"DELETE FROM SensorMinute WHERE minuteUtc < $t",("$t",DateTimeOffset.UtcNow.AddDays(-settings.AggregateHistoryDays).ToString("yyyy-MM-ddTHH:mm")));
        Exec(c,tx,"DELETE FROM NetworkObservation WHERE timestampUtc < $t",("$t",DateTimeOffset.UtcNow.AddDays(-settings.EventHistoryDays).ToString("O")));
        Exec(c, tx, "DELETE FROM MachineSnapshot WHERE timestampUtc < $t; DELETE FROM ProcessSample WHERE timestampUtc < $t;", ("$t", raw));
        Exec(c, tx, "DELETE FROM MinuteAggregate WHERE minuteUtc < $t", ("$t", DateTimeOffset.UtcNow.AddDays(-settings.AggregateHistoryDays).ToString("yyyy-MM-ddTHH:mm")));
        Exec(c, tx, "DELETE FROM AlertEvent WHERE timestampUtc < $t; DELETE FROM NetworkCheck WHERE timestampUtc < $t; DELETE FROM HardwareInventory WHERE seenAtUtc < $t;", ("$t", DateTimeOffset.UtcNow.AddDays(-settings.EventHistoryDays).ToString("O")));
        MaintainV3(c,tx,settings);
        tx.Commit();
    });
    public async Task<string> RecentReportAsync() 
    {
        var text = "";
        await Locked(() =>
        {
            using var c = Open(); using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT timestampUtc,cpuPct,ramPct,diskActivePct FROM MachineSnapshot ORDER BY timestampUtc DESC LIMIT 300";
            using var r = cmd.ExecuteReader(); var rows = new List<string>();
            while (r.Read()) rows.Add($"{r.GetString(0)}   CPU {Value(r,1)}%   RAM {Value(r,2)}%   Диск {Value(r,3)}%");
            text = "Последние 300 проб (UTC), сначала новые.\n\n" + string.Join('\n', rows) + "\n\nСрезы процессов каждые 5 секунд. Процесс, исчезнувший между срезами, может отсутствовать. Данных для автоматического определения виновника пока недостаточно. Полный мастер диагностики запланирован на v1.0.";
        }); return text;
    }
    private static string Value(SqliteDataReader r, int i) => r.IsDBNull(i) ? "N/A" : r.GetDouble(i).ToString("F1");
    public async Task ExportJsonAsync(string path)
    {
        await _gate.WaitAsync();
        try
        {
            await Task.Run(() =>
            {
                using var c = Open(); using var tx = c.BeginTransaction();
                using var stream = File.Create(path); using var writer = new Utf8JsonWriter(stream, new() { Indented = true });
                writer.WriteStartObject();
                foreach (var table in new[] { "MachineSnapshot", "MinuteAggregate", "ProcessSample", "NetworkCheck", "AlertEvent", "HardwareInventory", "SensorSample", "SensorMinute", "NetworkObservation", "process_identity", "process_samples", "baseline_profiles", "incidents", "incident_processes", "security_events", "ip_check_history" })
                {
                    writer.WriteStartArray(table); using var cmd = c.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = $"SELECT * FROM {table}";
                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        writer.WriteStartObject();
                        for (var i = 0; i < reader.FieldCount; i++)
                        {
                            writer.WritePropertyName(reader.GetName(i));object? value=reader.IsDBNull(i)?null:reader.GetValue(i);
                            if(value is string text)value=ExportRedaction.HideUncPaths(text);
                            JsonSerializer.Serialize(writer,value);
                        }
                        writer.WriteEndObject();
                    }
                    writer.WriteEndArray();
                }
                writer.WriteEndObject(); tx.Commit();
            });
        }
        finally { _gate.Release(); }
    }
}
