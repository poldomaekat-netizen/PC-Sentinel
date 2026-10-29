using PCSentinel.Core;
namespace PCSentinel.Diagnostics;
public sealed class TemperatureRules
{
    private readonly Dictionary<string,DateTimeOffset> _since=[],_last=[];
    public AlertEvent? Check(SensorReading r,AppSettings s)
    {
        if(r.Kind!=SensorKind.Temperature)return null;
        var threshold=r.DeviceType switch{"CPU"=>s.CpuTemperatureCritical,"GPU"=>s.GpuTemperatureCritical,"SSD"=>s.SsdTemperatureCritical,_=>double.PositiveInfinity};
        if(r.Status!=SensorStatus.Available || r.Value is null || r.Value<threshold){_since.Remove(r.Id);return null;}
        if(!_since.TryGetValue(r.Id,out var since)){_since[r.Id]=r.TimestampUtc;return null;}
        if(r.TimestampUtc-since<TimeSpan.FromSeconds(s.AlertDurationSeconds) || _last.TryGetValue(r.Id,out var last) && r.TimestampUtc-last<TimeSpan.FromSeconds(s.AlertCooldownSeconds))return null;
        _last[r.Id]=r.TimestampUtc;
        return new(r.TimestampUtc,"Temperature","warning",$"{r.HardwareName}: {r.Name} {r.Value:F1} °C, порог {threshold:F0} °C. Источник: {r.Source}.");
    }
}
