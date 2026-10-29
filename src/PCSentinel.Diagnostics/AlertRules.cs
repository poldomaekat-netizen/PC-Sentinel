using PCSentinel.Core;

namespace PCSentinel.Diagnostics;

public sealed class AlertRules
{
    private readonly Dictionary<string, DateTimeOffset> _since = [], _last = [];
    public AlertEvent? Check(string key, double? value, DateTimeOffset now, AppSettings settings)
    {
        if (value is null || value < settings.CriticalThreshold) { _since.Remove(key); return null; }
        if (!_since.TryGetValue(key, out var since)) { _since[key] = now; return null; }
        if (now - since < TimeSpan.FromSeconds(settings.AlertDurationSeconds) ||
            _last.TryGetValue(key, out var last) && now - last < TimeSpan.FromSeconds(settings.AlertCooldownSeconds)) return null;
        _last[key] = now;
        return new(now, key, "warning", $"{key}: {value:F0}% — порог превышен не менее {settings.AlertDurationSeconds} с. Это нагрузка, а не признак вируса.");
    }
    public void Reset() => _since.Clear();
}
