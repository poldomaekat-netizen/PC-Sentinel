using System.Diagnostics;
namespace PCSentinel.Network;
/// <summary>Serializes checks and bounds their start frequency, including repeated manual clicks.</summary>
public sealed class NetworkPollGate(TimeSpan minimumInterval)
{
    private readonly SemaphoreSlim _gate=new(1,1);
    private long _last;
    public async Task<T> RunAsync<T>(Func<Task<T>> operation,CancellationToken token)
    {
        await _gate.WaitAsync(token);
        try
        {
            var wait=_last==0?TimeSpan.Zero:minimumInterval-Stopwatch.GetElapsedTime(_last);
            if(wait>TimeSpan.Zero)await Task.Delay(wait,token);
            _last=Stopwatch.GetTimestamp();return await operation();
        }
        finally{_gate.Release();}
    }
}
