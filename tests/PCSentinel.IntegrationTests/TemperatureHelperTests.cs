using PCSentinel.Core;
using PCSentinel.Collectors;
using Xunit;
namespace PCSentinel.IntegrationTests;
public sealed class TemperatureHelperTests
{
    private static SensorReading Reading(DateTimeOffset at,double? value=50,string type="CPU")=>new("test",type,type,SensorKind.Temperature,"Temperature",value,"°C","test",at,SensorStatus.Available);
    [Fact]public void FreshCpuAndGpuRemainSeparate()
    {var at=DateTimeOffset.UtcNow;var values=TemperatureHelper.Validate([Reading(at,61),Reading(at,43,"GPU")],at);Assert.Equal(2,values.Count);Assert.Equal(61,values[0].Value);Assert.Equal(43,values[1].Value);}
    [Fact]public void StaleAndFutureMeasurementsAreDiscarded()
    {var at=DateTimeOffset.UtcNow;Assert.Empty(TemperatureHelper.Validate([Reading(at.AddSeconds(-16)),Reading(at.AddSeconds(6))],at));}
    [Theory][InlineData(double.NaN)][InlineData(double.PositiveInfinity)][InlineData(0)][InlineData(151)]
    public void InvalidMessageCannotBecomeTemperature(double value)
    {var at=DateTimeOffset.UtcNow;var reading=Assert.Single(TemperatureHelper.Validate([Reading(at,value)],at));Assert.Null(reading.Value);Assert.Equal(SensorStatus.Unavailable,reading.Status);}
    [Fact]public void OtherKindsAndDevicesAreRejected()
    {var at=DateTimeOffset.UtcNow;Assert.Empty(TemperatureHelper.Validate([Reading(at,type:"SSD"),Reading(at) with{Kind=SensorKind.Power}],at));}
    [Fact]public async Task WorkerRejectsMalformedCommandWithoutOpeningDriver()=>Assert.Equal(2,await TemperatureHelper.RunWorkerAsync(["--hardware-sensor-helper","other", "1", "1"]));
    [Fact]public async Task StoppedHelperDoesNotKeepOldData()
    {using var helper=new TemperatureHelper();await helper.StopAsync();Assert.All(helper.Read(CancellationToken.None),r=>Assert.Null(r.Value));Assert.False(helper.IsRunning);}
    [Fact]public async Task LocalPipeAuthenticatesBothActualProcessesAndRejectsWrongPid()
    {
        var name="PCSentinel.Sensor."+Guid.NewGuid().ToString("N");
        using var server=new System.IO.Pipes.NamedPipeServerStream(name,System.IO.Pipes.PipeDirection.Out,1,System.IO.Pipes.PipeTransmissionMode.Byte,System.IO.Pipes.PipeOptions.Asynchronous|System.IO.Pipes.PipeOptions.CurrentUserOnly);
        using var client=TemperatureHelper.CreateReader(name);using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var waiting=server.WaitForConnectionAsync(timeout.Token);await client.ConnectAsync(timeout.Token);await waiting;
        Assert.True(TemperatureHelper.IsExpectedPeer(server.SafePipeHandle,Environment.ProcessId,true));
        Assert.True(TemperatureHelper.IsExpectedPeer(client.SafePipeHandle,Environment.ProcessId,false));
        Assert.False(TemperatureHelper.IsExpectedPeer(server.SafePipeHandle,0,true));
        var data=new byte[1];var receiving=client.ReadExactlyAsync(data,timeout.Token);await server.WriteAsync(new byte[]{42},timeout.Token);await receiving;Assert.Equal(42,data[0]);Assert.False(client.CanWrite);
    }
}
