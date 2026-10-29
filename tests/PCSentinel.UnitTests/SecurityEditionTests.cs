using PCSentinel.Core;
using PCSentinel.Diagnostics;
using PCSentinel.Network;
using Xunit;
using System.Net.Sockets;
namespace PCSentinel.UnitTests;
public sealed class SecurityEditionTests
{
    private static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-10-26T00:00:00Z");
    private static MachineSample Sample(int seconds,double? cpu=5,double ram=40,double? disk=5,double? net=1000)=>new(Now.AddSeconds(seconds),cpu,ram,100,200,100,300,disk,0,0,1,0,99,net,net,"test");
    private static AppSettings Settings()=>new(){Anomalies=new(){SustainedSeconds=10,ProcessSeconds=5,RecoverySeconds=5,CooldownSeconds=300}};
    private static ProcessSample Proc(int seconds,int pid=123,DateTimeOffset? start=null,double? cpu=20,long memory=50*1048576)=>new(Now.AddSeconds(seconds),pid,start??Now.AddHours(-1),"probe",@"C:\Apps\probe.exe",cpu,memory,memory,100,200,"test");
    private static IpObservation Ip(string ip="8.8.8.8",bool agree=true,int age=0)=>new(Now.AddSeconds(-age),ip,"2001:4860:4860::8888",agree,true,"test","test");
    [Theory][InlineData("8.8.8.8")][InlineData("1.1.1.1")][InlineData("45.128.96.197")]
    public void PublicIpv4Accepted(string value)=>Assert.Equal(value,PublicAddress.Normalize(value,AddressFamily.InterNetwork));
    [Theory][InlineData("10.0.0.1")][InlineData("127.0.0.1")][InlineData("192.168.1.1")][InlineData("100.64.0.1")][InlineData("203.0.113.4")][InlineData("198.18.0.1")][InlineData("224.0.0.1")][InlineData("0.0.0.0")][InlineData("https://8.8.8.8")][InlineData("8.8.8.8 ")][InlineData("8.8.8.8/32")][InlineData("8.8.8")]
    public void ReservedAndMalformedIpv4Rejected(string value)=>Assert.Throws<ArgumentException>(()=>PublicAddress.Normalize(value,AddressFamily.InterNetwork));
    [Theory][InlineData("::1")][InlineData("fe80::1")][InlineData("fc00::1")][InlineData("2001:db8::1")][InlineData("::ffff:8.8.8.8")]
    public void ReservedIpv6Rejected(string value)=>Assert.Throws<ArgumentException>(()=>PublicAddress.Normalize(value,AddressFamily.InterNetworkV6));
    [Fact]public void Ipv6Normalized()=>Assert.Equal("2001:4860:4860::8888",PublicAddress.Normalize("2001:4860:4860:0:0:0:0:8888",AddressFamily.InterNetworkV6));
    [Fact]public void EqualIpv4IsTrustedWithoutVpnClaim()=>Assert.Equal(IpTrustState.Trusted,IpTrustPolicy.Evaluate("8.8.8.8",Ip(),true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void ChangedIpv4IsRed()=>Assert.Equal(IpTrustState.Changed,IpTrustPolicy.Evaluate("1.1.1.1",Ip(),true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void EmptyTrustIsNotConfigured()=>Assert.Equal(IpTrustState.NotConfigured,IpTrustPolicy.Evaluate("",null,false,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void ProviderDisagreementIsUnknown()=>Assert.Equal(IpTrustState.Unknown,IpTrustPolicy.Evaluate("8.8.8.8",Ip(agree:false),true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void OfflineIsUnknown()=>Assert.Equal(IpTrustState.Unknown,IpTrustPolicy.Evaluate("8.8.8.8",Ip() with{Online=false},true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void DisabledIsUnknown()=>Assert.Equal(IpTrustState.Unknown,IpTrustPolicy.Evaluate("8.8.8.8",Ip(),false,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void StaleIsUnknown()=>Assert.Equal(IpTrustState.Unknown,IpTrustPolicy.Evaluate("8.8.8.8",Ip(age:91),true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void Ipv6CannotReplaceIpv4()=>Assert.Equal(IpTrustState.Unknown,IpTrustPolicy.Evaluate("8.8.8.8",Ip() with{Ipv4=null,Agree4=false},true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void UnverifiedIpv6DoesNotPreventAccurateIpv4Trust()=>Assert.Equal(IpTrustState.Trusted,IpTrustPolicy.Evaluate("8.8.8.8",Ip() with{Agree6=false,Ipv6=null},true,Now,TimeSpan.FromSeconds(90)).State);
    [Fact]public void PidReuseGetsDifferentIdentity()=>Assert.NotEqual(Proc(0).InstanceId,Proc(0,start:Now).InstanceId);
    [Fact]public void RobustBaselineResistsOutlier(){var stats=BaselineService.Robust(Enumerable.Repeat(100d,100).Append(1000000));Assert.Equal(100,stats.Median);Assert.Equal(0,stats.Mad);Assert.Equal(100,stats.P95);}
    [Fact]public void BaselineLearnsFirst24Hours(){var b=new BaselineService();for(var n=0;n<60;n++)b.Add(new(Now.AddMinutes(n),1,2,3,4));Assert.True(b.Learning(Now.AddHours(23)));Assert.False(b.Learning(Now.AddHours(25)));}
    [Fact]public void ShortCpuSpikeDoesNotAlert(){var e=new AnomalyRuleEngine();var s=Settings();Assert.Empty(e.Evaluate(Sample(0,cpu:99),[],[],s,new(),new Dictionary<string,DateTimeOffset>()));Assert.Empty(e.Evaluate(Sample(5,cpu:5),[],[],s,new(),new Dictionary<string,DateTimeOffset>()));}
    [Fact]public void ContinuousCpuCreatesOneAndClosesAfterRecovery()
    {
        var engine=new AnomalyRuleEngine();var s=Settings();var known=new Dictionary<string,DateTimeOffset>{{@"C:\Apps\probe.exe",Now.AddDays(-2)}};var baseline=new BaselineService();
        engine.Evaluate(Sample(0,99),[Proc(0)],[],s,baseline,known);engine.Evaluate(Sample(5,99),[Proc(5)],[],s,baseline,known);
        var opened=Assert.Single(engine.Evaluate(Sample(10,99),[Proc(10)],[],s,baseline,known));Assert.True(opened.Notify);Assert.Equal("CPU Saturation",opened.Incident.Rule);Assert.Single(opened.Incident.Processes);
        Assert.Empty(engine.Evaluate(Sample(15,99),[Proc(15)],[],s,baseline,known));var update=Assert.Single(engine.Evaluate(Sample(20,98),[Proc(20)],[],s,baseline,known));Assert.Equal(opened.Incident.Id,update.Incident.Id);Assert.False(update.Notify);Assert.Equal(99,update.Incident.PeakCpu);
        engine.Evaluate(Sample(25,20),[],[],s,baseline,known);var closed=Assert.Single(engine.Evaluate(Sample(30,20),[],[],s,baseline,known));Assert.NotNull(closed.Incident.EndedUtc);
        engine.Evaluate(Sample(35,99),[],[],s,baseline,known);engine.Evaluate(Sample(40,99),[],[],s,baseline,known);Assert.False(Assert.Single(engine.Evaluate(Sample(45,99),[],[],s,baseline,known)).Notify);
    }
    [Fact]public void GapResetsPendingSaturation(){var e=new AnomalyRuleEngine();var s=Settings();e.Evaluate(Sample(0,99),[],[],s,new(),new Dictionary<string,DateTimeOffset>());Assert.Empty(e.Evaluate(Sample(60,99),[],[],s,new(),new Dictionary<string,DateTimeOffset>()));}
    [Fact]public void DiskFillAloneIsNotDiskOverload(){var e=new AnomalyRuleEngine();for(var n=0;n<=20;n+=5)Assert.DoesNotContain(e.Evaluate(Sample(n,disk:0),[],[],Settings(),new(),new Dictionary<string,DateTimeOffset>()),u=>u.Incident.Rule=="Disk Overload");}
    [Fact]public void NullTemperatureNeverCreatesThermal(){var e=new AnomalyRuleEngine();var sensor=new SensorReading("cpu","cpu","CPU",SensorKind.Temperature,"Package",null,"°C","test",Now,SensorStatus.Unsupported);for(var n=0;n<=20;n+=5)Assert.DoesNotContain(e.Evaluate(Sample(n),[],[sensor],Settings(),new(),new Dictionary<string,DateTimeOffset>()),u=>u.Incident.Rule=="Thermal Incident");}
    [Fact]public void TemperatureIncidentContainsDevice(){var e=new AnomalyRuleEngine();var sensor=new SensorReading("cpu","test cpu","CPU",SensorKind.Temperature,"Package",99,"°C","test",Now,SensorStatus.Available);e.Evaluate(Sample(0),[],[sensor],Settings(),new(),new Dictionary<string,DateTimeOffset>());var i=Assert.Single(e.Evaluate(Sample(5),[],[sensor],Settings(),new(),new Dictionary<string,DateTimeOffset>()));Assert.Equal(99,i.Incident.PeakTemperature);Assert.Contains("test cpu",i.Incident.Reason);}
    [Fact]public void IgnoredRuleCannotOpen(){var e=new AnomalyRuleEngine();var s=Settings();s.Anomalies.IgnoredRules.Add("CPU Saturation");for(var n=0;n<=20;n+=5)Assert.Empty(e.Evaluate(Sample(n,99),[],[],s,new(),new Dictionary<string,DateTimeOffset>()));}
    [Fact]public void NetworkLearningDoesNotInventBaseline(){var e=new AnomalyRuleEngine();for(var n=0;n<=20;n+=5)Assert.DoesNotContain(e.Evaluate(Sample(n,net:100000000),[],[],Settings(),new(),new Dictionary<string,DateTimeOffset>()),u=>u.Incident.Rule=="Unusual Network Burst");}
    [Fact]public async Task NetworkGateSerializesAndLimitsStartFrequency()
    {
        var gate=new NetworkPollGate(TimeSpan.FromMilliseconds(40));var running=0;var maximum=0;var clock=System.Diagnostics.Stopwatch.StartNew();var starts=new List<long>();
        async Task<int> Op(){lock(starts)starts.Add(clock.ElapsedMilliseconds);var active=Interlocked.Increment(ref running);maximum=Math.Max(maximum,active);await Task.Delay(10);Interlocked.Decrement(ref running);return 1;}
        await Task.WhenAll(Enumerable.Range(0,3).Select(_=>gate.RunAsync(Op,CancellationToken.None)));Assert.Equal(1,maximum);Assert.True(starts[1]-starts[0]>=30);Assert.True(starts[2]-starts[1]>=30);
    }
    [Theory][InlineData(1116)][InlineData(1117)][InlineData(1118)]public void DefenderEventsKeepOfficialIdAndNeverCollectCommands(int eventId)
    {
        var xml=$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-10-26T00:00:00Z'/></System><EventData><Data Name='Threat Name'>TEST ONLY</Data><Data Name='CommandLine'>-Password=real-secret</Data><Data Name='Path'>C:\\test.exe token=secret</Data></EventData></Event>";
        var e=SecurityEventParser.Parse("Microsoft-Windows-Windows Defender/Operational",xml)!;Assert.Equal(eventId,e.EventId);Assert.Equal(42,e.RecordId);Assert.DoesNotContain("CommandLine",e.Fields.Keys);Assert.DoesNotContain("secret",e.Fields["Path"]);Assert.Equal(Now,e.TimestampUtc);
    }
    [Fact]public void MissingEventTimeIsNotInvented()=>Assert.Null(SecurityEventParser.Parse("Microsoft-Windows-Windows Defender/Operational","<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1116</EventID><EventRecordID>42</EventRecordID></System></Event>"));
    [Fact]public void ConfirmedNetworkBurstHasNoInventedProcess()
    {
        var b=new BaselineService();for(var n=0;n<1500;n++)b.Add(new(Now.AddMinutes(n),1,20,1,1000));var e=new AnomalyRuleEngine();var s=Settings();var offset=25*3600;
        e.Evaluate(Sample(offset,net:100000000),[],[],s,b,new Dictionary<string,DateTimeOffset>());e.Evaluate(Sample(offset+5,net:100000000),[],[],s,b,new Dictionary<string,DateTimeOffset>());
        var i=Assert.Single(e.Evaluate(Sample(offset+10,net:100000000),[],[],s,b,new Dictionary<string,DateTimeOffset>()));Assert.Equal("Unusual Network Burst",i.Incident.Rule);Assert.Empty(i.Incident.Processes);Assert.Contains("Источник не установлен",i.Incident.Reason);
    }
    [Fact]public void ProcessMemoryGrowthNeedsTenMinuteHistory()
    {
        var engine=new AnomalyRuleEngine();var s=Settings();var known=new Dictionary<string,DateTimeOffset>{{@"C:\Apps\probe.exe",Now.AddDays(-2)}};var updates=new List<IncidentUpdate>();
        for(var n=0;n<=600;n+=5){var memory=n<550?100*1048576L:800*1048576L;updates.AddRange(engine.Evaluate(Sample(n),[Proc(n,cpu:1,memory:memory)],[],s,new(),known));}
        Assert.Contains(updates,u=>u.Incident.Rule=="Memory Growth");Assert.DoesNotContain(updates,u=>u.Incident.StartedUtc<Now.AddSeconds(540));
    }
    [Fact]public void NewUnsignedNameAloneIsNotUnexpectedProcess(){var engine=new AnomalyRuleEngine();for(var n=0;n<20;n+=5)Assert.Empty(engine.Evaluate(Sample(n),[Proc(n,cpu:1)],[],Settings(),new(),new Dictionary<string,DateTimeOffset>()));}
    [Fact]public void IgnoringAProcessDoesNotHideGlobalCpuSaturation()
    {
        var engine=new AnomalyRuleEngine();var settings=Settings();settings.Anomalies.IgnoredPaths.Add(@"C:\Apps\probe.exe");var updates=new List<IncidentUpdate>();
        for(var n=0;n<=15;n+=5)updates.AddRange(engine.Evaluate(Sample(n,99),[Proc(n)],[],settings,new(),new Dictionary<string,DateTimeOffset>()));
        Assert.Contains(updates,u=>u.Incident.Rule=="CPU Saturation");Assert.DoesNotContain(updates,u=>u.Incident.Rule=="Unexpected Process");
    }
}
