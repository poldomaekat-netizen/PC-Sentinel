using PCSentinel.Core;
using PCSentinel.Diagnostics;
using PCSentinel.Network;
using Xunit;
namespace PCSentinel.UnitTests;
public sealed class GlassTests
{
    private static ProfileEvidence Good=>new(true,true,true,true,true,true,true,true,false,true,true,true,true);
    private static AdapterInfo Adapter(string name,string kind="Ethernet",bool ip=true,bool up=true)=>new(name,name,name,7,7,up,kind,"",false,ip);
    [Fact]public void ProfileAndRoutesRequired()=>Assert.Equal(VpnState.Protected,ProfilePolicy.Evaluate(Good).State);
    [Fact]public void NoProfileIsNeverGreen()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{HasProfile=false}).State);
    [Fact]public void SiteAccessCannotReplaceIpEvidence()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{Agree4=false}).State);
    [Fact]public void MissingV6EvidenceIsUnknown()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{Agree6=false}).State);
    [Fact]public void MissingRoutesIsUnknown()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{RoutesKnown=false}).State);
    [Fact]public void MixedRoutesArePartial()=>Assert.Equal(VpnState.Partial,ProfilePolicy.Evaluate(Good with{AllRoutesSelected=false}).State);
    [Fact]public void RouteBypassIsDisconnected()=>Assert.Equal(VpnState.Disconnected,ProfilePolicy.Evaluate(Good with{AllRoutesSelected=false,SomeRoutesSelected=false}).State);
    [Fact]public void LostProfileTunnelIsDisconnected()=>Assert.Equal(VpnState.Disconnected,ProfilePolicy.Evaluate(Good with{SelectedUp=false}).State);
    [Fact]public void IpRotationNeedsSecondConfirmation()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{IpChangeConfirmed=false}).State);
    [Fact]public void ConfirmedRotationRemainsProtected()=>Assert.Equal(VpnState.Protected,ProfilePolicy.Evaluate(Good with{IpChangeConfirmed=true}).State);
    [Fact]public void ProxyCannotBeGuaranteed()=>Assert.Equal(VpnState.Unknown,ProfilePolicy.Evaluate(Good with{Proxy=true}).State);
    [Theory][InlineData("Ethernet-WFP Native MAC Layer LightWeight Filter-0000")][InlineData("Ethernet-QoS Packet Scheduler-0000")][InlineData("Kernel Debug Ethernet")]
    public void ServiceInterfacesAreHidden(string name)=>Assert.False(AdapterClassifier.IsVisible(Adapter(name)));
    [Theory][InlineData("AmneziaWG")][InlineData("WireGuard Tunnel")][InlineData("OpenVPN TAP-Windows")][InlineData("Wintun")]
    public void EthernetTunnelsAreRecognized(string name)=>Assert.True(AdapterClassifier.IsTunnel(Adapter(name)));
    [Fact]public void PlainEthernetIsNotAutomaticallyVpn()=>Assert.False(AdapterClassifier.IsTunnel(Adapter("Ethernet")));
    [Fact]public void PhysicalEthernetCannotBeConfirmedAsManualVpn()=>Assert.False(AdapterClassifier.IsManualTunnel(Adapter("Ethernet") with{HardwareInterface=true}));
    [Fact]public void VirtualEthernetCanBeManuallyConfirmed()=>Assert.True(AdapterClassifier.IsManualTunnel(Adapter("Ethernet") with{HardwareInterface=false}));
    [Fact]public void NativeFilterFlagHidesRenamedFilter()=>Assert.False(AdapterClassifier.IsVisible(Adapter("Ordinary name") with{FilterInterface=true}));
    [Fact]public void AnonymousPppIsTunnel()=>Assert.True(AdapterClassifier.IsTunnel(Adapter("Connection","Ppp")));
    [Fact]public void InterfacesNeedRealIndex()=>Assert.False(AdapterClassifier.IsVisible(Adapter("WireGuard") with{Index4=0,Index6=0}));
    [Fact]public void MultipleTunnelsNeedRoutingOrManualChoice()
    {var a=Adapter("WireGuard1");var b=Adapter("WireGuard2") with{Index4=8,Index6=8};Assert.Null(AdapterClassifier.Select([a,b],new(),[]));Assert.Equal(b,AdapterClassifier.Select([a,b],new(),[8]));}
    [Fact]public void SavedProfileIsNotReplacedByAnotherTunnel()
    {var a=Adapter("WireGuard1");var b=Adapter("WireGuard2");var s=new AppSettings{VpnProfile=new("missing","old",null,null,DateTimeOffset.UtcNow)};Assert.Null(AdapterClassifier.Select([a,b],s,[7]));}
    [Theory][InlineData("http://example.com")][InlineData("https://user:password@example.com")][InlineData("https://example.com?token=secret")][InlineData("https://example.com/#secret")]
    public void SensitiveOrNonHttpsSiteIsRejected(string url)=>Assert.Throws<ArgumentException>(()=>SiteTarget.Normalize(url));
    [Theory][InlineData(double.NaN)][InlineData(double.PositiveInfinity)][InlineData(300)][InlineData(-100)]
    public void InvalidTemperatureIsNull(double value)=>Assert.Null(SensorValues.Validate(SensorKind.Temperature,value));
    [Fact]public void MissingTemperatureIsNull()=>Assert.Null(SensorValues.Validate(SensorKind.Temperature,null));
    [Fact]public void GenuineIdleGpuMayBeZero()=>Assert.Equal(0d,SensorValues.Validate(SensorKind.Utilization,0));
    [Fact]public void WidgetIsNotForcedTopmost()=>Assert.False(new WidgetSettings().Topmost);
    [Fact]public void DisconnectedMonitorClampsPosition()
    {var r=WidgetPlacement.Place(new(0,0,1920,1040),new(-2000,2000,320,230),"None");Assert.Equal(new WidgetBounds(0,810,320,230),r);}
    [Fact]public void DockWorksOnNegativeCoordinateMonitor()
    {var r=WidgetPlacement.Place(new(-1920,0,1920,1040),new(20,20,320,230),"TopRight");Assert.Equal(-332,r.Left);Assert.Equal(12,r.Top);}
    [Fact]public void OversizedWidgetRemainsInWorkArea()
    {Assert.Equal(new WidgetBounds(0,0,200,150),WidgetPlacement.Place(new(0,0,200,150),new(0,0,320,230),"BottomRight"));}
    [Fact]public void TemperatureThresholdsAreDeviceSpecific()
    {
        var rules=new TemperatureRules();var s=new AppSettings();var now=DateTimeOffset.UtcNow;
        SensorReading R(string type,DateTimeOffset at)=>new(type,type,type,SensorKind.Temperature,"Temperature",80,"°C","test",at,SensorStatus.Available);
        Assert.Null(rules.Check(R("GPU",now),s));Assert.Null(rules.Check(R("GPU",now.AddSeconds(60)),s));
        Assert.Null(rules.Check(R("SSD",now),s));Assert.NotNull(rules.Check(R("SSD",now.AddSeconds(60)),s));
    }
}
