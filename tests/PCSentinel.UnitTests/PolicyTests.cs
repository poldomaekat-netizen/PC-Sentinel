using PCSentinel.Core;
using PCSentinel.Network;
using PCSentinel.Diagnostics;
using Xunit;

namespace PCSentinel.UnitTests;

public sealed class PolicyTests
{
    private static VpnEvidence Good => new(true, true, true, true, true, true, true, false, "203.0.113.7", "2001:db8::7", "203.0.113.0/24,2001:db8::/32");
    [Fact] public void CpuIncludesIdleInKernel() => Assert.Equal(75d, MetricsMath.Cpu(100, 200, 100, 150, 300, 200));
    [Fact] public void CpuResetIsUnavailable() => Assert.Null(MetricsMath.Cpu(200, 300, 200, 100, 100, 100));
    [Fact] public void ZeroIntervalIsUnavailable() => Assert.Null(MetricsMath.Cpu(1,2,3,1,2,3));
    [Fact] public void ProcessCpuIsNormalizedAcrossCores() => Assert.Equal(25d, MetricsMath.ProcessCpu(1000,1000,4));
    [Fact] public void MissingFirstProcessSampleIsUnavailable() => Assert.Null(MetricsMath.ProcessCpu(100,0,4));
    [Theory]
    [InlineData("203.0.113.0/24","203.0.113.255",true)]
    [InlineData("203.0.113.0/24","203.0.114.1",false)]
    [InlineData("2001:db8::/32","2001:db8:abcd::1",true)]
    [InlineData("2001:db8::/32","2001:db9::1",false)]
    [InlineData("203.0.113.7","203.0.113.8",false)]
    [InlineData("0.0.0.0/0","1.2.3.4",true)]
    [InlineData("::/0","1.2.3.4",false)]
    public void CidrComparison(string rule, string ip, bool expected) => Assert.Equal(expected, IpRange.Contains(rule, ip));
    [Fact] public void RejectsInvalidCidr() => Assert.Throws<ArgumentException>(() => new AppSettings { ApprovedIps = "203.0.113.0/33" }.Validate());
    [Fact] public void RejectsReversedThresholds() => Assert.Throws<ArgumentException>(() => new AppSettings { WarningThreshold = 90, CriticalThreshold = 80 }.Validate());
    [Fact] public void ProtectedRequiresAllEvidence() => Assert.Equal(VpnState.Protected, VpnPolicy.Evaluate(Good).State);
    [Fact] public void ServiceFailureIsUnknown() => Assert.Equal(VpnState.Unknown, VpnPolicy.Evaluate(Good with { ChecksAgree4 = false }).State);
    [Fact] public void MissingIpv6ConfirmationCannotBeProtected() => Assert.Equal(VpnState.Unknown, VpnPolicy.Evaluate(Good with { ChecksAgree6 = false }).State);
    [Fact] public void ProxyCannotBePromisedProtected() => Assert.Equal(VpnState.Unknown, VpnPolicy.Evaluate(Good with { Proxy = true }).State);
    [Fact] public void MissingRouteIsUnknown() => Assert.Equal(VpnState.Unknown, VpnPolicy.Evaluate(Good with { RoutesKnown = false }).State);
    [Fact] public void PartialRoutingIsExplicit() { var r = VpnPolicy.Evaluate(Good with { AllRoutesSelected = false }); Assert.Equal(VpnState.Unprotected,r.State); Assert.Contains("Частичная",r.Reason); }
    [Fact] public void WrongIpIsUnprotected() => Assert.Equal(VpnState.Unprotected, VpnPolicy.Evaluate(Good with { Ip4 = "198.51.100.1" }).State);
    [Fact] public void NoBaselineIsUnknown() => Assert.Equal(VpnState.Unknown, VpnPolicy.Evaluate(Good with { ApprovedIps = "" }).State);
    [Fact] public void OfflineIsSeparate() => Assert.Equal(VpnState.Offline, VpnPolicy.Evaluate(Good with { Online = false }).State);
    [Fact] public void NoIpv6DoesNotRequireIpv6Answers() => Assert.Equal(VpnState.Protected, VpnPolicy.Evaluate(Good with { HasIpv6 = false, ChecksAgree6 = false, Ip6 = null }).State);
    [Fact] public void ShortPeakDoesNotNotify()
    {
        var rules = new AlertRules(); var now = DateTimeOffset.UtcNow; var s = new AppSettings();
        Assert.Null(rules.Check("CPU",90,now,s)); Assert.Null(rules.Check("CPU",90,now.AddSeconds(14),s));
        Assert.Null(rules.Check("CPU",10,now.AddSeconds(15),s)); Assert.Null(rules.Check("CPU",90,now.AddSeconds(16),s));
    }
    [Fact] public void SustainedPeakNotifiesWithCooldown()
    {
        var rules = new AlertRules(); var now = DateTimeOffset.UtcNow; var s = new AppSettings();
        rules.Check("CPU",90,now,s); Assert.NotNull(rules.Check("CPU",90,now.AddSeconds(15),s));
        Assert.Null(rules.Check("CPU",99,now.AddSeconds(30),s)); Assert.NotNull(rules.Check("CPU",99,now.AddSeconds(315),s));
    }
    [Fact] public void MissingMetricResetsDuration()
    {
        var rules = new AlertRules(); var now = DateTimeOffset.UtcNow; var s = new AppSettings();
        rules.Check("CPU",90,now,s); rules.Check("CPU",null,now.AddSeconds(10),s);
        Assert.Null(rules.Check("CPU",90,now.AddSeconds(20),s));
    }
}
