using PCSentinel.Collectors;
using Xunit;
namespace PCSentinel.IntegrationTests;
public sealed class InstallerSecurityTests
{
    [Theory][InlineData(@"C:\Users\Alice\PC Sentinel")][InlineData(@"\\server\PC Sentinel")][InlineData(@"C:\Program Files\PC Sentinel-Other")][InlineData(@"C:\Program Files\PC Sentinel\..\Other")]
    public void UntrustedLocationsAreRejected(string path)=>Assert.False(ProtectedInstall.IsExpectedDirectory(path,@"C:\Program Files\PC Sentinel"));
    [Fact]public void ExactProtectedDirectoryIsRecognized()=>Assert.True(ProtectedInstall.IsExpectedDirectory(@"C:\Program Files\PC Sentinel\",@"C:\Program Files\PC Sentinel"));
    [Fact]public void ServiceCommandMustBeExact()
    {Assert.True(SensorServiceControl.IsExpectedBinary($"\"{SensorServiceControl.Executable}\" --service"));Assert.False(SensorServiceControl.IsExpectedBinary($"\"{SensorServiceControl.Executable}\" --service --other"));Assert.False(SensorServiceControl.IsExpectedBinary("C:\\Users\\Alice\\evil.exe --service"));}
    [Fact]public void DevelopmentTreeCannotOpenPrivilegedModules()=>Assert.False(ProtectedInstall.CheckCurrent(out _));
    [Fact]public void MissingInstallationIsNotMisreportedAsReparsePoint()
    {Assert.False(ProtectedInstall.CheckTree(Path.Combine(Path.GetTempPath(),"PCSentinel-Missing-"+Guid.NewGuid().ToString("N")),out var reason));Assert.DoesNotContain("Reparse point",reason);}
    [Fact]public void AmdTctlRangeCorrectionsAreApplied()
    {Assert.Equal(65,AmdTemperatureProvider.Decode(520u<<21));Assert.Equal(65,AmdTemperatureProvider.Decode((912u<<21)|(1u<<19)));Assert.Equal(65,AmdTemperatureProvider.Decode((912u<<21)|(3u<<16)));}
    [Theory][InlineData(0u)][InlineData(uint.MaxValue)][InlineData(2047u<<21)]
    public void InvalidAmdValuesAreMissing(uint raw)=>Assert.Null(AmdTemperatureProvider.Decode(raw));
}
