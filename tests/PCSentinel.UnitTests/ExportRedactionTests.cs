using PCSentinel.Core;
using Xunit;
namespace PCSentinel.UnitTests;
public sealed class ExportRedactionTests
{
    [Theory][InlineData(@"\\server\private\file.txt")][InlineData(@"\\?\UNC\server\private\file.txt")][InlineData(@"C:\Users\Alice\file.txt")][InlineData(@"\\192.168.1.2\share\secret")]
    public void PrivatePathsAreHiddenByDefault(string path)
    {var result=ExportRedaction.Apply("source="+path,false,false,"Alice");Assert.DoesNotContain("private",result);Assert.DoesNotContain("file.txt",result);Assert.DoesNotContain("secret",result);Assert.Contains("[путь скрыт]",result);}
    [Fact]public void ExplicitOptInPreservesUncPath()=>Assert.Equal(@"\\server\share\a.txt",ExportRedaction.Apply(@"\\server\share\a.txt",true,true,"Alice"));
    [Fact]public void IpAndUsernameAreHidden()=>Assert.Equal("[пользователь] [IP скрыт]",ExportRedaction.Apply("Alice 192.168.0.1",false,false,"Alice"));
    [Fact]public void WebUrlIsNotMistakenForUnc()=>Assert.Equal("https://example.com/page",ExportRedaction.Apply("https://example.com/page",false,false,"Alice"));
    [Fact]public void NestedMetadataRemainsValidJsonAfterUncRedaction()
    {
        var raw=System.Text.Json.JsonSerializer.Serialize(new{Path=@"\\server\secret\file.txt",Label="retained"});
        using var json=System.Text.Json.JsonDocument.Parse(ExportRedaction.HideUncPaths(raw));
        Assert.Equal("[путь скрыт]",json.RootElement.GetProperty("Path").GetString());Assert.Equal("retained",json.RootElement.GetProperty("Label").GetString());
    }
}
