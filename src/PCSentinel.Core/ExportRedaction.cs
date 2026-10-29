using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
namespace PCSentinel.Core;

public static class ExportRedaction
{
    public static string HideUncPaths(string text)=>HideUncPaths(text,0);
    private static string HideUncPaths(string text,int depth)
    {
        if(!text.Contains(@"\\",StringComparison.Ordinal))return text;
        var trimmed=text.TrimStart();
        if(depth<4 && (trimmed.StartsWith('{') || trimmed.StartsWith('[')))
        {
            try
            {
                var node=JsonNode.Parse(text)!;
                void Walk(JsonNode? n)
                {
                    if(n is JsonObject obj)foreach(var entry in obj.ToArray())
                    {if(entry.Value is JsonValue value && value.TryGetValue<string>(out var content))obj[entry.Key]=HideUncPaths(content,depth+1);else Walk(entry.Value);}
                    else if(n is JsonArray array)for(var i=0;i<array.Count;i++)
                    {if(array[i] is JsonValue value && value.TryGetValue<string>(out var content))array[i]=HideUncPaths(content,depth+1);else Walk(array[i]);}
                }
                Walk(node);return node.ToJsonString();
            }
            catch(JsonException){}
        }
        return Regex.Replace(text,@"\\\\[^\r\n\""<>]*","[путь скрыт]");
    }
    public static string Apply(string text,bool includePaths,bool includeIps,string userName)
    {
        if(!includePaths)
        {
            // Covers ordinary UNC, extended UNC, device paths and drive paths before the username pass.
            text=HideUncPaths(text);
            text=Regex.Replace(text,@"[A-Za-z]:\\[^\r\n\""<>]*","[путь скрыт]");
            if(!string.IsNullOrWhiteSpace(userName))text=text.Replace(userName,"[пользователь]",StringComparison.OrdinalIgnoreCase);
        }
        if(!includeIps)
        {
            text=Regex.Replace(text,@"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])","[IP скрыт]");
            text=Regex.Replace(text,@"(?i)(?<!\w)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,39}(?!\w)","[IPv6 скрыт]");
        }
        return text;
    }
}
