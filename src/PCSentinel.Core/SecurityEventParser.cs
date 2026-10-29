using System.Xml.Linq;
namespace PCSentinel.Core;
public static class SecurityEventParser
{
    public static SecurityEvent? Parse(string channel,string xml)
    {
        var doc=XDocument.Parse(xml);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";var sys=doc.Root?.Element(ns+"System");
        if(!int.TryParse(sys?.Element(ns+"EventID")?.Value,out var id)||!long.TryParse(sys?.Element(ns+"EventRecordID")?.Value,out var record)||!DateTimeOffset.TryParse(sys?.Element(ns+"TimeCreated")?.Attribute("SystemTime")?.Value,out var time))return null;
        var defender=channel=="Microsoft-Windows-Windows Defender/Operational";var sysmon=channel=="Microsoft-Windows-Sysmon/Operational";
        if(!defender && !sysmon || defender && id is not (1116 or 1117 or 1118) || sysmon && id is not (1 or 3 or 5))return null;
        var allowed=new HashSet<string>(["Threat Name","Threat ID","Severity Name","Category Name","Action Name","Error Code","Process Name","Path","Image","ProcessId","ProcessGuid","ParentImage","ParentProcessId","DestinationIp","DestinationPort","Protocol","Signed","Signature","SignatureStatus"]);
        var fields=new Dictionary<string,string>();
        foreach(var data in doc.Descendants(ns+"Data"))
        {
            var name=data.Attribute("Name")?.Value??"";if(!allowed.Contains(name))continue;
            var value=System.Text.RegularExpressions.Regex.Replace(data.Value,@"(?i)(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s;,]+","$1=[скрыто]");fields[name]=value.Length>1000?value[..1000]:value;
        }
        var label=defender?id switch{1116=>"Обнаружение Microsoft Defender",1117=>"Действие Microsoft Defender (не обязательно лечение)",_=>"Ошибка действия Microsoft Defender"}:$"Sysmon {id}: дополнительная телеметрия";
        return new(channel,record,id,time,label,fields);
    }
}
