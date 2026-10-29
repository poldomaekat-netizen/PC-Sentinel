using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using PCSentinel.Core;
namespace PCSentinel.App;
public sealed class SecurityEventProvider
{
    public const string Defender="Microsoft-Windows-Windows Defender/Operational",Sysmon="Microsoft-Windows-Sysmon/Operational";
    public string Status {get;private set;}="Источник не опрашивался";
    public IReadOnlyList<SecurityEvent> Read(string channel,long afterRecordId,CancellationToken token)
    {
        var result=new List<SecurityEvent>();
        try
        {
            var ids=channel==Defender?"(EventID=1116 or EventID=1117 or EventID=1118)":"(EventID=1 or EventID=3 or EventID=5)";
            var query=$"*[System[{ids} and EventRecordID > {Math.Max(0,afterRecordId)} and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
            using var reader=new EventLogReader(new EventLogQuery(channel,PathType.LogName,query){ReverseDirection=false});
            for(var n=0;n<100 && !token.IsCancellationRequested;n++)
            {
                using var record=reader.ReadEvent(TimeSpan.FromSeconds(2));if(record==null)break;
                if(SecurityEventParser.Parse(channel,record.ToXml()) is {} e)result.Add(e);
            }
            Status=$"{channel}: доступен, {result.Count} новых событий (только последние 24 часа, до 100 за проход).";
        }
        catch(Exception e) when(e is EventLogException or UnauthorizedAccessException or System.Security.SecurityException){Status=$"{channel}: недоступен ({e.GetType().Name}); источник не включается и права не повышаются.";}
        return result;
    }
}
