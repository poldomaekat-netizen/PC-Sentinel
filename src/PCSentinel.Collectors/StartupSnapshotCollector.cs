using Microsoft.Win32;
using PCSentinel.Core;
namespace PCSentinel.Collectors;
public sealed class StartupSnapshotCollector
{
    public string Status {get;private set;}="";
    public HashSet<string> AccessibleLocations {get;}=[];
    public IReadOnlyList<StartupEntry> Read()
    {
        AccessibleLocations.Clear();var result=new List<StartupEntry>();var denied=new List<string>();
        foreach(var hive in new[]{RegistryHive.CurrentUser,RegistryHive.LocalMachine})foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            var location=$"{hive}/{view}/Run";
            try
            {
                using var root=RegistryKey.OpenBaseKey(hive,view);using var key=root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run",false);
                AccessibleLocations.Add(location);if(key==null)continue;
                foreach(var name in key.GetValueNames())
                {
                    // Keep executable target only; never persist startup command arguments/tokens.
                    var raw=key.GetValue(name,"",RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString()??"";
                    result.Add(new(location+"/"+name,location,name,TargetOnly(raw)));
                }
            }catch(Exception e) when(e is UnauthorizedAccessException or System.Security.SecurityException or IOException){denied.Add(location);}
        }
        foreach(var folder in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Startup),Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)}.Where(x=>x.Length>0))
        {
            try{var files=Directory.Exists(folder)?Directory.GetFiles(folder):[];foreach(var f in files.Take(300))result.Add(new(f,folder,Path.GetFileName(f),f+" [modified "+File.GetLastWriteTimeUtc(f).ToString("O")+"]"));AccessibleLocations.Add(folder);}
            catch(Exception e) when(e is IOException or UnauthorizedAccessException){denied.Add(folder);}
        }
        Status=$"Read-only Run/Startup: {result.Count}; {(denied.Count==0?"доступны":string.Join(", ",denied)+" — нет доступа")}. Планировщик задач не опрашивается. Аргументы Run не сохраняются; изменения только аргументов не отслеживаются.";
        return result;
    }
    public static string TargetOnly(string command)
    {
        var text=Environment.ExpandEnvironmentVariables(command.Trim());
        if(text.StartsWith('"')){var end=text.IndexOf('"',1);return end>0?text[1..end]:"[Некорректная кавычка]";}
        var exe=text.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);if(exe>=0)return text[..(exe+4)];
        var split=text.IndexOf(' ');return split>=0?text[..split]:text;
    }
    public static IReadOnlyList<StartupEntry> Changes(IEnumerable<StartupEntry> previous,IEnumerable<StartupEntry> current)
    {
        var old=previous.ToDictionary(x=>x.Id);var next=current.ToDictionary(x=>x.Id);
        return next.Values.Where(x=>!old.TryGetValue(x.Id,out var p)||p.Target!=x.Target).Concat(old.Values.Where(x=>!next.ContainsKey(x.Id)).Select(x=>x with{Target="Удалена: "+x.Target})).ToArray();
    }
}
