using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PCSentinel.Collectors;

public static class ProtectedInstall
{
    public static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"PC Sentinel");
    private static readonly HashSet<string> TrustedOwners=["S-1-5-18","S-1-5-32-544","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
    public static bool IsExpectedDirectory(string directory,string root)=>
        !directory.StartsWith(@"\\",StringComparison.Ordinal) && string.Equals(Path.GetFullPath(directory).TrimEnd('\\'),Path.GetFullPath(root).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);
    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("SingleFile","IL3000",Justification="An empty entry-assembly Location intentionally rejects privileged access from a single-file executable.")]
    public static bool CheckCurrent(out string reason)
    {
        reason="Привилегированные датчики доступны только в защищённой folder-установке в Program Files.";
        if(string.IsNullOrEmpty(Assembly.GetEntryAssembly()?.Location) || !(IsExpectedDirectory(AppContext.BaseDirectory,Root) || IsExpectedDirectory(AppContext.BaseDirectory,Path.Combine(Root,"Service"))))return false;
        return CheckTree(Root,out reason);
    }
    public static bool CheckTree(string root,out string reason)
    {
        reason="";
        try
        {
            CheckAcl(new DirectoryInfo(Path.GetDirectoryName(root)!));
            CheckAcl(new DirectoryInfo(root));
            var pending=new Stack<string>();pending.Push(root);
            while(pending.Count>0)foreach(var path in Directory.EnumerateFileSystemEntries(pending.Pop()))
            {
                if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point: "+path);
                CheckAcl(Directory.Exists(path)?new DirectoryInfo(path):new FileInfo(path));
                if(Directory.Exists(path))pending.Push(path);
            }
            return true;
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or System.Security.SecurityException){reason=e.Message;return false;}
    }
    private static void CheckAcl(FileSystemInfo entry)
    {
        if(!entry.Exists)throw new DirectoryNotFoundException("Отсутствует каталог/файл установки: "+entry.Name);
        if((entry.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point: "+entry.Name);
        FileSystemSecurity acl=entry is DirectoryInfo directory?directory.GetAccessControl():((FileInfo)entry).GetAccessControl();
        if(!TrustedOwners.Contains(acl.GetOwner(typeof(SecurityIdentifier))!.Value))throw new UnauthorizedAccessException("Незащищённый владелец: "+entry.Name);
        const FileSystemRights write=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.WriteExtendedAttributes|FileSystemRights.WriteAttributes|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && (rule.PropagationFlags&PropagationFlags.InheritOnly)==0 && (rule.FileSystemRights&write)!=0 && !TrustedOwners.Contains(rule.IdentityReference.Value))
                throw new UnauthorizedAccessException("Запись разрешена непривилегированной учётной записи: "+entry.Name);
    }
}
