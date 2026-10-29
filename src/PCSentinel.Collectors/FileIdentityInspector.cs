using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PCSentinel.Core;
namespace PCSentinel.Collectors;
public sealed class FileIdentityInspector
{
    private readonly Dictionary<string,(string? Publisher,string Signature,string? Hash)> _cache=new(StringComparer.OrdinalIgnoreCase);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct FileInfoNative{public uint Size;[MarshalAs(UnmanagedType.LPWStr)]public string File;public IntPtr Handle,Subject;}
    [StructLayout(LayoutKind.Sequential)]private struct TrustData{public uint Size;public IntPtr Policy,Sip;public uint Ui,Revocation,Choice;public IntPtr File;public uint StateAction;public IntPtr StateData,Url;public uint Flags,Context;}
    [DllImport("wintrust.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]private static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref TrustData data);
    public IncidentProcess Inspect(IncidentProcess item)
    {
        var path=item.Sample.Path;if(path==null)return item with{Signature="Путь недоступен"};
        string cacheKey=path;
        string? publisher=null,hash=null;var signature="Недоступна";
        try
        {
            var file=new FileInfo(path);if(!file.Exists)return item with{Signature="Файл отсутствует"};
            cacheKey=$"{path}|{file.Length}|{file.LastWriteTimeUtc.Ticks}";
            if(_cache.TryGetValue(cacheKey,out var known))return item with{Publisher=known.Publisher,Signature=known.Signature,Sha256=known.Hash};
            // At most one bounded file per incident processing step. No revocation/network retrieval.
            if(file.Length<=100*1024*1024){using var stream=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);hash=Convert.ToHexString(SHA256.HashData(stream));}
            var info=new FileInfoNative{Size=(uint)Marshal.SizeOf<FileInfoNative>(),File=path};var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<FileInfoNative>());
            try
            {
                Marshal.StructureToPtr(info,pointer,false);var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),Ui=2,Choice=1,File=pointer,Flags=0x1000};var guid=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");var code=WinVerifyTrust(new IntPtr(-1),ref guid,ref data);
                signature=code==0?"Подпись доверена (локальный кеш)":$"Не подтверждена / отсутствует: 0x{code:X8}";
                if(code==0)
                {
#pragma warning disable SYSLIB0057
                    using var cert=new X509Certificate2(X509Certificate.CreateFromSignedFile(path));publisher=cert.GetNameInfo(X509NameType.SimpleName,false);
#pragma warning restore SYSLIB0057
                }
            }
            finally{Marshal.DestroyStructure<FileInfoNative>(pointer);Marshal.FreeHGlobal(pointer);}
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or CryptographicException){signature="Недоступна: "+e.GetType().Name;}
        if(_cache.Count>=128)_cache.Clear();_cache[cacheKey]=(publisher,signature,hash);
        return item with{Publisher=publisher,Signature=signature,Sha256=hash};
    }
}
