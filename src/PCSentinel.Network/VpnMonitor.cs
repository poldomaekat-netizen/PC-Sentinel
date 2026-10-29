using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PCSentinel.Core;

namespace PCSentinel.Network;

public static class AdapterClassifier
{
    public static bool IsService(AdapterInfo a) => a.FilterInterface==true || a.Kind is "Loopback" or "Unknown" ||
        new[] { "WFP", "QoS", "Packet Scheduler", "LightWeight Filter", "MAC Layer", "Kernel Debug", "Miniport (Network Monitor)" }
        .Any(s => (a.Name+" "+a.Description).Contains(s,StringComparison.OrdinalIgnoreCase));
    public static bool IsTunnel(AdapterInfo a) => !IsService(a) && (a.Kind is "Ppp" or "Tunnel" ||
        new[] { "Amnezia", "WireGuard", "Wintun", "OpenVPN", "TAP-Windows", "VPN", "TUN Adapter" }.Any(s=>(a.Name+" "+a.Description).Contains(s,StringComparison.OrdinalIgnoreCase)));
    public static bool IsVisible(AdapterInfo a) => !IsService(a) && !a.Description.Contains("Wi-Fi Direct Virtual",StringComparison.OrdinalIgnoreCase) &&
        (!a.Description.Contains("Bluetooth",StringComparison.OrdinalIgnoreCase) || a.Up) && (a.Index4>0 || a.Index6>0) && (a.HasIp || IsTunnel(a) || a.Kind is "Ethernet" or "Wireless80211");
    public static bool IsManualTunnel(AdapterInfo a)=>IsTunnel(a) || IsVisible(a) && a.HardwareInterface==false;
    public static AdapterInfo? Select(IReadOnlyList<AdapterInfo> all,AppSettings s,IReadOnlyList<int> routeIndices)
    {
        if(!s.AutoDetectVpn) return all.FirstOrDefault(a=>a.Id==s.PreferredAdapterId && IsVisible(a));
        if(s.VpnProfile!=null) return all.FirstOrDefault(a=>a.Id==s.VpnProfile.AdapterId && IsVisible(a));
        var candidates=all.Where(a=>a.Up && a.HasIp && IsTunnel(a)).ToArray();
        var routed=candidates.Where(a=>routeIndices.Any(i=>i>0 && (i==a.Index4 || i==a.Index6))).ToArray();
        return routed.Length==1 ? routed[0] : candidates.Length==1 ? candidates[0] : null;
    }
}
public sealed record ProfileEvidence(bool Online,bool Agree4,bool Agree6,bool HasIpv6,bool SelectedUp,
    bool AllRoutesSelected,bool SomeRoutesSelected,bool RoutesKnown,bool Proxy,bool ProfileMatches,
    bool TunnelKnown,bool IpChangeConfirmed,bool HasProfile);
public static class ProfilePolicy
{
    public static (VpnState State,string Reason) Evaluate(ProfileEvidence e)
    {
        if(!e.Online) return (VpnState.Offline,"Windows сообщает: нет активного сетевого подключения.");
        if(e.HasProfile && !e.SelectedUp) return (VpnState.Disconnected,"Сохранённый VPN-туннель отключён или отсутствует.");
        if(e.Proxy) return (VpnState.Unknown,"Обнаружен proxy среды или Windows: маршрут HTTPS нельзя достоверно связать с VPN-туннелем.");
        if(e.RoutesKnown && e.SomeRoutesSelected && !e.AllRoutesSelected) return (VpnState.Partial,"Частичная маршрутизация: часть проверенных назначений проходит вне туннеля.");
        if(!e.Agree4 || e.HasIpv6 && !e.Agree6) return (VpnState.Unknown,"Два IP-сервиса не дали согласованных ответов для каждой доступной семьи IP. Смотрите IPv4 и IPv6 отдельно.");
        if(!e.RoutesKnown) return (VpnState.Unknown,"Не удалось проверить все контрольные маршруты.");
        if(e.HasProfile && !e.AllRoutesSelected) return (VpnState.Disconnected,"Контрольные маршруты обходят сохранённый VPN-туннель.");
        if(!e.TunnelKnown || !e.SelectedUp) return (VpnState.Unknown,"VPN не определён однозначно. Выберите подключение вручную в мастере.");
        if(!e.HasProfile) return (VpnState.Unknown,"Туннель найден. Подключите VPN и запомните соединение в мастере настроек.");
        if(!e.ProfileMatches) return (VpnState.Unknown,"Подключение отличается от сохранённого профиля. Проверьте и обновите профиль.");
        if(!e.IpChangeConfirmed) return (VpnState.Unknown,"Выходной IP изменился. Ожидается повторная проверка IP и маршрутов; обрыв VPN ещё не подтверждён.");
        return (VpnState.Protected,"Профиль, туннель и контрольные маршруты подтверждены. Правила отдельных приложений и все назначения не проверяются.");
    }
}
public sealed class VpnMonitor : IDisposable
{
    private readonly HttpClient _v4=VpnGuard.CreateClient(AddressFamily.InterNetwork),_v6=VpnGuard.CreateClient(AddressFamily.InterNetworkV6);
    private readonly HttpClient _sites=new(new SocketsHttpHandler { AllowAutoRedirect=false,UseCookies=false,Credentials=null,ConnectTimeout=TimeSpan.FromSeconds(4) }) { Timeout=TimeSpan.FromSeconds(6) };
    private static readonly string[] Urls4=["https://api.ipify.org","https://ipv4.icanhazip.com"],Urls6=["https://api6.ipify.org","https://ipv6.icanhazip.com"];
    private (string? Adapter,string? Ip4,string? Ip6,DateTimeOffset At)? _lastGood;
    public async Task<SiteCheckResult> CheckSiteAsync(string url,CancellationToken ct)
    {
        url=SiteTarget.Normalize(url); double? dns=null; var clock=Stopwatch.StartNew();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(6));
        try
        {
            await Dns.GetHostAddressesAsync(new Uri(url).Host,timeout.Token); dns=clock.Elapsed.TotalMilliseconds; clock.Restart();
            using var request=new HttpRequestMessage(HttpMethod.Head,url);
            using var response=await _sites.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            return new(url,dns,clock.Elapsed.TotalMilliseconds,(int)response.StatusCode,"HTTPS отвечает",DateTimeOffset.UtcNow);
        }
        catch(Exception e) when(e is HttpRequestException or SocketException or OperationCanceledException or IOException)
        { return new(url,dns,null,null,e is OperationCanceledException?"Тайм-аут / отмена":"Недоступен: "+e.GetType().Name,DateTimeOffset.UtcNow); }
    }
    public async Task<NetworkCheck> CheckAsync(AppSettings s,CancellationToken ct)
    {
        var now=DateTimeOffset.UtcNow;
        if(!s.EnablePublicIp && !s.EnableSiteChecks) return new(now,null,null,VpnState.Unknown,"—","Проверки сети выключены. Включите их в настройках; внешние сервисы видят исходящий IP.");
        if(!NetworkInterface.GetIsNetworkAvailable()) return new(now,null,null,VpnState.Offline,"—","Нет активного подключения Windows.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15));
        var siteResults=Task.WhenAll(s.EnableSiteChecks?s.ControlSites.Where(x=>x.Enabled).Take(12).Select(x=>CheckSiteAsync(x.Url,timeout.Token)):[]);
        if(!s.EnablePublicIp) return new(now,null,null,VpnState.Unknown,"—","Проверены только сайты. Их доступность не доказывает VPN.",Sites:await siteResults);
        var adapters=VpnGuard.GetAdapters(); var has6=adapters.Any(a=>a.Up && a.HasIpv6 && AdapterClassifier.IsVisible(a));
        var task4=Task.WhenAll(Urls4.Select(u=>VpnGuard.PublicIp(_v4,u,AddressFamily.InterNetwork,timeout.Token)));
        var task6=Task.WhenAll(has6?Urls6.Select(u=>VpnGuard.PublicIp(_v6,u,AddressFamily.InterNetworkV6,timeout.Token)):[]);
        var probes=new List<IPAddress>{IPAddress.Parse("1.1.1.1"),IPAddress.Parse("8.8.8.8")};
        if(has6) probes.AddRange([IPAddress.Parse("2606:4700:4700::1111"),IPAddress.Parse("2001:4860:4860::8888")]);
        var hosts=Urls4.Concat(has6?Urls6:[]).Select(u=>new Uri(u).Host).Concat(s.ControlSites.Where(x=>s.EnableSiteChecks && x.Enabled).Select(x=>new Uri(x.Url).Host)).Distinct();
        var lookups=hosts.Select(async host=>{try{return await Dns.GetHostAddressesAsync(host,timeout.Token);}catch(Exception e) when(e is SocketException or OperationCanceledException){return Array.Empty<IPAddress>();}}).ToArray();
        var known=true;
        foreach(var addresses in await Task.WhenAll(lookups)){if(addresses.Length==0)known=false;probes.AddRange(addresses);}
        var routes=probes.Distinct().Where(a=>has6 || a.AddressFamily==AddressFamily.InterNetwork).Select(a=>(Address:a,Index:VpnGuard.Route(a))).ToArray();
        known &= routes.All(r=>r.Index is >0);
        var selected=AdapterClassifier.Select(adapters,s,routes.Where(r=>r.Index.HasValue).Select(r=>r.Index!.Value).ToArray());
        bool Matches((IPAddress Address,int? Index) r)=>r.Index is >0 && r.Index==(r.Address.AddressFamily==AddressFamily.InterNetwork?selected?.Index4:selected?.Index6);
        var all=routes.Length>0 && routes.All(Matches); var some=routes.Any(Matches);
        var ipv4=await task4; var ipv6=await task6;
        var agree4=ipv4.Length==2 && ipv4[0]!=null && ipv4[0]==ipv4[1]; var agree6=ipv6.Length==2 && ipv6[0]!=null && ipv6[0]==ipv6[1];
        var ip4=agree4?ipv4[0]:null; var ip6=agree6?ipv6[0]:null;
        var proxy=Urls4.Concat(has6?Urls6:[]).Any(u=>!HttpClient.DefaultProxy.IsBypassed(new Uri(u)));
        var profile=s.VpnProfile; var matches=profile!=null && selected?.Id==profile.AdapterId && selected.Description==profile.AdapterDescription;
        var changed=profile!=null && (profile.BaselineIp4!=ip4 || has6 && profile.BaselineIp6!=ip6);
        var confirmed=!changed || _lastGood is {} previous && previous.Adapter==selected?.Id && previous.Ip4==ip4 && previous.Ip6==ip6 && now-previous.At>=TimeSpan.FromSeconds(5) && now-previous.At<=TimeSpan.FromMinutes(15);
        var tunnel=selected!=null && (AdapterClassifier.IsTunnel(selected) || !s.AutoDetectVpn && AdapterClassifier.IsManualTunnel(selected));
        var decision=ProfilePolicy.Evaluate(new(true,agree4,agree6,has6,selected?.Up==true,all,some,known,proxy,matches,tunnel,confirmed,profile!=null));
        if(agree4 && (!has6 || agree6) && all && known && !proxy && tunnel)_lastGood=(selected?.Id,ip4,ip6,now);else _lastGood=null;
        var routeText=string.Join("; ",routes.Select(r=>$"{r.Address} → {adapters.FirstOrDefault(a=>a.Index4==r.Index || a.Index6==r.Index)?.Name ?? "не определён"}"));
        return new(now,ip4,ip6,decision.State,routeText,decision.Reason,selected?.Id,all&&known,tunnel,agree4,agree6,has6,proxy,await siteResults);
    }
    public void Dispose(){_v4.Dispose();_v6.Dispose();_sites.Dispose();}
}
