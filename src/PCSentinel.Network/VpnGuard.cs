using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using PCSentinel.Core;

namespace PCSentinel.Network;

public sealed record VpnEvidence(bool Online, bool ChecksAgree4, bool ChecksAgree6, bool HasIpv6,
    bool SelectedUp, bool AllRoutesSelected, bool SomeRoutesSelected, bool Proxy,
    string? Ip4, string? Ip6, string ApprovedIps, bool RoutesKnown = true);

public static class VpnPolicy
{
    public static (VpnState State, string Reason) Evaluate(VpnEvidence e)
    {
        if (!e.Online) return (VpnState.Offline, "Windows сообщает: нет активного сетевого подключения.");
        if (!e.ChecksAgree4 || e.HasIpv6 && !e.ChecksAgree6)
            return (VpnState.Unknown, "Недостаточно согласованных ответов двух IP-сервисов для каждой доступной семьи адресов.");
        if (e.Proxy) return (VpnState.Unknown, "Обнаружен системный proxy: маршрут HTTPS может отличаться от проверенного маршрута IP.");
        if (!e.RoutesKnown) return (VpnState.Unknown, "Не удалось подтвердить маршруты всех контрольных назначений.");
        if (string.IsNullOrEmpty(e.ApprovedIps)) return (VpnState.Unknown, "Укажите VPN-адаптер и доверенные IP/CIDR в настройках.");
        if (!e.SelectedUp) return (VpnState.Unprotected, "Выбранный VPN-адаптер не подключён или не выбран.");
        if (!e.AllRoutesSelected) return (VpnState.Unprotected, e.SomeRoutesSelected
            ? "Частичная маршрутизация: проверенные назначения используют разные адаптеры."
            : "Проверенные маршруты проходят вне выбранного VPN-адаптера.");
        if (e.Ip4 is null || !IpRange.Approved(e.ApprovedIps, e.Ip4) || e.HasIpv6 && (e.Ip6 is null || !IpRange.Approved(e.ApprovedIps, e.Ip6)))
            return (VpnState.Unprotected, "Внешний IPv4 или IPv6 не входит в доверенный список.");
        return (VpnState.Protected, "Проверенные IP и маршруты соответствуют настройкам. Это выборочная проверка; политики отдельных приложений не проверены.");
    }
}

public sealed class VpnGuard : IDisposable
{
    private readonly HttpClient _v4 = CreateClient(AddressFamily.InterNetwork);
    private readonly HttpClient _v6 = CreateClient(AddressFamily.InterNetworkV6);
    private static readonly string[] Urls4 = ["https://api.ipify.org", "https://ipv4.icanhazip.com"];
    private static readonly string[] Urls6 = ["https://api6.ipify.org", "https://ipv6.icanhazip.com"];
    [DllImport("iphlpapi.dll")] private static extern uint GetBestInterfaceEx(byte[] destination, out uint index);
    [DllImport("iphlpapi.dll")] private static extern uint GetIfEntry2(IntPtr row);
    private static (bool? Hardware,bool? Filter,uint? Tunnel) InterfaceFlags(int index)
    {
        if(index<=0)return (null,null,null);
        // MIB_IF_ROW2, Windows x64 ABI: 257 UTF-16 chars each for Alias/Description.
        var memory=Marshal.AllocHGlobal(2048);
        try
        {
            Marshal.Copy(new byte[2048],0,memory,2048);Marshal.WriteInt32(memory,8,index);
            if(GetIfEntry2(memory)!=0)return (null,null,null);
            var flags=Marshal.ReadByte(memory,1152);
            return ((flags&1)!=0,(flags&2)!=0,(uint)Marshal.ReadInt32(memory,1132));
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
    public static IReadOnlyList<AdapterInfo> GetAdapters() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback).Select(n =>
        {
            var p = n.GetIPProperties();
            int i4 = 0, i6 = 0;
            try { i4 = p.GetIPv4Properties()?.Index ?? 0; } catch (NetworkInformationException) { }
            try { i6 = p.GetIPv6Properties()?.Index ?? 0; } catch (NetworkInformationException) { }
            var flags=InterfaceFlags(i4>0?i4:i6);
            return new AdapterInfo(n.Id, n.Name, n.Description, i4, i6, n.OperationalStatus == OperationalStatus.Up,
                n.NetworkInterfaceType.ToString(), string.Join(", ", p.GatewayAddresses.Select(g => g.Address)),
                p.UnicastAddresses.Any(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(a.Address)),p.UnicastAddresses.Count > 0,flags.Hardware,flags.Filter,flags.Tunnel);
        }).ToArray();

    internal static HttpClient CreateClient(AddressFamily family)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(5), AllowAutoRedirect = false,
            UseCookies = false, Credentials = null,
            ConnectCallback = async (context, ct) =>
            {
                var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, family, ct);
                foreach (var address in addresses)
                {
                    var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
                    try { await socket.ConnectAsync(address, context.DnsEndPoint.Port, ct); return new NetworkStream(socket, true); }
                    catch { socket.Dispose(); }
                }
                throw new HttpRequestException("Нет соединения для выбранной семьи IP.");
            }
        };
        return new(handler) { Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 4096 };
    }
    internal static int? Route(IPAddress address)
    {
        var ep = new IPEndPoint(address, 443).Serialize(); var bytes = new byte[ep.Size];
        for (var i = 0; i < bytes.Length; i++) bytes[i] = ep[i];
        return GetBestInterfaceEx(bytes, out var index) == 0 ? (int)index : null;
    }
    internal static async Task<string?> PublicIp(HttpClient client, string url, AddressFamily family, CancellationToken ct)
    {
        try
        {
            var text = (await client.GetStringAsync(url, ct)).Trim();
            try { return PublicAddress.Normalize(text,family) is {Length:>0} value?value:null; } catch(ArgumentException){return null;}
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { return null; }
    }
    public async Task<NetworkCheck> CheckAsync(AppSettings settings, CancellationToken ct)
    {
        if (!settings.EnablePublicIp) return new(DateTimeOffset.UtcNow, null, null, VpnState.Unknown, "—", "Проверки IP выключены. Включите их в настройках: запросы идут двум независимым HTTPS-сервисам.");
        if (!NetworkInterface.GetIsNetworkAvailable()) return new(DateTimeOffset.UtcNow, null, null, VpnState.Offline, "—", "Нет активного подключения Windows.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(12));
        var adapters = GetAdapters(); var selected = adapters.FirstOrDefault(a => a.Id == settings.PreferredAdapterId);
        var has6 = adapters.Any(a => a.Up && a.HasIpv6);
        var tasks4 = Urls4.Select(u => PublicIp(_v4, u, AddressFamily.InterNetwork, timeout.Token)).ToArray();
        var tasks6 = has6 ? Urls6.Select(u => PublicIp(_v6, u, AddressFamily.InterNetworkV6, timeout.Token)).ToArray() : [];
        var ipv4 = await Task.WhenAll(tasks4); var ipv6 = await Task.WhenAll(tasks6);
        var routes = new List<(string Target, int? Index, bool Matches)>();
        var routesKnown = true;
        var proxy = Urls4.Concat(has6 ? Urls6 : []).Any(u => HttpClient.DefaultProxy.IsBypassed(new Uri(u)) == false);
        var probes = new List<IPAddress> { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8") };
        if (has6) probes.AddRange([IPAddress.Parse("2606:4700:4700::1111"), IPAddress.Parse("2001:4860:4860::8888")]);
        foreach (var url in Urls4.Concat(has6 ? Urls6 : []))
        {
            try { probes.AddRange(await Dns.GetHostAddressesAsync(new Uri(url).Host, timeout.Token)); }
            catch (Exception error) when (error is SocketException or OperationCanceledException) { routesKnown = false; }
        }
        foreach (var address in probes.Distinct().Where(a => has6 || a.AddressFamily == AddressFamily.InterNetwork))
        {
            var index = Route(address); var targetIndex = address.AddressFamily == AddressFamily.InterNetwork ? selected?.Index4 : selected?.Index6;
            if (index is null) routesKnown = false;
            routes.Add((address.ToString(), index, index is > 0 && index == targetIndex));
        }
        var e = new VpnEvidence(true, ipv4.Length == 2 && ipv4[0] != null && ipv4[0] == ipv4[1],
            ipv6.Length == 2 && ipv6[0] != null && ipv6[0] == ipv6[1], has6, selected?.Up == true,
            routes.Count > 0 && routes.All(r => r.Matches), routes.Any(r => r.Matches), proxy,
            ipv4.FirstOrDefault(i => i != null), ipv6.FirstOrDefault(i => i != null), settings.ApprovedIps, routesKnown);
        var decision = VpnPolicy.Evaluate(e);
        return new(DateTimeOffset.UtcNow, e.Ip4, e.Ip6, decision.State,
            string.Join("; ", routes.Select(r => $"{r.Target} → {adapters.FirstOrDefault(a => a.Index4 == r.Index || a.Index6 == r.Index)?.Name ?? r.Index?.ToString() ?? "нет маршрута"}")), decision.Reason);
    }
    public void Dispose() { _v4.Dispose(); _v6.Dispose(); }
}
