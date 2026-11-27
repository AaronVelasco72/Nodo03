using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Nodo03.Core.Protocolo;

namespace Nodo03.Web;

/// <summary>
/// Configuración del nodo (sección "Nodo" de appsettings.json). Se puede cambiar por línea de comandos:
/// <code>dotnet run --project src/Nodo03.Web -- --Nodo:Equipo=3 --Nodo:Puerto=5003</code>
/// </summary>
public sealed class OpcionesNodo
{
    /// <summary>Número de equipo (1–99). Define el nodeId (EQ03) y el puerto (5003).</summary>
    public int Equipo { get; set; } = 3;

    /// <summary>nodeId del estándar v2.0: "EQ" + equipo a 2 dígitos.</summary>
    public string NodoId => Identificadores.NodoDeEquipo(Equipo);

    /// <summary>Interfaz de escucha. El estándar exige 0.0.0.0 (sección 5.1).</summary>
    public string Escucha { get; set; } = "0.0.0.0";

    /// <summary>Puerto HTTP. Vacío = 5000 + número de equipo (5003). 0 = libre (pruebas).</summary>
    public int? Puerto { get; set; }

    public int PuertoEfectivo => Puerto ?? 5000 + Equipo;

    /// <summary>IP que se anuncia (sourceIp y beacon). Vacío = se detecta la IP de la LAN.</summary>
    public string IpPublica { get; set; } = "";

    public string CarpetaDatos { get; set; } = "datos";
    public string ContrasenaLlaves { get; set; } = "cambia-esta-contrasena-equipo3";
    public int LimiteZipMb { get; set; } = 50;
    public bool AdminRemoto { get; set; }

    /// <summary>Anuncio UDP de descubrimiento (sección 6.1).</summary>
    public bool Descubrimiento { get; set; } = true;
    public int PuertoUdp { get; set; } = 5099;
    public int IntervaloAnuncioSegundos { get; set; } = 30;

    /// <summary>Destinos extra del anuncio (ej. "127.0.0.1" para probar varios nodos en una sola PC).</summary>
    public string[] DestinosAnuncioExtra { get; set; } = [];

    /// <summary>Tope síncrono de /api/crypto/* antes de responder 202 con jobId (10.6).</summary>
    public int TopeSincronoSegundos { get; set; } = 30;

    public long LimiteZipBytes => LimiteZipMb * 1024L * 1024L;
    public string RutaDatos => Path.GetFullPath(CarpetaDatos);
}

/// <summary>IP y puerto con los que este nodo se presenta a los demás.</summary>
public sealed class DireccionPropia(OpcionesNodo opciones, IServer servidor)
{
    /// <summary>"IP:puerto" para sourceIp.</summary>
    public string Obtener() => $"{Ip()}:{PuertoReal()}";

    public string Ip()
    {
        if (!string.IsNullOrWhiteSpace(opciones.IpPublica)) return opciones.IpPublica.Trim();
        if (opciones.Escucha is "127.0.0.1" or "localhost") return "127.0.0.1";
        return Interfaces().FirstOrDefault().Ip?.ToString() ?? "127.0.0.1";
    }

    /// <summary>Puerto real de Kestrel (importa cuando se pidió el 0).</summary>
    public int PuertoReal()
    {
        var primera = servidor.Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault();
        return primera is not null && Uri.TryCreate(primera.Replace("0.0.0.0", "localhost").Replace("[::]", "localhost"), UriKind.Absolute, out var u)
            ? u.Port : opciones.PuertoEfectivo;
    }

    /// <summary>
    /// Interfaces IPv4 activas con su broadcast de subred (para el anuncio UDP). Primero las que
    /// tienen puerta de enlace (descarta adaptadores virtuales sin salida).
    /// </summary>
    public static List<(IPAddress Ip, IPAddress Broadcast)> Interfaces()
    {
        var lista = new List<(IPAddress, IPAddress, bool)>();
        try
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = n.GetIPProperties();
                var conGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                foreach (var u in props.UnicastAddresses)
                {
                    if (u.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(u.Address)) continue;
                    var ip = u.Address.GetAddressBytes();
                    var mascara = (u.IPv4Mask ?? IPAddress.Parse("255.255.255.0")).GetAddressBytes();
                    var bc = new byte[4];
                    for (var i = 0; i < 4; i++) bc[i] = (byte)(ip[i] | ~mascara[i]);
                    lista.Add((u.Address, new IPAddress(bc), conGateway));
                }
            }
        }
        catch (NetworkInformationException) { }
        return lista.OrderByDescending(x => x.Item3).Select(x => (x.Item1, x.Item2)).ToList();
    }
}
