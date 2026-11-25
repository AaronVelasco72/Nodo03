using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Nodo03.Web;

/// <summary>
/// Configuración de arranque del nodo (sección "Nodo" de appsettings.json).
/// Cualquier valor se puede sobreescribir desde la línea de comandos, por ejemplo:
/// <code>dotnet run --project src/Nodo03.Web -- --Nodo:Puerto=5001 --Nodo:CarpetaDatos=datos/b</code>
/// </summary>
public sealed class OpcionesNodo
{
    /// <summary>Id del nodo; aparece en manifest.sourceNode y en el nombre del zip (sin guion).</summary>
    public string NodoId { get; set; } = "NODO-03";

    /// <summary>Interfaz donde escucha Kestrel. "0.0.0.0" = todas (necesario para la LAN).</summary>
    public string Escucha { get; set; } = "0.0.0.0";

    /// <summary>Puerto HTTP. La propuesta recomienda 5000 u 8080. 0 = puerto libre aleatorio (pruebas).</summary>
    public int Puerto { get; set; } = 5000;

    /// <summary>
    /// "IP:Puerto" que se anuncia en manifest.sourceIp. Vacío = se detecta la IP de la LAN.
    /// Útil si la máquina tiene varias tarjetas de red y se detecta la equivocada.
    /// </summary>
    public string DireccionPublica { get; set; } = "";

    /// <summary>Carpeta de datos (base SQLite, llaves, zips). Relativa al directorio actual.</summary>
    public string CarpetaDatos { get; set; } = "datos";

    /// <summary>Contraseña con la que se cifran las llaves privadas en disco.</summary>
    public string ContrasenaLlaves { get; set; } = "cambia-esta-contrasena-equipo3";

    /// <summary>Tamaño máximo del .zip recibido, en MB (la propuesta recomienda 50).</summary>
    public int LimiteZipMb { get; set; } = 50;

    /// <summary>
    /// Si es false (recomendado), la API de administración /api/local solo responde a
    /// peticiones desde la misma máquina. Así otro equipo de la LAN NO puede aceptar,
    /// rechazar ni descifrar nuestras solicitudes. Se puede encender desde Ajustes para
    /// manejar el nodo desde el celular.
    /// </summary>
    public bool AdminRemoto { get; set; }

    /// <summary>Límite en bytes.</summary>
    public long LimiteZipBytes => LimiteZipMb * 1024L * 1024L;

    /// <summary>Ruta absoluta de la carpeta de datos.</summary>
    public string RutaDatos => Path.GetFullPath(CarpetaDatos);
}

/// <summary>
/// Sabe cuál es la dirección "IP:Puerto" de este nodo para ponerla en manifest.sourceIp.
/// </summary>
public sealed class DireccionPropia(OpcionesNodo opciones, IServer servidor)
{
    /// <summary>"IP:Puerto" que los demás nodos usan para responder.</summary>
    public string Obtener()
    {
        if (!string.IsNullOrWhiteSpace(opciones.DireccionPublica)) return opciones.DireccionPublica.Trim();
        var ip = opciones.Escucha is "127.0.0.1" or "localhost" ? "127.0.0.1" : IpLan() ?? "127.0.0.1";
        return $"{ip}:{PuertoReal()}";
    }

    /// <summary>Puerto en el que de verdad quedó escuchando Kestrel (importa cuando se pidió el 0).</summary>
    public int PuertoReal()
    {
        var direcciones = servidor.Features.Get<IServerAddressesFeature>()?.Addresses;
        var primera = direcciones?.FirstOrDefault();
        return primera is not null && Uri.TryCreate(primera.Replace("0.0.0.0", "localhost").Replace("[::]", "localhost"),
            UriKind.Absolute, out var u) ? u.Port : opciones.Puerto;
    }

    /// <summary>
    /// IPv4 de la LAN: la primera tarjeta activa, que no sea loopback ni virtual, y que
    /// tenga puerta de enlace (eso descarta adaptadores de VirtualBox/WSL sin salida).
    /// </summary>
    public static string? IpLan()
    {
        try
        {
            var candidatas = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => (n, p: n.GetIPProperties()))
                .Select(x => (x.n, x.p,
                    ip: x.p.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address))
                .Where(x => x.ip is not null && !IPAddress.IsLoopback(x.ip))
                .OrderByDescending(x => x.p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                .ToList();
            return candidatas.FirstOrDefault().ip?.ToString();
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }
}
