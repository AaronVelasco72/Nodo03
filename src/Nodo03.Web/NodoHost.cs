using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Web.Endpoints;
using Nodo03.Web.Servicios;

namespace Nodo03.Web;

/// <summary>
/// Arma la aplicación completa del nodo. Está separada de <c>Program.cs</c> para que las
/// pruebas de integración puedan levantar DOS nodos reales en el mismo proceso
/// (cada uno con su puerto y su carpeta de datos) y jugar ping-pong entre ellos.
/// </summary>
public static class NodoHost
{
    /// <param name="args">Argumentos de línea de comandos (sobrescriben appsettings.json).</param>
    /// <param name="configurar">Ajuste opcional de las opciones (lo usan las pruebas).</param>
    public static WebApplication Crear(string[] args, Action<OpcionesNodo>? configurar = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            // wwwroot y appsettings.json se copian junto al ejecutable: así el nodo arranca
            // igual desde Visual Studio, desde "dotnet run" o desde la carpeta publicada.
            ContentRootPath = AppContext.BaseDirectory,
        });

        // ---------- Opciones ----------
        var opciones = new OpcionesNodo();
        builder.Configuration.GetSection("Nodo").Bind(opciones);
        configurar?.Invoke(opciones);
        builder.Services.AddSingleton(opciones);

        // Kestrel escucha en Escucha:Puerto (0.0.0.0:5000 por defecto = toda la LAN).
        builder.WebHost.UseUrls($"http://{opciones.Escucha}:{opciones.Puerto}");
        ProtocoloEndpoints.ConfigurarLimites(builder, opciones);

        // ---------- Servicios (todos singleton: un nodo = una identidad, una base) ----------
        Directory.CreateDirectory(opciones.RutaDatos);
        builder.Services.AddSingleton(_ => IdentidadNodo.CargarOCrear(
            Path.Combine(opciones.RutaDatos, "identidad"), opciones.NodoId, opciones.ContrasenaLlaves));
        builder.Services.AddSingleton(_ => new BaseDatos(Path.Combine(opciones.RutaDatos, "nodo03.db")));
        builder.Services.AddSingleton<RepositorioNodo>();
        builder.Services.AddSingleton<AjustesNodo>();
        builder.Services.AddSingleton<AlmacenPaquetes>();
        builder.Services.AddSingleton<BusEventos>();
        builder.Services.AddSingleton<DireccionPropia>();
        builder.Services.AddSingleton(_ => new ClienteNodos(new HttpClient { Timeout = TimeSpan.FromSeconds(60) }));
        builder.Services.AddSingleton<ServicioRecepcion>();
        builder.Services.AddSingleton<ServicioEnvio>();
        builder.Services.AddSingleton<MotorPingPong>();
        builder.Services.AddHostedService(sp => sp.GetRequiredService<MotorPingPong>());

        var app = builder.Build();

        // Fuerza la creación de identidad y base al arrancar (y no en la primera petición),
        // así los errores de configuración aparecen de inmediato en la consola.
        app.Services.GetRequiredService<IdentidadNodo>();
        app.Services.GetRequiredService<RepositorioNodo>().Registrar("arranque", $"{opciones.NodoId} en línea");

        // ---------- Tubería HTTP ----------
        LocalEndpoints.ProtegerAdministracion(app);
        app.UseDefaultFiles();   // "/" -> index.html
        app.UseStaticFiles();    // css, js
        ProtocoloEndpoints.Mapear(app);
        LocalEndpoints.Mapear(app);

        return app;
    }
}
