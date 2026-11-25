using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Web;

namespace Nodo03.Pruebas.Utilidades;

/// <summary>
/// Identidades de prueba reutilizables. Generar llaves RSA cuesta ~100 ms, así que se
/// crean una sola vez (Lazy es seguro entre hilos) y se comparten entre pruebas.
/// </summary>
public static class Identidades
{
    private static readonly Lazy<IdentidadNodo> _a = new(() => IdentidadNodo.CrearEnMemoria("NODO-A"));
    private static readonly Lazy<IdentidadNodo> _b = new(() => IdentidadNodo.CrearEnMemoria("NODO-B"));
    private static readonly Lazy<IdentidadNodo> _intruso = new(() => IdentidadNodo.CrearEnMemoria("INTRUSO"));

    public static IdentidadNodo A => _a.Value;
    public static IdentidadNodo B => _b.Value;
    public static IdentidadNodo Intruso => _intruso.Value;
}

/// <summary>Atajos para fabricar paquetes y zips (válidos y maliciosos).</summary>
public static class Fabrica
{
    public static ContenidoPlano Texto(string s) => new(Encoding.UTF8.GetBytes(s), ModosCarga.Texto, "mensaje.txt");

    /// <summary>Paquete válido de A para B.</summary>
    public static PaqueteGenerado Paquete(string codigo = CodigosAlgoritmo.Rsa, string texto = "hola",
        IdentidadNodo? emisor = null, IdentidadNodo? receptor = null, string direccion = "127.0.0.1:1") =>
        ServicioPaquetes.Armar(Texto(texto), codigo, (receptor ?? Identidades.B).Certificado(codigo),
            emisor ?? Identidades.A, direccion);

    /// <summary>Reescribe un zip aplicando un cambio a sus archivos (para simular ataques).</summary>
    public static byte[] Modificar(byte[] zip, Action<Dictionary<string, byte[]>> cambio)
    {
        var archivos = new Dictionary<string, byte[]>();
        using (var z = new ZipArchive(new MemoryStream(zip)))
            foreach (var e in z.Entries)
            {
                using var s = e.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                archivos[e.FullName] = ms.ToArray();
            }
        cambio(archivos);
        return ZipCon(archivos);
    }

    /// <summary>Crea un zip con los archivos indicados (nombre -> bytes).</summary>
    public static byte[] ZipCon(Dictionary<string, byte[]> archivos)
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (n, b) in archivos)
            {
                using var s = z.CreateEntry(n).Open();
                s.Write(b);
            }
        return ms.ToArray();
    }

    /// <summary>Cuerpo multipart con el zip en el campo "package", como lo manda cualquier nodo.</summary>
    public static MultipartFormDataContent Multipart(byte[] zip, string nombre, string campo = "package")
    {
        var contenido = new MultipartFormDataContent();
        var archivo = new ByteArrayContent(zip);
        archivo.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        contenido.Add(archivo, campo, nombre);
        return contenido;
    }
}

/// <summary>
/// Un nodo REAL para pruebas de integración: Kestrel escuchando en 127.0.0.1 en un
/// puerto libre, con su propia carpeta temporal (base, llaves y zips).
/// Se pueden levantar varios a la vez para probar el ping-pong.
/// </summary>
public sealed class NodoDePrueba : IAsyncDisposable
{
    public WebApplication App { get; }
    public HttpClient Http { get; }
    public string Direccion { get; }
    public string Carpeta { get; }

    private NodoDePrueba(WebApplication app, string carpeta)
    {
        App = app;
        Carpeta = carpeta;
        var puerto = app.Services.GetRequiredService<DireccionPropia>().PuertoReal();
        Direccion = $"127.0.0.1:{puerto}";
        Http = new HttpClient { BaseAddress = new Uri($"http://{Direccion}/"), Timeout = TimeSpan.FromSeconds(60) };
    }

    /// <summary>Arranca un nodo. <paramref name="ajustar"/> permite cambiar límites, id, etc.</summary>
    public static async Task<NodoDePrueba> Iniciar(string nodoId = "NODO-PRUEBA", Action<OpcionesNodo>? ajustar = null)
    {
        var carpeta = Path.Combine(Path.GetTempPath(), "nodo03-pruebas", Guid.NewGuid().ToString("N"));
        var app = NodoHost.Crear([], o =>
        {
            o.NodoId = nodoId;
            o.Escucha = "127.0.0.1";
            o.Puerto = 0;                // puerto libre aleatorio
            o.CarpetaDatos = carpeta;
            o.ContrasenaLlaves = "pruebas";
            ajustar?.Invoke(o);
        });
        await app.StartAsync();
        return new NodoDePrueba(app, carpeta);
    }

    public T Servicio<T>() where T : notnull => App.Services.GetRequiredService<T>();

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
        try { Directory.Delete(Carpeta, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

internal static class ExtensionesPrueba
{
    /// <summary>Espera hasta que <paramref name="condicion"/> sea verdadera o se acabe el tiempo.</summary>
    public static async Task<bool> EsperarHasta(Func<bool> condicion, int maxMs = 15_000)
    {
        var limite = DateTime.UtcNow.AddMilliseconds(maxMs);
        while (DateTime.UtcNow < limite)
        {
            if (condicion()) return true;
            await Task.Delay(50);
        }
        return condicion();
    }
}
