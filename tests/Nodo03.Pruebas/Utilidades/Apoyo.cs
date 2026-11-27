using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Web;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Utilidades;

/// <summary>
/// Identidades de prueba reutilizables (RSA-2048 cuesta ~100 ms: se crean una sola vez).
/// </summary>
public static class Identidades
{
    private static readonly Lazy<IdentidadNodo> _eq03 = new(() => IdentidadNodo.CrearEnMemoria(3));
    private static readonly Lazy<IdentidadNodo> _eq05 = new(() => IdentidadNodo.CrearEnMemoria(5));
    private static readonly Lazy<IdentidadNodo> _eq07 = new(() => IdentidadNodo.CrearEnMemoria(7));

    /// <summary>Un EQ03 "de laboratorio" (no es el del nodo de prueba).</summary>
    public static IdentidadNodo Eq03 => _eq03.Value;
    public static IdentidadNodo Eq05 => _eq05.Value;
    public static IdentidadNodo Eq07 => _eq07.Value;
}

/// <summary>Proveedor RSA/ECC en memoria (base SQLite temporal) para pruebas unitarias.</summary>
public sealed class Laboratorio : IDisposable
{
    public string Carpeta { get; } = Path.Combine(Path.GetTempPath(), "nodo03-lab", Guid.NewGuid().ToString("N"));
    public BaseDatos Db { get; }
    public RepositorioNodo Repo { get; }
    public GestorLlaves Llaves { get; }
    public ProveedorLocal Proveedor { get; }
    public IdentidadNodo Yo { get; }

    public Laboratorio(IdentidadNodo? yo = null)
    {
        Directory.CreateDirectory(Carpeta);
        Yo = yo ?? Identidades.Eq03;
        Db = new BaseDatos(Path.Combine(Carpeta, "lab.db"));
        Repo = new RepositorioNodo(Db);
        Llaves = new GestorLlaves(Repo, Yo, "pruebas");
        Proveedor = new ProveedorLocal(Yo, Llaves);
    }

    public PaqueteGenerado Forward(string codigo = Diccionario.Rsa, string texto = "hola", string? keyId = null,
        Dictionary<string, string>? opciones = null, string solicitante = "EQ03") =>
        Proveedor.Forward(new PeticionForward(codigo, Encoding.UTF8.GetBytes(texto), ModosCarga.Texto, "mensaje.txt",
            keyId, opciones ?? [], null, solicitante), "127.0.0.1:5003");

    public void Dispose()
    {
        try { Directory.Delete(Carpeta, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

/// <summary>Atajos para fabricar paquetes y zips (válidos y maliciosos).</summary>
public static class Fabrica
{
    private static readonly Lazy<Laboratorio> _lab = new(() => new Laboratorio());

    /// <summary>Laboratorio compartido (EQ03 de laboratorio con su base de llaves).</summary>
    public static Laboratorio Lab => _lab.Value;

    /// <summary>
    /// Paquete válido producido por el EQ03 de laboratorio y reenviado (9.6) por
    /// <paramref name="emisor"/> (EQ05 por defecto), como llegaría a una bandeja.
    /// </summary>
    public static PaqueteGenerado Paquete(string codigo = Diccionario.Rsa, string texto = "hola", IdentidadNodo? emisor = null)
    {
        var p = Lab.Forward(codigo, texto);
        var quien = emisor ?? Identidades.Eq05;
        return new ProveedorLocal(quien, Lab.Llaves).Reempaquetar(EmpaquetadorZip.Leer(p.Zip), $"127.0.0.1:{5000 + quien.Equipo}");
    }

    /// <summary>Cambia el manifiesto y lo VUELVE A FIRMAR (para probar validaciones posteriores a la firma).</summary>
    public static byte[] Refirmar(byte[] zip, Action<Manifiesto> cambio, IdentidadNodo firmante)
    {
        var p = EmpaquetadorZip.Leer(zip);
        var m = p.Manifiesto.Clonar();
        cambio(m);
        // Firmar() recalcula publicParametersSha256; si la prueba lo quiere roto, lo rompe después.
        FirmaManifiesto.Firmar(m, firmante);
        return EmpaquetadorZip.Crear(p.Datos, firmante.CertificadoPem, m);
    }

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

    /// <summary>Cambia un campo del manifest.json SIN volver a firmar.</summary>
    public static byte[] CambiarManifiesto(byte[] zip, Action<System.Text.Json.Nodes.JsonObject> cambio) => Modificar(zip, a =>
    {
        var j = System.Text.Json.Nodes.JsonNode.Parse(a["manifest.json"])!.AsObject();
        cambio(j);
        a["manifest.json"] = Encoding.UTF8.GetBytes(j.ToJsonString());
    });

    public static byte[] ZipCon(Dictionary<string, byte[]> archivos, CompressionLevel nivel = CompressionLevel.Optimal)
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (n, b) in archivos)
            {
                using var s = z.CreateEntry(n, nivel).Open();
                s.Write(b);
            }
        return ms.ToArray();
    }

    /// <summary>Cuerpo multipart con el zip en el campo "package".</summary>
    public static MultipartFormDataContent Multipart(byte[] zip, string nombre, string campo = "package")
    {
        var contenido = new MultipartFormDataContent();
        var archivo = new ByteArrayContent(zip);
        archivo.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        contenido.Add(archivo, campo, nombre);
        return contenido;
    }

    /// <summary>
    /// Petición <c>/api/crypto/*</c> como la mandaría OTRO equipo (sección 10.6): request firmada
    /// con RSA-PSS por <paramref name="solicitante"/>, su certificado y las partes binarias.
    /// </summary>
    public static MultipartFormDataContent PeticionCripto(PeticionCripto p, IdentidadNodo solicitante,
        byte[]? payload = null, byte[]? package = null, Func<byte[], byte[]>? alterarFirma = null, string? certificadoPem = null)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(p, Nodo03.Web.Servicios.PeticionCripto.Json);
        var firma = solicitante.Firmar(bytes);
        if (alterarFirma is not null) firma = alterarFirma(firma);
        var c = new MultipartFormDataContent();
        var req = new ByteArrayContent(bytes);
        req.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        c.Add(req, "request");
        c.Add(new StringContent(Convert.ToBase64String(firma)), "requestSignature");
        c.Add(new StringContent(certificadoPem ?? solicitante.CertificadoPem), "requesterCertificate");
        if (payload is not null) c.Add(new ByteArrayContent(payload), "payload", p.OriginalFileName);
        if (package is not null)
        {
            var z = new ByteArrayContent(package);
            z.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
            c.Add(z, "package", "paquete.zip");
        }
        return c;
    }

    public static PeticionCripto Request(string operacion, string algoritmo = Diccionario.Rsa, string solicitante = "EQ05",
        string destino = "EQ03", string? keyId = null, Dictionary<string, string>? opciones = null) => new()
    {
        RequesterNode = solicitante, TargetNode = destino, AlgorithmCode = algoritmo, Operation = operacion,
        PayloadMode = ModosCarga.Texto, OriginalFileName = "mensaje.txt", KeyId = keyId,
        Options = opciones ?? new Dictionary<string, string>(StringComparer.Ordinal),
    };
}

/// <summary>
/// Un nodo REAL para pruebas de integración: Kestrel en 127.0.0.1 en un puerto libre, con su
/// propia carpeta temporal. Se pueden levantar varios a la vez (ping-pong, delegación).
/// </summary>
public sealed class NodoDePrueba : IAsyncDisposable
{
    public WebApplication App { get; }
    public HttpClient Http { get; }
    public string Direccion { get; }
    public string Carpeta { get; }
    public string NodoId => Servicio<IdentidadNodo>().NodoId;

    private NodoDePrueba(WebApplication app, string carpeta)
    {
        App = app;
        Carpeta = carpeta;
        Direccion = $"127.0.0.1:{app.Services.GetRequiredService<DireccionPropia>().PuertoReal()}";
        Http = new HttpClient { BaseAddress = new Uri($"http://{Direccion}/"), Timeout = TimeSpan.FromSeconds(90) };
    }

    /// <summary>Arranca un nodo del equipo indicado (3 por defecto). Sin UDP salvo que se pida.</summary>
    public static async Task<NodoDePrueba> Iniciar(int equipo = 3, Action<OpcionesNodo>? ajustar = null)
    {
        var carpeta = Path.Combine(Path.GetTempPath(), "nodo03-pruebas", Guid.NewGuid().ToString("N"));
        var app = NodoHost.Crear([], o =>
        {
            o.Equipo = equipo;
            o.Escucha = "127.0.0.1";
            o.IpPublica = "127.0.0.1";
            o.Puerto = 0;                // puerto libre aleatorio
            o.CarpetaDatos = carpeta;
            o.ContrasenaLlaves = "pruebas";
            o.Descubrimiento = false;    // las pruebas de UDP lo encienden a propósito
            ajustar?.Invoke(o);
        });
        await app.StartAsync();
        return new NodoDePrueba(app, carpeta);
    }

    public T Servicio<T>() where T : notnull => App.Services.GetRequiredService<T>();

    /// <summary>Da de alta a <paramref name="otro"/> en el directorio de este nodo y confirma su huella (TOFU).</summary>
    public async Task Conocer(NodoDePrueba otro)
    {
        var dir = Servicio<ServicioDirectorio>();
        var r = await dir.AltaManual(otro.Direccion);
        Assert.True(r.Ok, r.Mensaje);
        Assert.NotNull(dir.Confirmar(otro.NodoId));
    }

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

    /// <summary>Lee el "code" de un application/problem+json.</summary>
    public static async Task<string?> Codigo(this HttpResponseMessage r)
    {
        var texto = await r.Content.ReadAsStringAsync();
        try { using var d = JsonDocument.Parse(texto); return d.RootElement.TryGetProperty("code", out var c) ? c.GetString() : null; }
        catch (JsonException) { return null; }
    }
}
