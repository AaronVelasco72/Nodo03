using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nodo03.Core.Datos;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Integracion;

/// <summary>
/// DOS nodos reales en la misma máquina (como dos células en la LAN) intercambiando
/// paquetes: enviar, aceptar, descifrar, rechazar y el ping-pong manual y automático.
/// </summary>
public sealed class FlujoEntreNodosTests : IAsyncLifetime
{
    private NodoDePrueba _a = null!, _b = null!;

    public async Task InitializeAsync()
    {
        _a = await NodoDePrueba.Iniciar("NODO-03");
        _b = await NodoDePrueba.Iniciar("NODO-05");
    }

    public async Task DisposeAsync()
    {
        await _a.DisposeAsync();
        await _b.DisposeAsync();
    }

    /// <summary>Usa la API local del emisor, igual que la pantalla "Enviar".</summary>
    private static async Task<ResultadoEnvio> Enviar(NodoDePrueba de, NodoDePrueba para, string algoritmo,
        string? texto = null, byte[]? archivo = null, string nombre = "foto.png")
    {
        var f = new MultipartFormDataContent
        {
            { new StringContent(texto is null ? "image" : "text"), "modo" },
            { new StringContent(algoritmo), "algoritmo" },
            { new StringContent("remoto"), "destinatario" },
            { new StringContent(para.Direccion), "direccion" },
        };
        if (texto is not null) f.Add(new StringContent(texto), "texto");
        else f.Add(new ByteArrayContent(archivo!), "archivo", nombre);
        var r = await de.Http.PostAsync("api/local/enviar", f);
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<ResultadoEnvio>())!;
    }

    private static async Task<JsonElement> Descifrar(NodoDePrueba nodo, string consultaId)
    {
        var r = await nodo.Http.PostAsync($"api/local/consultas/{consultaId}/descifrar", null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task<string> Aceptar(NodoDePrueba nodo, string solicitudId)
    {
        var r = await nodo.Http.PostAsync($"api/local/solicitudes/{solicitudId}/aceptar", null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("consultaId").GetString()!;
    }

    [Theory]
    [InlineData("RSA", "Frase corta")]
    [InlineData("RSA", "Frase larga que supera los 190 bytes para forzar el esquema híbrido RSA-OAEP + AES-256-GCM: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")]
    [InlineData("ECC", "CURP VERA040101HDFLMR09 · ñ · 🔐")]
    public async Task Texto_DeANodoB_SeAceptaYSeDescifraIgual(string algoritmo, string texto)
    {
        var envio = await Enviar(_a, _b, algoritmo, texto);
        Assert.True(envio.Ok, envio.Mensaje);
        Assert.Equal(202, envio.CodigoHttp);

        var repoB = _b.Servicio<RepositorioNodo>();
        var solicitud = Assert.Single(repoB.ListarSolicitudes(EstadosSolicitud.Pendiente));
        Assert.Equal("NODO-03", solicitud.NodoOrigen);
        Assert.Equal(algoritmo, solicitud.AlgoritmoCodigo);

        var consultaId = await Aceptar(_b, solicitud.Id);
        var claro = await Descifrar(_b, consultaId);
        Assert.Equal(texto, claro.GetProperty("texto").GetString());
    }

    [Fact]
    public async Task Imagen_ECC_LlegaIdenticaByteAByte()
    {
        var imagen = RandomNumberGenerator.GetBytes(400_000);
        await Enviar(_a, _b, "ECC", archivo: imagen);
        var s = Assert.Single(_b.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal("image", s.Modo);
        var claro = await Descifrar(_b, await Aceptar(_b, s.Id));
        Assert.Equal(imagen, Convert.FromBase64String(claro.GetProperty("base64").GetString()!));
    }

    [Fact]
    public async Task Rechazar_NoGuardaEnConsultas()
    {
        await Enviar(_a, _b, "RSA", "no lo quiero");
        var s = Assert.Single(_b.Servicio<RepositorioNodo>().ListarSolicitudes());
        var r = await _b.Http.PostAsync($"api/local/solicitudes/{s.Id}/rechazar", null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(0, _b.Servicio<RepositorioNodo>().ContarConsultas());
    }

    [Fact]
    public async Task EmisorNoPuedeDescifrarLoQueEnvio_SoloElDestino()
    {
        var envio = await Enviar(_a, _b, "RSA", "solo para B");
        var r = await _a.Http.PostAsync($"api/local/consultas/{envio.ConsultaId}/descifrar", null);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task PingPongManual_BRebotaYADescifraElMismoMensaje()
    {
        const string mensaje = "pelota manual";
        await Enviar(_a, _b, "ECC", mensaje);
        var sB = Assert.Single(_b.Servicio<RepositorioNodo>().ListarSolicitudes());
        var consultaB = await Aceptar(_b, sB.Id);

        // B: descifra con SU llave y re-cifra con el certificado de A (que venía en el zip)
        var rebote = await (await _b.Http.PostAsync($"api/local/consultas/{consultaB}/rebotar", null))
            .Content.ReadFromJsonAsync<ResultadoEnvio>();
        Assert.True(rebote!.Ok, rebote.Mensaje);

        var sA = Assert.Single(_a.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal(1, sA.Salto);
        Assert.Equal(sB.RallyId, sA.RallyId);
        var claro = await Descifrar(_a, await Aceptar(_a, sA.Id));
        Assert.Equal(mensaje, claro.GetProperty("texto").GetString());
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECC")]
    public async Task PingPongAutomatico_SeDetieneEnElMaximoDeRebotes(string algoritmo)
    {
        foreach (var n in new[] { _a, _b })
            n.Servicio<AjustesNodo>().Guardar(new ValoresAjustes { RebotarAutomatico = true, MaxRebotes = 4, PausaRebotesMs = 0 });

        const string mensaje = "pelota automática";
        await Enviar(_a, _b, algoritmo, mensaje);

        // Saque 0 (A→B), 1 (B→A), 2 (A→B), 3 (B→A), 4 (A→B) y B ya no regresa la 4.
        var repoA = _a.Servicio<RepositorioNodo>();
        var repoB = _b.Servicio<RepositorioNodo>();
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => repoB.ListarSolicitudes().Any(s => s.Salto == 4)));
        await Task.Delay(500); // margen por si (incorrectamente) siguiera rebotando

        Assert.Equal(new[] { 0, 2, 4 }, repoB.ListarSolicitudes().Select(s => s.Salto).OrderBy(x => x).ToArray());
        Assert.Equal(new[] { 1, 3 }, repoA.ListarSolicitudes().Select(s => s.Salto).OrderBy(x => x).ToArray());

        // La última pelota quedó pendiente en B y sigue diciendo lo mismo tras 4 re-cifrados.
        var ultima = repoB.ListarSolicitudes(EstadosSolicitud.Pendiente).Single();
        var claro = await Descifrar(_b, await Aceptar(_b, ultima.Id));
        Assert.Equal(mensaje, claro.GetProperty("texto").GetString());
    }

    [Fact]
    public async Task ReenviarATercero_ConservaLaFirmaDelEmisorOriginal()
    {
        await using var c = await NodoDePrueba.Iniciar("NODO-07");
        var envio = await Enviar(_a, _b, "RSA", "para reenviar");
        var r = await _a.Http.PostAsJsonAsync($"api/local/consultas/{envio.ConsultaId}/reenviar", new { direccion = c.Direccion });
        Assert.True((await r.Content.ReadFromJsonAsync<ResultadoEnvio>())!.Ok);

        var s = Assert.Single(c.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal("NODO-03", s.NodoOrigen);   // la firma sigue siendo de A
        Assert.Equal("X.509 OK", s.Verificacion);
    }

    [Fact]
    public async Task DestinoApagado_DevuelveMensajeClaroSinTronar()
    {
        var f = new MultipartFormDataContent
        {
            { new StringContent("text"), "modo" }, { new StringContent("hola"), "texto" },
            { new StringContent("RSA"), "algoritmo" }, { new StringContent("propio"), "destinatario" },
            { new StringContent("127.0.0.1:1"), "direccion" },
        };
        var r = await (await _a.Http.PostAsync("api/local/enviar", f)).Content.ReadFromJsonAsync<ResultadoEnvio>();
        Assert.False(r!.Ok);
        Assert.Equal(0, r.CodigoHttp);
        Assert.Contains("No se pudo conectar", r.Mensaje);
    }

    [Fact]
    public async Task SoloGenerar_CreaZipDescargableConNombreOficial()
    {
        var f = new MultipartFormDataContent
        {
            { new StringContent("text"), "modo" }, { new StringContent("archivo local"), "texto" },
            { new StringContent("ECC"), "algoritmo" }, { new StringContent("propio"), "destinatario" },
            { new StringContent("true"), "soloGenerar" },
        };
        var r = (await (await _a.Http.PostAsync("api/local/enviar", f)).Content.ReadFromJsonAsync<ResultadoEnvio>())!;
        Assert.True(r.Ok);
        var zip = await _a.Http.GetAsync($"api/local/consultas/{r.ConsultaId}/zip");
        Assert.Equal("application/zip", zip.Content.Headers.ContentType!.MediaType);
        Assert.Equal(r.NombreZip, zip.Content.Headers.ContentDisposition!.FileName!.Trim('"'));
        Assert.True(Nodo03.Core.Protocolo.NombrePaquete.EsValido(r.NombreZip));
        // Cifrado "para mí": el propio nodo lo puede descifrar.
        Assert.Equal("archivo local", (await Descifrar(_a, r.ConsultaId!)).GetProperty("texto").GetString());
    }
}
