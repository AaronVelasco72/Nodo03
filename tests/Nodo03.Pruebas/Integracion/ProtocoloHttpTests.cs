using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Integracion;

/// <summary>
/// Un nodo EQ03 REAL y la prueba haciendo de "otro equipo" (EQ05) por HTTP, exactamente como
/// lo haría el programa de cualquier equipo. Cubre la lista de conformidad 16.2.
/// </summary>
public sealed class ProtocoloHttpTests : IAsyncLifetime
{
    private NodoDePrueba _nodo = null!;

    public async Task InitializeAsync() => _nodo = await NodoDePrueba.Iniciar(3, o => o.LimiteZipMb = 2);
    public async Task DisposeAsync() => await _nodo.DisposeAsync();

    private Task<HttpResponseMessage> Recibir(byte[] zip, string nombre = "paquete.zip") =>
        _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(zip, nombre));

    // ------------------------------------------------------------------ 10.3 / 7 / 10.4

    [Fact]
    public async Task Status_DiceEQ03_Puerto_AlgoritmosYHuella()
    {
        using var j = JsonDocument.Parse(await _nodo.Http.GetStringAsync("api/status"));
        var r = j.RootElement;
        Assert.Equal("EQ03", r.GetProperty("nodeId").GetString());
        Assert.Equal(3, r.GetProperty("teamNumber").GetInt32());
        Assert.Equal("2.0", r.GetProperty("protocolVersion").GetString());
        Assert.True(r.GetProperty("acceptingPackages").GetBoolean());
        Assert.Equal(int.Parse(_nodo.Direccion.Split(':')[1]), r.GetProperty("httpPort").GetInt32());
        Assert.Equal(JsonValueKind.Null, r.GetProperty("httpsPort").ValueKind);
        Assert.Equal(new[] { "5:RSA", "6:ECC" }, r.GetProperty("algorithms").EnumerateArray()
            .Select(a => $"{a.GetProperty("algorithmId").GetInt32()}:{a.GetProperty("algorithmCode").GetString()}"));
        Assert.Matches(Identificadores.Timestamp(), r.GetProperty("serverTimeUtc").GetString());

        var pem = await _nodo.Http.GetStringAsync("api/certificate");
        using var cert = IdentidadNodo.LeerPem(pem);
        Assert.Equal(Huellas.HuellaCertificado(cert), r.GetProperty("certificateThumbprintSha256").GetString());
        Assert.Contains("CN=EQ03", cert.Subject);
    }

    [Fact]
    public async Task Algorithms_PublicaElPerfilDeRsaYEcc()
    {
        using var j = JsonDocument.Parse(await _nodo.Http.GetStringAsync("api/algorithms"));
        var algs = j.RootElement.GetProperty("algorithms").EnumerateArray().ToList();
        Assert.Equal(new[] { "RSA", "ECC" }, algs.Select(a => a.GetProperty("algorithmCode").GetString()));
        Assert.Equal("cifrar", algs[0].GetProperty("operations").GetProperty("forward").GetProperty("name").GetString());
        Assert.Contains(algs[0].GetProperty("options").EnumerateArray(), o => o.GetProperty("name").GetString() == "allowedNodes");
    }

    // ------------------------------------------------------------------ 10.5 / 13.1 / 14

    [Fact]
    public async Task Bandeja_PaqueteValido_202_YRemitenteNoConfirmado()
    {
        var p = Fabrica.Paquete();
        var r = await Recibir(p.Zip, p.NombreZip);
        Assert.Equal(HttpStatusCode.Accepted, r.StatusCode);
        using var j = JsonDocument.Parse(await r.Content.ReadAsStringAsync());
        Assert.Equal(p.Manifiesto.PacketId, j.RootElement.GetProperty("packetId").GetString());
        Assert.Equal("Pendiente", j.RootElement.GetProperty("status").GetString());
        Assert.Matches(Identificadores.Timestamp(), j.RootElement.GetProperty("receivedAtUtc").GetString());

        var s = Assert.Single(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal(Verificaciones.NoConfirmado, s.Verificacion);    // EQ05 no está fijado
        Assert.Equal("EQ05", s.NodoOrigen);
        Assert.Equal("EQ03", s.NodoProductor);
        Assert.Equal("cifrar", s.OperacionNombre);
    }

    [Fact]
    public async Task Bandeja_RemitenteFijado_FirmaOk()
    {
        _nodo.Servicio<RepositorioNodo>().GuardarNodo(new NodoConocido { NodeId = "EQ05", Equipo = 5, Ip = "127.0.0.1", HttpPort = 5005, HuellaFijada = Identidades.Eq05.Huella, HuellaPresentada = Identidades.Eq05.Huella, Algoritmos = "", Estado = "online" });
        Assert.Equal(HttpStatusCode.Accepted, (await Recibir(Fabrica.Paquete().Zip)).StatusCode);
        Assert.Equal(Verificaciones.FirmaOk, Assert.Single(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes()).Verificacion);
    }

    [Fact]
    public async Task Bandeja_FijadoConOtraHuella_403_ECertUntrusted()
    {
        _nodo.Servicio<RepositorioNodo>().GuardarNodo(new NodoConocido { NodeId = "EQ05", Equipo = 5, Ip = "127.0.0.1", HttpPort = 5005, HuellaFijada = new string('C', 64), Algoritmos = "", Estado = "online" });
        var r = await Recibir(Fabrica.Paquete().Zip);
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal("E-CERT-UNTRUSTED", await r.Codigo());
        Assert.Equal(Verificaciones.Invalida, Assert.Single(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes()).Verificacion);
    }

    [Fact]
    public async Task Bandeja_Repetido_409_EDuplicate_ConProblemJson()
    {
        var p = Fabrica.Paquete();
        Assert.Equal(HttpStatusCode.Accepted, (await Recibir(p.Zip)).StatusCode);
        var r = await Recibir(p.Zip);
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal("application/problem+json", r.Content.Headers.ContentType!.MediaType);
        using var j = JsonDocument.Parse(await r.Content.ReadAsStringAsync());
        Assert.Equal("E-DUPLICATE", j.RootElement.GetProperty("code").GetString());
        Assert.Equal(409, j.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("EQ03", j.RootElement.GetProperty("nodeId").GetString());
        Assert.Equal("https://centrociber.local/errors/E-DUPLICATE", j.RootElement.GetProperty("type").GetString());
        Assert.False(string.IsNullOrWhiteSpace(j.RootElement.GetProperty("title").GetString()));
    }

    [Fact]
    public async Task Bandeja_HashAlterado_422_EHash_QuedaComoEvidencia()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a["datos.enc"][0] ^= 1);
        var r = await Recibir(zip);
        Assert.Equal((HttpStatusCode)422, r.StatusCode);
        Assert.Equal("E-HASH", await r.Codigo());
        var s = Assert.Single(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal(EstadosSolicitud.Rechazada, s.Estado);
        Assert.Equal(Verificaciones.Invalida, s.Verificacion);
    }

    [Fact]
    public async Task Bandeja_CuatroArchivos_400_EZipStructure()
    {
        var r = await Recibir(Fabrica.Modificar(Fabrica.Paquete().Zip, a => a["leeme.txt"] = [1, 2]));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal("E-ZIP-STRUCTURE", await r.Codigo());
    }

    [Fact]
    public async Task Bandeja_FirmaAlterada_422_ESignature() =>
        Assert.Equal("E-SIGNATURE", await (await Recibir(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j["producerNode"] = "EQ07"))).Codigo());

    [Fact]
    public async Task Bandeja_FechaVieja_422_ETimestamp() =>
        Assert.Equal("E-TIMESTAMP", await (await Recibir(Fabrica.Refirmar(Fabrica.Paquete().Zip,
            m => m.TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow.AddMinutes(-30)), Identidades.Eq05))).Codigo());

    [Fact]
    public async Task Bandeja_MuyGrande_413_ESize()
    {
        var r = await Recibir(new byte[3 * 1024 * 1024]);   // límite de prueba: 2 MB
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r.StatusCode);
        Assert.Equal("E-SIZE", await r.Codigo());
    }

    [Fact]
    public async Task Bandeja_SinMultipart_415() =>
        Assert.Equal("E-UNSUPPORTED-MEDIA", await (await _nodo.Http.PostAsync("api/requests/receive", new StringContent("{}"))).Codigo());

    [Fact]
    public async Task Bandeja_NoAceptando_503_EBusy()
    {
        var aj = _nodo.Servicio<AjustesNodo>();
        aj.Guardar(aj.Actual with { AceptandoPaquetes = false });
        var r = await Recibir(Fabrica.Paquete().Zip);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
        Assert.Equal("E-BUSY", await r.Codigo());
    }

    // ------------------------------------------------------------------ 10.6 / 13.2 (EQ05 le pide a EQ03)

    private Task<HttpResponseMessage> Cripto(string op, MultipartFormDataContent c) => _nodo.Http.PostAsync($"api/crypto/{op}", c);

    private async Task<byte[]> ForwardRemoto(string algoritmo, string texto, Dictionary<string, string>? opciones = null)
    {
        var r = await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward", algoritmo, opciones: opciones), Identidades.Eq05, Encoding.UTF8.GetBytes(texto)));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("application/zip", r.Content.Headers.ContentType!.MediaType);
        return await r.Content.ReadAsByteArrayAsync();
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECC")]
    public async Task ForwardEInverseRemotos_RegresanElOriginalCifradoParaElSolicitante(string algoritmo)
    {
        var zip = await ForwardRemoto(algoritmo, "Hola EQ03, soy EQ05");
        var paquete = EmpaquetadorZip.Leer(zip);
        ValidadorPaquete.Validar(paquete, DateTime.UtcNow);
        Assert.Equal("EQ03", paquete.Manifiesto.SourceNode);
        Assert.Equal("EQ03", paquete.Manifiesto.ProducerNode);
        Assert.Matches(Identificadores.Uuid4(), paquete.Manifiesto.RequestId);
        Assert.StartsWith("EQ03-KEY-", paquete.Manifiesto.KeyRef!.KeyId);

        // EQ05 reenvía (9.6) para refrescar la fecha y pide el inverse.
        var reenviado = new ProveedorLocal(Identidades.Eq05, Fabrica.Lab.Llaves).Reempaquetar(paquete, "127.0.0.1:5005");
        var req = Fabrica.Request("inverse", algoritmo);
        var r = await Cripto("inverse", Fabrica.PeticionCripto(req, Identidades.Eq05, package: reenviado.Zip));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var resultado = EmpaquetadorZip.Leer(await r.Content.ReadAsByteArrayAsync());
        ValidadorPaquete.Validar(resultado, DateTime.UtcNow);
        Assert.Equal("result", resultado.Manifiesto.PacketType);
        Assert.Equal(req.RequestId, resultado.Manifiesto.RequestId);
        Assert.Equal("EQ05", resultado.Manifiesto.ResultEnvelope!.RecipientNode);
        Assert.Equal("Hola EQ03, soy EQ05", Encoding.UTF8.GetString(ProveedorLocal.AbrirResultado(resultado, Identidades.Eq05)));
    }

    [Fact]
    public async Task Inverse_ConPaqueteSinReenviar_TambienFunciona()
    {
        // Somos tolerantes: la ventana de ±10 min no se aplica al package de un inverse (ver README).
        var zip = await ForwardRemoto("RSA", "directo");
        var r = await Cripto("inverse", Fabrica.PeticionCripto(Fabrica.Request("inverse"), Identidades.Eq05, package: zip));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task FirmaDeLaPeticionAlterada_401()
    {
        var r = await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward"), Identidades.Eq05, "x"u8.ToArray(),
            alterarFirma: f => { f[10] ^= 1; return f; }));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal("E-REQUEST-SIGNATURE", await r.Codigo());
    }

    [Fact]
    public async Task CertificadoNoEsDelSolicitante_422_ECert()
    {
        // Dice ser EQ05 pero manda el certificado de EQ07.
        var r = await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward"), Identidades.Eq07, "x"u8.ToArray()));
        Assert.Equal("E-CERT", await r.Codigo());
    }

    [Fact]
    public async Task TargetNodeEquivocado_400_ERequest() =>
        Assert.Equal("E-REQUEST", await (await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward", destino: "EQ04"), Identidades.Eq05, "x"u8.ToArray()))).Codigo());

    [Fact]
    public async Task RequestIdRepetido_409()
    {
        var req = Fabrica.Request("forward");
        Assert.Equal(HttpStatusCode.OK, (await Cripto("forward", Fabrica.PeticionCripto(req, Identidades.Eq05, "x"u8.ToArray()))).StatusCode);
        var r = await Cripto("forward", Fabrica.PeticionCripto(req, Identidades.Eq05, "x"u8.ToArray()));
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal("E-DUPLICATE", await r.Codigo());
    }

    [Fact]
    public async Task PeticionVieja_422_ETimestamp()
    {
        var req = Fabrica.Request("forward");
        req.TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow.AddMinutes(-15));
        Assert.Equal("E-TIMESTAMP", await (await Cripto("forward", Fabrica.PeticionCripto(req, Identidades.Eq05, "x"u8.ToArray()))).Codigo());
    }

    [Fact]
    public async Task AlgoritmoDeOtroEquipo_404_EAlgorithmNotProvided()
    {
        var r = await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward", "AESGCM"), Identidades.Eq05, "x"u8.ToArray()));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.Equal("E-ALGORITHM-NOT-PROVIDED", await r.Codigo());
    }

    [Fact]
    public async Task SobreParaOtroNodo_401_EEnvRecipient()
    {
        var req = Fabrica.Request("forward");
        req.Secrets = SobreCc.Cerrar("{}"u8.ToArray(), Identidades.Eq07.Certificado, "EQ07", req.RequestId, false, out _);
        var r = await Cripto("forward", Fabrica.PeticionCripto(req, Identidades.Eq05, "x"u8.ToArray()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal("E-ENV-RECIPIENT", await r.Codigo());
    }

    [Fact]
    public async Task FaltaPayload_400_ERequest() =>
        Assert.Equal("E-REQUEST", await (await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward"), Identidades.Eq05))).Codigo());

    [Fact]
    public async Task AllowedNodes_OtroNodoNoPuedeDescifrar_403()
    {
        var zip = await ForwardRemoto("RSA", "solo EQ01", new() { ["allowedNodes"] = "EQ01" });
        var r = await Cripto("inverse", Fabrica.PeticionCripto(Fabrica.Request("inverse"), Identidades.Eq05, package: zip));
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal("E-KEY-FORBIDDEN", await r.Codigo());
    }

    [Fact]
    public async Task KeyIdDesconocido_404()
    {
        var r = await Cripto("forward", Fabrica.PeticionCripto(Fabrica.Request("forward", keyId: "EQ03-KEY-11111111-1111-4111-8111-111111111111"), Identidades.Eq05, "x"u8.ToArray()));
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        Assert.Equal("E-KEY-NOT-FOUND", await r.Codigo());
    }

    [Fact]
    public async Task Keys_DevuelveSoloLaPublica()
    {
        var keyId = EmpaquetadorZip.Leer(await ForwardRemoto("ECC", "x")).Manifiesto.KeyRef!.KeyId;
        var texto = await _nodo.Http.GetStringAsync($"api/keys/{keyId}");
        using var j = JsonDocument.Parse(texto);
        Assert.Equal("EQ03", j.RootElement.GetProperty("ownerNode").GetString());
        Assert.Equal("ECC", j.RootElement.GetProperty("algorithmCode").GetString());
        Assert.DoesNotContain("PRIVATE", texto, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.NotFound, (await _nodo.Http.GetAsync("api/keys/EQ03-KEY-no-existe")).StatusCode);
    }

    [Fact]
    public async Task EncabezadosXcc_EnLasRespuestas()
    {
        var r = await _nodo.Http.GetAsync("api/status");
        Assert.Equal("EQ03", r.Headers.GetValues("X-CC-Node").Single());
        Assert.Equal("2.0", r.Headers.GetValues("X-CC-Protocol").Single());
    }
}

/// <summary>10.6 paso 4 y 10.7: si no termina en el tope síncrono → 202 + jobId.</summary>
public sealed class TrabajosAsincronosTests : IAsyncLifetime
{
    private NodoDePrueba _nodo = null!;

    public async Task InitializeAsync() => _nodo = await NodoDePrueba.Iniciar(3, o => o.TopeSincronoSegundos = 0);
    public async Task DisposeAsync() => await _nodo.DisposeAsync();

    [Fact]
    public async Task TopeSincrono_Responde202_YElResultadoSoloLoBajaElSolicitante()
    {
        var r = await _nodo.Http.PostAsync("api/crypto/forward",
            Fabrica.PeticionCripto(Fabrica.Request("forward"), Identidades.Eq05, "lento"u8.ToArray()));
        Assert.Equal(HttpStatusCode.Accepted, r.StatusCode);
        using var j = JsonDocument.Parse(await r.Content.ReadAsStringAsync());
        var jobId = j.RootElement.GetProperty("jobId").GetString()!;
        Assert.Equal($"/api/jobs/{jobId}", j.RootElement.GetProperty("statusUrl").GetString());

        string? estado = null;
        Assert.True(await ExtensionesPrueba.EsperarHasta(() =>
        {
            using var e = JsonDocument.Parse(_nodo.Http.GetStringAsync($"api/jobs/{jobId}").Result);
            estado = e.RootElement.GetProperty("state").GetString();
            return estado == "done";
        }), estado);

        var ajeno = new HttpRequestMessage(HttpMethod.Get, $"api/jobs/{jobId}/result");
        ajeno.Headers.Add("X-CC-Node", "EQ07");
        Assert.Equal(HttpStatusCode.NotFound, (await _nodo.Http.SendAsync(ajeno)).StatusCode);

        var propio = new HttpRequestMessage(HttpMethod.Get, $"api/jobs/{jobId}/result");
        propio.Headers.Add("X-CC-Node", "EQ05");
        var zip = await (await _nodo.Http.SendAsync(propio)).Content.ReadAsByteArrayAsync();
        ValidadorPaquete.Validar(EmpaquetadorZip.Leer(zip), DateTime.UtcNow);

        Assert.Equal("E-JOB-NOT-FOUND", await (await _nodo.Http.GetAsync($"api/jobs/{Identificadores.NuevoUuid()}")).Codigo());
    }
}
