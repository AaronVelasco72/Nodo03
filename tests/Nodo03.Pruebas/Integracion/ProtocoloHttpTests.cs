using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Pruebas.Utilidades;

namespace Nodo03.Pruebas.Integracion;

/// <summary>
/// El nodo REAL respondiendo por HTTP lo que exige la sección 3 de la propuesta:
/// cada código de respuesta (202, 400, 413, 422) con un paquete construido a propósito.
/// </summary>
public sealed class ProtocoloHttpTests : IAsyncLifetime
{
    private NodoDePrueba _nodo = null!;

    public async Task InitializeAsync() => _nodo = await NodoDePrueba.Iniciar("NODO-03", o => o.LimiteZipMb = 1);
    public async Task DisposeAsync() => await _nodo.DisposeAsync();

    private Task<HttpResponseMessage> Enviar(byte[] zip, string nombre = "NODOA_RSA_20261124_101500_ABCDEF12.zip") =>
        _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(zip, nombre));

    [Fact]
    public async Task Status_RespondeElFormatoDelEstandar()
    {
        var json = await _nodo.Http.GetFromJsonAsync<JsonElement>("api/status");
        Assert.Equal("NODO-03", json.GetProperty("nodeId").GetString());
        Assert.Equal("1.0", json.GetProperty("protocolVersion").GetString());
        Assert.Equal("online", json.GetProperty("status").GetString());
        Assert.True(json.GetProperty("acceptingPackages").GetBoolean());
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECC")]
    public async Task Certificado_SePublicaEnPem(string codigo)
    {
        var pem = await _nodo.Http.GetStringAsync($"api/certificate?algorithm={codigo}");
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
    }

    [Fact]
    public async Task PaqueteValido_202_YQuedaPendiente()
    {
        var p = Fabrica.Paquete();
        var r = await Enviar(p.Zip, p.NombreZip);
        Assert.Equal(HttpStatusCode.Accepted, r.StatusCode);
        var cuerpo = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Pendiente", cuerpo.GetProperty("status").GetString());
        Assert.Equal("X.509 OK", cuerpo.GetProperty("verification").GetString());

        var s = _nodo.Servicio<RepositorioNodo>().ObtenerSolicitudPorPaquete(p.Manifiesto.PacketId)!;
        Assert.Equal(EstadosSolicitud.Pendiente, s.Estado);
        Assert.Equal("127.0.0.1", s.OrigenIp);
        Assert.True(File.Exists(s.RutaZip));
    }

    [Fact]
    public async Task NoEsZip_400()
    {
        var r = await Enviar(Encoding.UTF8.GetBytes("esto no es un zip"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task FaltaCertificado_400()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a.Remove(EmpaquetadorZip.ArchivoCertificado));
        var r = await Enviar(zip);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("certificado.pem", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SinMultipart_400()
    {
        var r = await _nodo.Http.PostAsync("api/requests/receive", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task ShaAlterado_422_YQuedaRechazadaComoInvalida()
    {
        var p = Fabrica.Paquete();
        var zip = Fabrica.Modificar(p.Zip, a => a[EmpaquetadorZip.ArchivoDatos][5] ^= 0xFF);
        var r = await Enviar(zip, p.NombreZip);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, r.StatusCode);

        var s = _nodo.Servicio<RepositorioNodo>().ObtenerSolicitudPorPaquete(p.Manifiesto.PacketId)!;
        Assert.Equal(EstadosSolicitud.Rechazada, s.Estado);  // nunca llega a Pendiente
        Assert.Equal("Inválida", s.Verificacion);
    }

    [Fact]
    public async Task FirmaFalsificada_422()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a =>
            a[EmpaquetadorZip.ArchivoCertificado] = Encoding.ASCII.GetBytes(Identidades.Intruso.CertificadoPem("RSA")));
        var r = await Enviar(zip);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, r.StatusCode);
    }

    [Fact]
    public async Task MasGrandeQueElLimite_413()
    {
        // Este nodo se levantó con LimiteZipMb = 1.
        // "Expect: 100-continue": el cliente manda primero solo los encabezados y espera.
        // El nodo ve Content-Length > límite y contesta 413 SIN recibir el cuerpo. Sin esto,
        // en Windows el servidor corta la conexión mientras el cliente sigue subiendo los
        // 2 MB y la prueba ve "conexión interrumpida" en lugar del 413.
        using var peticion = new HttpRequestMessage(HttpMethod.Post, "api/requests/receive")
        {
            Content = Fabrica.Multipart(new byte[2 * 1024 * 1024], "grande.zip"),
        };
        peticion.Headers.ExpectContinue = true;
        var r = await _nodo.Http.SendAsync(peticion);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r.StatusCode);
    }

    [Fact]
    public async Task MismoPaqueteDosVeces_EsIdempotente()
    {
        var p = Fabrica.Paquete();
        var r1 = await Enviar(p.Zip, p.NombreZip);
        var r2 = await Enviar(p.Zip, p.NombreZip);
        Assert.Equal(HttpStatusCode.Accepted, r1.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, r2.StatusCode);
        Assert.True((await r2.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("duplicate").GetBoolean());
    }

    [Fact]
    public async Task NodoQueNoAceptaPaquetes_503()
    {
        await _nodo.Http.PutAsJsonAsync("api/local/ajustes", new { aceptandoPaquetes = false, algoritmosHabilitados = new[] { "RSA" } });
        var status = await _nodo.Http.GetFromJsonAsync<JsonElement>("api/status");
        Assert.False(status.GetProperty("acceptingPackages").GetBoolean());
        var r = await Enviar(Fabrica.Paquete().Zip);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
    }

    [Fact]
    public async Task Verificador_ReportaSinRegistrar()
    {
        var p = Fabrica.Paquete("ECC");
        var r = await _nodo.Http.PostAsync("api/local/verificar", Fabrica.Multipart(p.Zip, p.NombreZip));
        var json = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.GetProperty("validacion").GetProperty("valido").GetBoolean());
        Assert.Empty(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes());
    }
}
