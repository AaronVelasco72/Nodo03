using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Integracion;

/// <summary>
/// DOS nodos reales: EQ03 (proveedor de RSA/ECC) y EQ13 (un nodo que solo es solicitante, como
/// lo sería el de cualquier otro equipo). Flujos 11.1 a 11.4 y ping-pong de punta a punta.
/// </summary>
public sealed class FlujoEntreNodosTests : IAsyncLifetime
{
    private NodoDePrueba _eq03 = null!;
    private NodoDePrueba _eq13 = null!;

    public async Task InitializeAsync()
    {
        _eq03 = await NodoDePrueba.Iniciar(3);
        _eq13 = await NodoDePrueba.Iniciar(13);
    }

    public async Task DisposeAsync()
    {
        await _eq13.DisposeAsync();
        await _eq03.DisposeAsync();
    }

    private async Task ConocerseMutuamente()
    {
        await _eq03.Conocer(_eq13);
        await _eq13.Conocer(_eq03);
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECC")]
    public async Task ForwardDelegado_Bandeja_Aceptar_InverseLocal(string algoritmo)
    {
        await ConocerseMutuamente();
        var sol13 = _eq13.Servicio<ServicioSolicitante>();

        // 11.2 EQ13 le pide a EQ03 que cifre
        var f = await sol13.Forward(new EntradaForward(algoritmo, Encoding.UTF8.GetBytes("¡Hola desde EQ13!"), ModosCarga.Texto, "mensaje.txt", [], null, null));
        Assert.True(f.Delegado);
        Assert.Equal("EQ03", f.Ejecutor);
        Assert.Equal(OrigenesConsulta.Generado, f.Consulta.Origen);
        Assert.Equal(Verificaciones.FirmaOk, f.Consulta.Verificacion);

        // 11.4 EQ13 descifra su propio paquete delegando a EQ03
        var inv = await sol13.Inverse(f.Consulta.Id, null);
        Assert.True(inv.Delegado);
        Assert.Equal("¡Hola desde EQ13!", Encoding.UTF8.GetString(inv.Original!));
        Assert.Equal(OrigenesConsulta.Resultado, inv.Consulta.Origen);
        Assert.StartsWith("RES_EQ03_", inv.Consulta.NombreZip);

        // 11.3 EQ13 lo manda a la bandeja de EQ03 (reempaquetado 9.6)
        var e = await _eq13.Servicio<ServicioEnvio>().EnviarABandeja(f.Consulta.Id, "EQ03");
        Assert.True(e.Ok, e.Mensaje);
        Assert.StartsWith("EQ13_" + algoritmo, e.NombreZip);
        var repo03 = _eq03.Servicio<RepositorioNodo>();
        var s = Assert.Single(repo03.ListarSolicitudes());
        Assert.Equal("EQ13", s.NodoOrigen);
        Assert.Equal("EQ03", s.NodoProductor);
        Assert.Equal(Verificaciones.FirmaOk, s.Verificacion);       // EQ13 está fijado en EQ03

        // Aceptar → Consultas (Recibido) → inverse local en EQ03
        var c = repo03.Aceptar(s.Id)!;
        var local = await _eq03.Servicio<ServicioSolicitante>().Inverse(c.Id, null);
        Assert.False(local.Delegado);
        Assert.Equal("¡Hola desde EQ13!", Encoding.UTF8.GetString(local.Original!));
        Assert.Equal(OrigenesConsulta.Resultado, local.Consulta.Origen);
    }

    [Fact]
    public async Task Imagen_ViajaIntacta()
    {
        await ConocerseMutuamente();
        var imagen = System.Security.Cryptography.RandomNumberGenerator.GetBytes(300_000);
        var sol = _eq13.Servicio<ServicioSolicitante>();
        var f = await sol.Forward(new EntradaForward("RSA", imagen, ModosCarga.Imagen, "foto.png", [], null, null));
        Assert.Equal("image/png", Nodo03.Core.Protocolo.EmpaquetadorZip.Leer(File.ReadAllBytes(f.Consulta.RutaZip)).Manifiesto.ContentType);
        Assert.Equal(imagen, (await sol.Inverse(f.Consulta.Id, null)).Original);
    }

    [Fact]
    public async Task SinConfirmarHuella_ElAlgoritmoNoEstaDisponible()
    {
        var r = await _eq13.Servicio<ServicioDirectorio>().AltaManual(_eq03.Direccion);
        Assert.True(r.Ok, r.Mensaje);
        var ex = await Assert.ThrowsAsync<ErrorOperacionException>(() => _eq13.Servicio<ServicioSolicitante>()
            .Forward(new EntradaForward("RSA", "x"u8.ToArray(), ModosCarga.Texto, "m.txt", [], null, null)));
        Assert.Contains("Confirma la huella", ex.Message);
    }

    [Fact]
    public async Task AlgoritmoDeOtroEquipo_SinDueno_NoDisponible()
    {
        var ex = await Assert.ThrowsAsync<ErrorOperacionException>(() => _eq13.Servicio<ServicioSolicitante>()
            .Forward(new EntradaForward("AESGCM", "x"u8.ToArray(), ModosCarga.Texto, "m.txt", [], new() { ["key"] = "AAAA" }, null)));
        Assert.Contains("EQ01 no está en el directorio", ex.Message);
    }

    [Fact]
    public async Task HuellaCambia_SeAlerta_YNoSeUsaHastaReconfirmar()
    {
        await _eq13.Conocer(_eq03);
        var repo = _eq13.Servicio<RepositorioNodo>();
        var dir = _eq13.Servicio<ServicioDirectorio>();
        // Simulamos que EQ03 regeneró su certificado: la huella fijada ya no coincide.
        var n = repo.ObtenerNodo("EQ03")!;
        n.HuellaFijada = new string('A', 64);
        repo.GuardarNodo(n);
        Assert.True((await dir.AltaManual(_eq03.Direccion)).Ok);
        Assert.True(repo.ObtenerNodo("EQ03")!.Alerta);
        Assert.Contains("huella distinta", dir.Proveedor(Diccionario.PorCodigo("RSA")!).Motivo);
        Assert.Contains(repo.ListarBitacora(), b => b.Tipo == "alerta");

        dir.Confirmar("EQ03");
        Assert.NotNull(dir.Proveedor(Diccionario.PorCodigo("RSA")!).Nodo);
    }

    [Fact]
    public async Task PingPongAutomatico_RebotaHastaElLimite()
    {
        await ConocerseMutuamente();
        foreach (var n in new[] { _eq03, _eq13 })
        {
            var aj = n.Servicio<AjustesNodo>();
            aj.Guardar(aj.Actual with { RebotarAutomatico = true, MaxRebotes = 4, PausaRebotesMs = 0 });
        }
        var f = await _eq13.Servicio<ServicioSolicitante>().Forward(new EntradaForward("ECC", "pelota"u8.ToArray(), ModosCarga.Texto, "pelota.txt", [], null, null));
        Assert.True((await _eq13.Servicio<ServicioEnvio>().EnviarABandeja(f.Consulta.Id, "EQ03")).Ok);

        // Saltos: EQ13→EQ03 (0) · EQ03→EQ13 (1) · EQ13→EQ03 (2) · EQ03→EQ13 (3) · EQ13→EQ03 (4, se detiene)
        var r03 = _eq03.Servicio<RepositorioNodo>();
        var r13 = _eq13.Servicio<RepositorioNodo>();
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => r03.ListarSolicitudes().Any(s => s.Salto == 4), 40_000),
            string.Join(" | ", r03.ListarBitacora(30).Select(b => b.Mensaje)));
        await Task.Delay(500);
        Assert.Equal(new[] { 0, 2, 4 }, r03.ListarSolicitudes().Select(s => s.Salto).Order().ToArray());
        Assert.Equal(new[] { 1, 3 }, r13.ListarSolicitudes().Select(s => s.Salto).Order().ToArray());
        Assert.Single(r03.ListarSolicitudes(EstadosSolicitud.Pendiente));     // la última ya no rebota
        Assert.Equal(1, r03.ListarSolicitudes().Select(s => s.RallyId).Distinct().Count());
    }

    [Fact]
    public async Task ReboteManual_RegresaLaPelota()
    {
        await ConocerseMutuamente();
        var f = await _eq13.Servicio<ServicioSolicitante>().Forward(new EntradaForward("RSA", "ida"u8.ToArray(), ModosCarga.Texto, "m.txt", [], null, null));
        await _eq13.Servicio<ServicioEnvio>().EnviarABandeja(f.Consulta.Id, "EQ03");
        var r03 = _eq03.Servicio<RepositorioNodo>();
        var c = r03.Aceptar(r03.ListarSolicitudes().Single().Id)!;
        var r = await _eq03.Servicio<ServicioEnvio>().Rebotar(c.Id, null);
        Assert.True(r.Ok, r.Mensaje);
        var s = Assert.Single(_eq13.Servicio<RepositorioNodo>().ListarSolicitudes());
        Assert.Equal(1, s.Salto);
        Assert.Equal("EQ03", s.NodoOrigen);
    }

    [Fact]
    public async Task Escaneo_EncuentraAlOtroNodo()
    {
        var puerto = int.Parse(_eq03.Direccion.Split(':')[1]);
        var n = await _eq13.Servicio<ServicioDirectorio>().Escanear([IPAddress.Loopback], puertos: [puerto]);
        Assert.True(n >= 1);
        var nodo = _eq13.Servicio<RepositorioNodo>().ObtenerNodo("EQ03")!;
        Assert.Equal("scan", nodo.Fuente);
        Assert.Null(nodo.HuellaFijada);           // encontrado, pero falta que el usuario confirme
    }
}

/// <summary>Descubrimiento UDP real (sección 6.1) en un puerto de prueba.</summary>
public sealed class DescubrimientoUdpTests : IAsyncLifetime
{
    private NodoDePrueba _eq03 = null!;
    private NodoDePrueba _escucha = null!;
    private int _puertoUdp;

    public async Task InitializeAsync()
    {
        _puertoUdp = Random.Shared.Next(42000, 48000);
        _eq03 = await NodoDePrueba.Iniciar(3);
        _escucha = await NodoDePrueba.Iniciar(13, o => { o.Descubrimiento = true; o.PuertoUdp = _puertoUdp; o.IntervaloAnuncioSegundos = 3600; });
    }

    public async Task DisposeAsync()
    {
        await _escucha.DisposeAsync();
        await _eq03.DisposeAsync();
    }

    private byte[] Anuncio(Action<Dictionary<string, object?>>? cambio = null)
    {
        var a = new Dictionary<string, object?>
        {
            ["type"] = "CC-BEACON", ["protocolVersion"] = "2.0", ["nodeId"] = "EQ03", ["teamNumber"] = 3,
            ["ip"] = "127.0.0.1", ["httpPort"] = int.Parse(_eq03.Direccion.Split(':')[1]), ["httpsPort"] = null,
            ["status"] = "online", ["algorithms"] = new[] { "RSA", "ECC" },
            ["certificateThumbprintSha256"] = _eq03.Servicio<Nodo03.Core.Cripto.IdentidadNodo>().Huella,
            ["timestampUtc"] = Identificadores.FormatoFecha(DateTime.UtcNow),
        };
        cambio?.Invoke(a);
        return JsonSerializer.SerializeToUtf8Bytes(a);
    }

    [Fact]
    public async Task AnuncioUdp_DaDeAltaAlNodo_TrasVerificarloPorHttp()
    {
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => _escucha.Servicio<Descubrimiento>().Activo, 5000));
        using var udp = new UdpClient();
        await udp.SendAsync(Anuncio(), new IPEndPoint(IPAddress.Loopback, _puertoUdp));

        var repo = _escucha.Servicio<RepositorioNodo>();
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => repo.ObtenerNodo("EQ03") is not null, 10_000));
        var n = repo.ObtenerNodo("EQ03")!;
        Assert.Equal("beacon", n.Fuente);
        Assert.Equal("online", n.Estado);
        Assert.Equal(new[] { "RSA", "ECC" }, n.ListaAlgoritmos);

        // Anuncio de apagado → offline
        await udp.SendAsync(Anuncio(a => a["status"] = "offline"), new IPEndPoint(IPAddress.Loopback, _puertoUdp));
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => repo.ObtenerNodo("EQ03")!.Estado == "offline", 5000));
    }

    [Fact]
    public async Task AnuncioConHuellaFalsa_NoSeDaDeAlta()
    {
        Assert.True(await ExtensionesPrueba.EsperarHasta(() => _escucha.Servicio<Descubrimiento>().Activo, 5000));
        using var udp = new UdpClient();
        await udp.SendAsync(Anuncio(a => a["certificateThumbprintSha256"] = new string('F', 64)), new IPEndPoint(IPAddress.Loopback, _puertoUdp));
        await Task.Delay(1500);
        Assert.Null(_escucha.Servicio<RepositorioNodo>().ObtenerNodo("EQ03"));
    }

    [Fact]
    public void Interpretar_IgnoraPropiosYMalFormados()
    {
        var bueno = Anuncio();
        Assert.NotNull(Descubrimiento.Interpretar(bueno, "EQ13"));
        Assert.Null(Descubrimiento.Interpretar(bueno, "EQ03"));                                       // propio
        Assert.Null(Descubrimiento.Interpretar(Anuncio(a => a["type"] = "OTRO"), "EQ13"));
        Assert.Null(Descubrimiento.Interpretar(Anuncio(a => a["protocolVersion"] = "1.0"), "EQ13"));
        Assert.Null(Descubrimiento.Interpretar(Anuncio(a => a["teamNumber"] = 4), "EQ13"));          // no cuadra con EQ03
        Assert.Null(Descubrimiento.Interpretar(new byte[1025], "EQ13"));                              // > 1024 bytes
        Assert.Null(Descubrimiento.Interpretar("no json"u8.ToArray(), "EQ13"));
    }

    [Fact]
    public void AnuncioPropio_CabeEnUnKilobyte()
    {
        var d = _escucha.Servicio<Descubrimiento>().Anuncio("192.168.100.200");
        Assert.True(d.Length <= 1024);
        using var j = JsonDocument.Parse(d);
        Assert.Equal("CC-BEACON", j.RootElement.GetProperty("type").GetString());
        Assert.Equal("EQ13", j.RootElement.GetProperty("nodeId").GetString());
    }
}
