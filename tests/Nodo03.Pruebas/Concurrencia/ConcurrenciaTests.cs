using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Concurrencia;

/// <summary>
/// VALIDACIÓN DE CONCURRENCIA. Cada prueba lanza muchas operaciones al mismo tiempo
/// (Task.WhenAll / Parallel) y comprueba que el resultado sea exactamente el que daría
/// hacerlas una por una: sin registros perdidos, sin duplicados y sin decisiones dobles.
/// </summary>
public sealed class ConcurrenciaTests : IAsyncLifetime
{
    private NodoDePrueba _nodo = null!;

    public async Task InitializeAsync() => _nodo = await NodoDePrueba.Iniciar(3);
    public async Task DisposeAsync() => await _nodo.DisposeAsync();

    [Fact]
    public async Task Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde()
    {
        const int n = 50;
        // Se arman antes para que la prueba mida al RECEPTOR, no al emisor.
        var paquetes = Enumerable.Range(0, n).Select(i => Fabrica.Paquete(i % 2 == 0 ? "RSA" : "ECC", $"mensaje {i}")).ToArray();
        var respuestas = await Task.WhenAll(paquetes.Select(p =>
            _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip))));

        Assert.All(respuestas, r => Assert.Equal(HttpStatusCode.Accepted, r.StatusCode));
        var repo = _nodo.Servicio<RepositorioNodo>();
        Assert.Equal(n, repo.ContarPendientes());
        Assert.Equal(n, repo.ListarSolicitudes().Select(s => s.PacketId).Distinct().Count());
    }

    [Fact]
    public async Task VeinticincoCopias_DelMismoPaquete_SoloSeRegistraUna_ElRestoEs409()
    {
        // Simula a un emisor que reintenta como loco por una red inestable.
        var p = Fabrica.Paquete();
        var respuestas = await Task.WhenAll(Enumerable.Range(0, 25).Select(_ =>
            _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip))));

        Assert.Equal(1, respuestas.Count(r => r.StatusCode == HttpStatusCode.Accepted));
        Assert.Equal(24, respuestas.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        Assert.Single(_nodo.Servicio<RepositorioNodo>().ListarSolicitudes());
        // Y no quedan zips huérfanos en disco de las copias descartadas.
        Assert.Single(Directory.GetFiles(Path.Combine(_nodo.Carpeta, "paquetes", "recibidos")));
    }

    [Fact]
    public async Task VeinteClicsEnAceptar_AlMismoTiempo_SoloUnoGana()
    {
        var p = Fabrica.Paquete();
        await _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip));
        var id = _nodo.Servicio<RepositorioNodo>().ListarSolicitudes().Single().Id;

        var respuestas = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            _nodo.Http.PostAsync($"api/local/solicitudes/{id}/aceptar", null)));

        Assert.Equal(1, respuestas.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(19, respuestas.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        Assert.Equal(1, _nodo.Servicio<RepositorioNodo>().ContarConsultas());
    }

    [Fact]
    public async Task AceptarYRechazar_AlMismoTiempo_QuedaUnSoloEstadoFinal()
    {
        var p = Fabrica.Paquete();
        await _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip));
        var id = _nodo.Servicio<RepositorioNodo>().ListarSolicitudes().Single().Id;

        var respuestas = await Task.WhenAll(Enumerable.Range(0, 20).Select(i =>
            _nodo.Http.PostAsync($"api/local/solicitudes/{id}/{(i % 2 == 0 ? "aceptar" : "rechazar")}", null)));

        Assert.Equal(1, respuestas.Count(r => r.StatusCode == HttpStatusCode.OK));
        var final = _nodo.Servicio<RepositorioNodo>().ObtenerSolicitud(id)!.Estado;
        // Coherencia: si quedó Aceptada hay 1 consulta; si quedó Rechazada, 0.
        Assert.Equal(final == EstadosSolicitud.Aceptada ? 1 : 0, _nodo.Servicio<RepositorioNodo>().ContarConsultas());
    }

    [Fact]
    public async Task TreintaPeticionesCripto_Simultaneas_LimiteDe10_SinErroresRaros()
    {
        // 13.3: máximo 10 /api/crypto/* a la vez; las demás reciben 503 E-BUSY (nunca otro error).
        var respuestas = await Task.WhenAll(Enumerable.Range(0, 30).Select(i =>
            _nodo.Http.PostAsync("api/crypto/forward", Fabrica.PeticionCripto(Fabrica.Request("forward", i % 2 == 0 ? "RSA" : "ECC"),
                Identidades.Eq05, Encoding.UTF8.GetBytes($"m{i}")))));
        var ok = respuestas.Count(r => r.StatusCode == HttpStatusCode.OK);
        var ocupado = respuestas.Where(r => r.StatusCode == HttpStatusCode.ServiceUnavailable).ToList();
        Assert.Equal(30, ok + ocupado.Count);
        Assert.True(ok >= 10, $"solo {ok} OK");
        foreach (var r in ocupado) Assert.Equal("E-BUSY", await r.Codigo());
        // Cada forward sin keyId generó su propia llave, sin choques de keyId.
        Assert.Equal(ok, _nodo.Servicio<RepositorioNodo>().ContarLlaves());
    }

    [Fact]
    public async Task DoscientasOperacionesCripto_ConLaMismaLlave_EnParalelo()
    {
        // La misma llave keyId se usa desde 16 hilos: cada operación importa su propia instancia.
        var lab = Fabrica.Lab;
        var keyId = lab.Forward().Manifiesto.KeyRef!.KeyId;
        var errores = new ConcurrentBag<string>();
        await Parallel.ForEachAsync(Enumerable.Range(0, 200), new ParallelOptions { MaxDegreeOfParallelism = 16 }, (i, _) =>
        {
            var texto = $"operación {i}";
            var p = lab.Forward(Diccionario.Rsa, texto, keyId);
            var leido = EmpaquetadorZip.Leer(p.Zip);
            try { ValidadorPaquete.Validar(leido, DateTime.UtcNow); } catch (ErrorProtocolo e) { errores.Add($"{i}: {e.Codigo}"); }
            var claro = Encoding.UTF8.GetString(lab.Proveedor.Inverse(leido, "EQ05"));
            if (claro != texto) errores.Add($"{i}: '{claro}'");
            return ValueTask.CompletedTask;
        });
        Assert.Empty(errores);
    }

    [Fact]
    public async Task DosNodos_DelegandoYEnviando_EnAmbasDirecciones()
    {
        await using var otro = await NodoDePrueba.Iniciar(13);
        await _nodo.Conocer(otro);
        await otro.Conocer(_nodo);
        const int porLado = 8;

        async Task<bool> Ciclo(NodoDePrueba de, string para, int i)
        {
            var f = await de.Servicio<ServicioSolicitante>().Forward(new EntradaForward(i % 2 == 0 ? "RSA" : "ECC",
                Encoding.UTF8.GetBytes($"msg {i}"), ModosCarga.Texto, "m.txt", [], null, null));
            return (await de.Servicio<ServicioEnvio>().EnviarABandeja(f.Consulta.Id, para)).Ok;
        }

        var resultados = await Task.WhenAll(Enumerable.Range(0, porLado).SelectMany(i => new[] { Ciclo(_nodo, "EQ13", i), Ciclo(otro, "EQ03", i) }));
        Assert.All(resultados, r => Assert.True(r));
        Assert.Equal(porLado, _nodo.Servicio<RepositorioNodo>().ContarPendientes());
        Assert.Equal(porLado, otro.Servicio<RepositorioNodo>().ContarPendientes());
    }

    [Fact]
    public async Task BaseDeDatos_CienEscriturasParalelas_SinErroresDeBloqueo()
    {
        var repo = _nodo.Servicio<RepositorioNodo>();
        await Parallel.ForEachAsync(Enumerable.Range(0, 100), async (i, _) =>
        {
            repo.Registrar("prueba", $"evento {i}");
            repo.InsertarSolicitud(new Solicitud
            {
                PacketId = $"pkt-{i}", NombreZip = "x.zip", OrigenIp = "1.1.1.1", NodoOrigen = "EQ05", NodoProductor = "EQ03",
                DireccionRespuesta = "", AlgoritmoCodigo = "RSA", AlgoritmoNombre = "RSA", Operacion = "forward",
                OperacionNombre = "cifrar", Modo = "text", NombreOriginal = "m", Sha256 = "s", RutaZip = "",
            });
            repo.RegistrarPeticion($"req-{i % 50}");   // la mitad son repetidos: no debe tronar
            await Task.Yield();
        });
        Assert.Equal(100, repo.ContarPendientes());
        Assert.Equal(100, repo.ListarBitacora(500).Count(e => e.Tipo == "prueba"));
    }
}
