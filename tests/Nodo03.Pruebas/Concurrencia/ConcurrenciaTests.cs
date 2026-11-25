using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Concurrencia;

/// <summary>
/// VALIDACIÓN DE CONCURRENCIA. Cada prueba lanza muchas operaciones al mismo tiempo
/// (Task.WhenAll) y comprueba que el resultado sea exactamente el que daría hacerlas
/// una por una: sin registros perdidos, sin duplicados y sin decisiones dobles.
/// </summary>
public sealed class ConcurrenciaTests : IAsyncLifetime
{
    private NodoDePrueba _nodo = null!;

    public async Task InitializeAsync() => _nodo = await NodoDePrueba.Iniciar("NODO-03");
    public async Task DisposeAsync() => await _nodo.DisposeAsync();

    [Fact]
    public async Task Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde()
    {
        const int n = 50;
        // Se arman antes para que la prueba mida al RECEPTOR, no al emisor.
        var paquetes = Enumerable.Range(0, n)
            .Select(i => Fabrica.Paquete(i % 2 == 0 ? "RSA" : "ECC", $"mensaje {i}")).ToArray();

        var respuestas = await Task.WhenAll(paquetes.Select(p =>
            _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip))));

        Assert.All(respuestas, r => Assert.Equal(HttpStatusCode.Accepted, r.StatusCode));
        var repo = _nodo.Servicio<RepositorioNodo>();
        Assert.Equal(n, repo.ContarPendientes());
        Assert.Equal(n, repo.ListarSolicitudes().Select(s => s.PacketId).Distinct().Count());
    }

    [Fact]
    public async Task VeinticincoCopias_DelMismoPaquete_SoloSeRegistraUna()
    {
        // Simula a un emisor que reintenta como loco por una red inestable.
        var p = Fabrica.Paquete();
        var respuestas = await Task.WhenAll(Enumerable.Range(0, 25).Select(_ =>
            _nodo.Http.PostAsync("api/requests/receive", Fabrica.Multipart(p.Zip, p.NombreZip))));

        Assert.All(respuestas, r => Assert.Equal(HttpStatusCode.Accepted, r.StatusCode));
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

        var tareas = Enumerable.Range(0, 20).Select(i =>
            _nodo.Http.PostAsync($"api/local/solicitudes/{id}/{(i % 2 == 0 ? "aceptar" : "rechazar")}", null));
        var respuestas = await Task.WhenAll(tareas);

        Assert.Equal(1, respuestas.Count(r => r.StatusCode == HttpStatusCode.OK));
        var final = _nodo.Servicio<RepositorioNodo>().ObtenerSolicitud(id)!.Estado;
        var consultas = _nodo.Servicio<RepositorioNodo>().ContarConsultas();
        // Coherencia: si quedó Aceptada hay 1 consulta; si quedó Rechazada, 0.
        Assert.Equal(final == EstadosSolicitud.Aceptada ? 1 : 0, consultas);
    }

    [Fact]
    public async Task DosNodos_EnviandoseALaVez_EnAmbasDirecciones()
    {
        await using var otro = await NodoDePrueba.Iniciar("NODO-05");
        const int porLado = 15;

        async Task<ResultadoEnvio> Enviar(NodoDePrueba de, NodoDePrueba para, int i)
        {
            var f = new MultipartFormDataContent
            {
                { new StringContent("text"), "modo" }, { new StringContent($"msg {i}"), "texto" },
                { new StringContent(i % 2 == 0 ? "RSA" : "ECC"), "algoritmo" },
                { new StringContent("remoto"), "destinatario" }, { new StringContent(para.Direccion), "direccion" },
            };
            return (await (await de.Http.PostAsync("api/local/enviar", f)).Content.ReadFromJsonAsync<ResultadoEnvio>())!;
        }

        var tareas = Enumerable.Range(0, porLado).SelectMany(i => new[] { Enviar(_nodo, otro, i), Enviar(otro, _nodo, i) });
        var resultados = await Task.WhenAll(tareas);

        Assert.All(resultados, r => Assert.True(r.Ok, r.Mensaje));
        Assert.Equal(porLado, _nodo.Servicio<RepositorioNodo>().ContarPendientes());
        Assert.Equal(porLado, otro.Servicio<RepositorioNodo>().ContarPendientes());
    }

    [Fact]
    public async Task DoscientasOperacionesCripto_ConLaMismaIdentidad_EnParalelo()
    {
        // La identidad se comparte entre hilos: cada operación crea su propia instancia
        // de RSA/ECDsa a partir de los parámetros, así que no debe haber interferencia.
        var errores = new ConcurrentBag<string>();
        await Parallel.ForEachAsync(Enumerable.Range(0, 200), new ParallelOptions { MaxDegreeOfParallelism = 16 },
            (i, _) =>
            {
                var codigo = i % 2 == 0 ? CodigosAlgoritmo.Rsa : CodigosAlgoritmo.Ecc;
                var texto = $"operación {i}";
                var p = Fabrica.Paquete(codigo, texto);
                var leido = EmpaquetadorZip.Leer(p.Zip);
                if (!ValidadorPaquete.Validar(leido).Valido) errores.Add($"{i}: firma");
                var claro = Encoding.UTF8.GetString(ServicioPaquetes.Abrir(leido, Identidades.B).Bytes);
                if (claro != texto) errores.Add($"{i}: '{claro}'");
                return ValueTask.CompletedTask;
            });
        Assert.Empty(errores);
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
                PacketId = $"pkt-{i}", NombreZip = "x.zip", OrigenIp = "1.1.1.1", NodoOrigen = "N", DireccionRespuesta = "",
                AlgoritmoCodigo = "RSA", Algoritmo = "RSA", Modo = "text", NombreOriginal = "m", Sha256 = "s",
                Verificacion = "X.509 OK", RutaZip = "",
            });
            await Task.Yield();
        });
        Assert.Equal(100, repo.ContarPendientes());
        Assert.Equal(100, repo.ListarBitacora(500).Count(e => e.Tipo == "prueba"));
    }
}
