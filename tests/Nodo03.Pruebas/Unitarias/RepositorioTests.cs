using Nodo03.Core.Datos;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Base de datos SQLite (sin servidor web).</summary>
public sealed class RepositorioTests : IDisposable
{
    private readonly string _ruta = Path.Combine(Path.GetTempPath(), $"nodo03-db-{Guid.NewGuid():N}.db");
    private readonly RepositorioNodo _repo;

    public RepositorioTests() => _repo = new RepositorioNodo(new BaseDatos(_ruta));

    private static Solicitud Nueva(string packetId) => new()
    {
        PacketId = packetId, NombreZip = "X.zip", OrigenIp = "1.1.1.1", NodoOrigen = "NODO-01",
        DireccionRespuesta = "1.1.1.1:5000", AlgoritmoCodigo = "RSA", Algoritmo = "RSA", Modo = "text",
        NombreOriginal = "m.txt", Sha256 = "ab", Verificacion = "X.509 OK", RutaZip = "/tmp/x.zip",
    };

    [Fact]
    public void PacketIdDuplicado_NoSeInsertaDosVeces()
    {
        Assert.True(_repo.InsertarSolicitud(Nueva("p1")));
        Assert.False(_repo.InsertarSolicitud(Nueva("p1")));
        Assert.Single(_repo.ListarSolicitudes());
    }

    [Fact]
    public void Aceptar_MueveAConsultas_UnaSolaVez()
    {
        var s = Nueva("p2");
        _repo.InsertarSolicitud(s);
        var c = _repo.Aceptar(s.Id);
        Assert.NotNull(c);
        Assert.Equal(OrigenesConsulta.Recibido, c!.Origen);
        Assert.Null(_repo.Aceptar(s.Id));            // segunda vez: ya no está Pendiente
        Assert.False(_repo.Rechazar(s.Id));          // ni se puede rechazar después
        Assert.Equal(1, _repo.ContarConsultas());
        Assert.Equal(EstadosSolicitud.Aceptada, _repo.ObtenerSolicitud(s.Id)!.Estado);
    }

    [Fact]
    public void Rechazar_NoEntraAConsultas()
    {
        var s = Nueva("p3");
        _repo.InsertarSolicitud(s);
        Assert.True(_repo.Rechazar(s.Id));
        Assert.Equal(0, _repo.ContarConsultas());
        Assert.Equal(0, _repo.ContarPendientes());
    }

    [Fact]
    public void TextoConAcentosYComillas_SeGuardaIntacto_SinInyeccionSql()
    {
        var s = Nueva("p4");
        s.NombreOriginal = "año'; DROP TABLE solicitudes; --.txt";
        _repo.InsertarSolicitud(s);
        Assert.Equal(s.NombreOriginal, _repo.ObtenerSolicitud(s.Id)!.NombreOriginal);
    }

    [Fact]
    public void Ajustes_YNodos_SePersisten()
    {
        _repo.GuardarAjuste("k", "v1");
        _repo.GuardarAjuste("k", "v2");
        Assert.Equal("v2", _repo.LeerAjuste("k"));

        _repo.GuardarNodo(new NodoConocido { Direccion = "10.0.0.1:5000", NodoId = "NODO-07", Estado = "en línea", CertificadoRsaPem = "pem" });
        _repo.GuardarNodo(new NodoConocido { Direccion = "10.0.0.1:5000", NodoId = "NODO-07", Estado = "sin respuesta" });
        var n = _repo.ObtenerNodo("10.0.0.1:5000")!;
        Assert.Equal("sin respuesta", n.Estado);
        Assert.Equal("pem", n.CertificadoRsaPem); // no se pierde el certificado si la segunda vez no respondió
    }

    public void Dispose()
    {
        foreach (var f in new[] { _ruta, _ruta + "-wal", _ruta + "-shm" })
            try { File.Delete(f); } catch (IOException) { }
    }
}
