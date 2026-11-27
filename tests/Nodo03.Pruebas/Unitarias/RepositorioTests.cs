using Nodo03.Core.Datos;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Base de datos SQLite (sin servidor web).</summary>
public sealed class RepositorioTests : IDisposable
{
    private readonly string _ruta = Path.Combine(Path.GetTempPath(), $"nodo03-db-{Guid.NewGuid():N}.db");
    private readonly RepositorioNodo _repo;

    public RepositorioTests() => _repo = new RepositorioNodo(new BaseDatos(_ruta));

    private static Solicitud Nueva(string packetId, string verificacion = Verificaciones.FirmaOk) => new()
    {
        PacketId = packetId, NombreZip = "EQ05_RSA_20261127_120000_ABCDEF12.zip", OrigenIp = "1.1.1.1", NodoOrigen = "EQ05",
        NodoProductor = "EQ03", DireccionRespuesta = "1.1.1.1:5005", AlgoritmoCodigo = "RSA", AlgoritmoNombre = "RSA-OAEP",
        Operacion = "forward", OperacionNombre = "cifrar", Modo = "text", NombreOriginal = "m.txt", Sha256 = "ab",
        Verificacion = verificacion, RutaZip = "/tmp/x.zip",
    };

    [Fact]
    public void PacketIdDuplicado_NoSeInsertaDosVeces()
    {
        Assert.True(_repo.InsertarSolicitud(Nueva("p1")));
        Assert.False(_repo.InsertarSolicitud(Nueva("p1")));
        Assert.True(_repo.ExistePaquete("p1"));
        Assert.Single(_repo.ListarSolicitudes());
    }

    [Fact]
    public void PaquetesInvalidos_SeGuardanComoEvidencia_SinBloquearAlValido()
    {
        // Un intento inválido con el mismo packetId no impide que luego llegue el bueno.
        Assert.True(_repo.InsertarSolicitud(Nueva("p9", Verificaciones.Invalida)));
        Assert.False(_repo.ExistePaquete("p9"));
        Assert.True(_repo.InsertarSolicitud(Nueva("p9")));
        Assert.Equal(2, _repo.ListarSolicitudes().Count);
    }

    [Fact]
    public void Aceptar_MueveAConsultas_UnaSolaVez()
    {
        var s = Nueva("p2");
        _repo.InsertarSolicitud(s);
        var c = _repo.Aceptar(s.Id);
        Assert.NotNull(c);
        Assert.Equal(OrigenesConsulta.Recibido, c!.Origen);
        Assert.Equal("EQ03", c.NodoProductor);
        Assert.Equal("cifrar", c.OperacionNombre);
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
    public void Directorio_GuardaHuellaFijadaYAlerta()
    {
        _repo.GuardarNodo(new NodoConocido { NodeId = "EQ07", Equipo = 7, Ip = "10.0.0.7", HttpPort = 5007, HuellaPresentada = "AA", Algoritmos = "MILLERRABIN,FISHERYATES", Fuente = "beacon", Estado = "online" });
        var n = _repo.ObtenerNodo("EQ07")!;
        Assert.False(n.Confiable);                       // aún no se confirma la huella
        n.HuellaFijada = "AA";
        _repo.GuardarNodo(n);
        Assert.True(_repo.ObtenerNodo("EQ07")!.Confiable);
        n.HuellaPresentada = "BB"; n.Alerta = true;
        _repo.GuardarNodo(n);
        var cambiado = _repo.ObtenerNodo("EQ07")!;
        Assert.False(cambiado.Confiable);
        Assert.Equal("AA", cambiado.HuellaFijada);       // la fijada no se pierde
        Assert.Equal(new[] { "MILLERRABIN", "FISHERYATES" }, cambiado.ListaAlgoritmos);
        Assert.Equal("10.0.0.7:5007", cambiado.Direccion);
    }

    [Fact]
    public void RequestId_SoloSeAceptaUnaVez()
    {
        Assert.True(_repo.RegistrarPeticion("r1"));
        Assert.False(_repo.RegistrarPeticion("r1"));
    }

    [Fact]
    public void Llaves_SeListanSinLaPrivada()
    {
        _repo.GuardarLlave(new LlaveAlgoritmo { KeyId = "EQ03-KEY-1", Algoritmo = "RSA", PublicaSpkiBase64 = "pub", PrivadaPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----", Permitidos = "EQ05" });
        var k = Assert.Single(_repo.ListarLlaves());
        Assert.Equal("", k.PrivadaPem);
        Assert.Equal("-----BEGIN ENCRYPTED PRIVATE KEY-----", _repo.ObtenerLlave("EQ03-KEY-1")!.PrivadaPem);
    }

    [Fact]
    public void Ajustes_SePersisten()
    {
        _repo.GuardarAjuste("k", "v1");
        _repo.GuardarAjuste("k", "v2");
        Assert.Equal("v2", _repo.LeerAjuste("k"));
    }

    public void Dispose()
    {
        foreach (var f in new[] { _ruta, _ruta + "-wal", _ruta + "-shm" })
            try { File.Delete(f); } catch (IOException) { }
    }
}
