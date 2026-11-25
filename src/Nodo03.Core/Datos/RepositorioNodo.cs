namespace Nodo03.Core.Datos;

// =====================================================================
//  Modelos que se guardan en la base de datos
// =====================================================================

/// <summary>Estados de una solicitud en la bandeja (sección 4 de la propuesta).</summary>
public static class EstadosSolicitud
{
    public const string Pendiente = "Pendiente";
    public const string Aceptada = "Aceptada";
    public const string Rechazada = "Rechazada";
}

/// <summary>Origen de un registro en Consultas.</summary>
public static class OrigenesConsulta
{
    /// <summary>Llegó por IP y el usuario lo aceptó.</summary>
    public const string Recibido = "Recibido";
    /// <summary>Lo armó este nodo y lo envió a otra IP.</summary>
    public const string Enviado = "Enviado";
    /// <summary>Lo armó este nodo solo para descargarlo (sin enviar).</summary>
    public const string Generado = "Generado";
}

/// <summary>Un paquete que llegó por <c>POST /api/requests/receive</c> (bandeja "Solicitudes").</summary>
public sealed class Solicitud
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string PacketId { get; set; } = "";
    public string NombreZip { get; set; } = "";
    /// <summary>IP real de la conexión TCP (no se puede falsificar tan fácil como sourceIp).</summary>
    public string OrigenIp { get; set; } = "";
    public string NodoOrigen { get; set; } = "";
    /// <summary>sourceIp declarado en el manifiesto ("IP:Puerto" para responder).</summary>
    public string DireccionRespuesta { get; set; } = "";
    public string AlgoritmoCodigo { get; set; } = "";
    public string Algoritmo { get; set; } = "";
    public string Modo { get; set; } = "";
    public string NombreOriginal { get; set; } = "";
    public long TamanoOriginal { get; set; }
    public string Sha256 { get; set; } = "";
    /// <summary>"X.509 OK" o "Inválida".</summary>
    public string Verificacion { get; set; } = "";
    /// <summary>ResultadoValidacion completo en JSON (errores, avisos, datos del certificado).</summary>
    public string DetalleJson { get; set; } = "{}";
    public string RutaZip { get; set; } = "";
    public string Estado { get; set; } = EstadosSolicitud.Pendiente;
    public DateTime RecibidoUtc { get; set; } = DateTime.UtcNow;
    public DateTime? DecididoUtc { get; set; }
    public int Salto { get; set; }
    public string RallyId { get; set; } = "";
}

/// <summary>Registro de la tabla principal "Consultas".</summary>
public sealed class Consulta
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? SolicitudId { get; set; }
    public string PacketId { get; set; } = "";
    public string NombreZip { get; set; } = "";
    public string Origen { get; set; } = OrigenesConsulta.Recibido;
    /// <summary>Nodo del otro lado (emisor si es Recibido, destino si es Enviado).</summary>
    public string NodoRemoto { get; set; } = "";
    /// <summary>"IP:Puerto" del otro lado.</summary>
    public string Direccion { get; set; } = "";
    public string AlgoritmoCodigo { get; set; } = "";
    public string Modo { get; set; } = "";
    public string NombreOriginal { get; set; } = "";
    public long TamanoOriginal { get; set; }
    public string Sha256 { get; set; } = "";
    public string Verificacion { get; set; } = "";
    public string RutaZip { get; set; } = "";
    public DateTime FechaUtc { get; set; } = DateTime.UtcNow;
    public int Salto { get; set; }
    public string RallyId { get; set; } = "";
    /// <summary>Resultado del envío, ej. "202 Accepted" (solo para Enviado).</summary>
    public string? ResultadoEnvio { get; set; }
}

/// <summary>Entrada de la bitácora (lo que se ve en el "rally" del panel).</summary>
public sealed record EventoBitacora(long Id, DateTime FechaUtc, string Tipo, string Mensaje, string? RallyId, int? Salto);

/// <summary>Otro nodo conocido (directorio de células).</summary>
public sealed class NodoConocido
{
    public string Direccion { get; set; } = "";
    public string NodoId { get; set; } = "";
    public string Estado { get; set; } = "desconocido";
    public DateTime? VistoUtc { get; set; }
    public string? CertificadoRsaPem { get; set; }
    public string? CertificadoEccPem { get; set; }
}

// =====================================================================
//  Repositorio
// =====================================================================

/// <summary>
/// Todas las operaciones de base de datos del nodo. Esquema:
/// <code>
/// solicitudes (bandeja)   consultas (archivo)   bitacora (eventos)   nodos (directorio)   ajustes (clave/valor)
/// </code>
/// </summary>
public sealed class RepositorioNodo
{
    private readonly BaseDatos _db;

    public RepositorioNodo(BaseDatos db)
    {
        _db = db;
        CrearEsquema();
    }

    /// <summary>Crea las tablas si no existen (idempotente: se puede llamar cada arranque).</summary>
    private void CrearEsquema()
    {
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS solicitudes (
              id TEXT PRIMARY KEY,
              packet_id TEXT NOT NULL UNIQUE,          -- UNIQUE = detección de duplicados
              nombre_zip TEXT NOT NULL,
              origen_ip TEXT NOT NULL,
              nodo_origen TEXT NOT NULL,
              direccion_respuesta TEXT NOT NULL,
              algoritmo_codigo TEXT NOT NULL,
              algoritmo TEXT NOT NULL,
              modo TEXT NOT NULL,
              nombre_original TEXT NOT NULL,
              tamano_original INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              verificacion TEXT NOT NULL,
              detalle_json TEXT NOT NULL,
              ruta_zip TEXT NOT NULL,
              estado TEXT NOT NULL CHECK (estado IN ('Pendiente','Aceptada','Rechazada')),
              recibido_utc TEXT NOT NULL,
              decidido_utc TEXT,
              salto INTEGER NOT NULL DEFAULT 0,
              rally_id TEXT NOT NULL DEFAULT ''
            );
            """);
        _db.Ejecutar("CREATE INDEX IF NOT EXISTS ix_solicitudes_estado ON solicitudes(estado, recibido_utc);");
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS consultas (
              id TEXT PRIMARY KEY,
              solicitud_id TEXT UNIQUE REFERENCES solicitudes(id), -- una solicitud aceptada => 1 consulta máx.
              packet_id TEXT NOT NULL,
              nombre_zip TEXT NOT NULL,
              origen TEXT NOT NULL CHECK (origen IN ('Recibido','Enviado','Generado')),
              nodo_remoto TEXT NOT NULL,
              direccion TEXT NOT NULL,
              algoritmo_codigo TEXT NOT NULL,
              modo TEXT NOT NULL,
              nombre_original TEXT NOT NULL,
              tamano_original INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              verificacion TEXT NOT NULL,
              ruta_zip TEXT NOT NULL,
              fecha_utc TEXT NOT NULL,
              salto INTEGER NOT NULL DEFAULT 0,
              rally_id TEXT NOT NULL DEFAULT '',
              resultado_envio TEXT
            );
            """);
        _db.Ejecutar("CREATE INDEX IF NOT EXISTS ix_consultas_fecha ON consultas(fecha_utc);");
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS bitacora (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              fecha_utc TEXT NOT NULL,
              tipo TEXT NOT NULL,
              mensaje TEXT NOT NULL,
              rally_id TEXT,
              salto INTEGER
            );
            """);
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS nodos (
              direccion TEXT PRIMARY KEY,
              nodo_id TEXT NOT NULL,
              estado TEXT NOT NULL,
              visto_utc TEXT,
              cert_rsa_pem TEXT,
              cert_ecc_pem TEXT
            );
            """);
        _db.Ejecutar("CREATE TABLE IF NOT EXISTS ajustes (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);");
    }

    // ------------------------------------------------------------------ Solicitudes

    /// <summary>
    /// Inserta la solicitud. Devuelve <c>false</c> si ya existía una con el mismo packetId
    /// (reenvío duplicado). Gracias al índice UNIQUE esto es correcto aunque lleguen
    /// 20 copias del mismo paquete al mismo tiempo: solo una se inserta.
    /// </summary>
    public bool InsertarSolicitud(Solicitud s) => _db.Ejecutar("""
        INSERT OR IGNORE INTO solicitudes (id, packet_id, nombre_zip, origen_ip, nodo_origen, direccion_respuesta,
          algoritmo_codigo, algoritmo, modo, nombre_original, tamano_original, sha256, verificacion, detalle_json,
          ruta_zip, estado, recibido_utc, decidido_utc, salto, rally_id)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20);
        """, s.Id, s.PacketId, s.NombreZip, s.OrigenIp, s.NodoOrigen, s.DireccionRespuesta, s.AlgoritmoCodigo,
        s.Algoritmo, s.Modo, s.NombreOriginal, s.TamanoOriginal, s.Sha256, s.Verificacion, s.DetalleJson,
        s.RutaZip, s.Estado, s.RecibidoUtc, s.DecididoUtc, s.Salto, s.RallyId) == 1;

    public Solicitud? ObtenerSolicitud(string id) =>
        _db.Consultar("SELECT * FROM solicitudes WHERE id = ?1", id).Select(ASolicitud).FirstOrDefault();

    public Solicitud? ObtenerSolicitudPorPaquete(string packetId) =>
        _db.Consultar("SELECT * FROM solicitudes WHERE packet_id = ?1", packetId).Select(ASolicitud).FirstOrDefault();

    public List<Solicitud> ListarSolicitudes(string? estado = null, int limite = 500) =>
        (estado is null
            ? _db.Consultar("SELECT * FROM solicitudes ORDER BY recibido_utc DESC LIMIT ?1", limite)
            : _db.Consultar("SELECT * FROM solicitudes WHERE estado = ?1 ORDER BY recibido_utc DESC LIMIT ?2", estado, limite))
        .Select(ASolicitud).ToList();

    public long ContarPendientes() =>
        (long)(_db.Escalar("SELECT COUNT(*) FROM solicitudes WHERE estado = 'Pendiente'") ?? 0L);

    /// <summary>
    /// ACEPTAR de forma ATÓMICA: cambia Pendiente -> Aceptada y crea el registro en
    /// Consultas en la MISMA transacción. Si dos usuarios (o el ping-pong automático y un
    /// usuario) aceptan a la vez, el <c>WHERE estado='Pendiente'</c> garantiza que solo uno
    /// gana; el otro recibe <c>null</c>.
    /// </summary>
    public Consulta? Aceptar(string solicitudId)
    {
        return _db.Transaccion(ejecutar =>
        {
            var cambiadas = ejecutar(
                "UPDATE solicitudes SET estado='Aceptada', decidido_utc=?2 WHERE id=?1 AND estado='Pendiente'",
                [solicitudId, DateTime.UtcNow]);
            if (cambiadas == 0) return null;

            var s = ObtenerSolicitud(solicitudId)!; // lectura dentro del candado: consistente
            var c = new Consulta
            {
                SolicitudId = s.Id, PacketId = s.PacketId, NombreZip = s.NombreZip,
                Origen = OrigenesConsulta.Recibido, NodoRemoto = s.NodoOrigen, Direccion = s.DireccionRespuesta,
                AlgoritmoCodigo = s.AlgoritmoCodigo, Modo = s.Modo, NombreOriginal = s.NombreOriginal,
                TamanoOriginal = s.TamanoOriginal, Sha256 = s.Sha256, Verificacion = s.Verificacion,
                RutaZip = s.RutaZip, Salto = s.Salto, RallyId = s.RallyId,
            };
            ejecutar(SqlInsertarConsulta, ParametrosConsulta(c));
            return c;
        });
    }

    /// <summary>RECHAZAR: Pendiente -> Rechazada. Devuelve false si ya estaba decidida.</summary>
    public bool Rechazar(string solicitudId) => _db.Ejecutar(
        "UPDATE solicitudes SET estado='Rechazada', decidido_utc=?2 WHERE id=?1 AND estado='Pendiente'",
        solicitudId, DateTime.UtcNow) == 1;

    // ------------------------------------------------------------------ Consultas

    private const string SqlInsertarConsulta = """
        INSERT INTO consultas (id, solicitud_id, packet_id, nombre_zip, origen, nodo_remoto, direccion, algoritmo_codigo,
          modo, nombre_original, tamano_original, sha256, verificacion, ruta_zip, fecha_utc, salto, rally_id, resultado_envio)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18);
        """;

    private static object?[] ParametrosConsulta(Consulta c) =>
    [
        c.Id, c.SolicitudId, c.PacketId, c.NombreZip, c.Origen, c.NodoRemoto, c.Direccion, c.AlgoritmoCodigo,
        c.Modo, c.NombreOriginal, c.TamanoOriginal, c.Sha256, c.Verificacion, c.RutaZip, c.FechaUtc, c.Salto,
        c.RallyId, c.ResultadoEnvio,
    ];

    public void InsertarConsulta(Consulta c) => _db.Ejecutar(SqlInsertarConsulta, ParametrosConsulta(c));

    public void ActualizarResultadoEnvio(string consultaId, string resultado) =>
        _db.Ejecutar("UPDATE consultas SET resultado_envio = ?2 WHERE id = ?1", consultaId, resultado);

    public Consulta? ObtenerConsulta(string id) =>
        _db.Consultar("SELECT * FROM consultas WHERE id = ?1", id).Select(AConsulta).FirstOrDefault();

    public List<Consulta> ListarConsultas(int limite = 500) =>
        _db.Consultar("SELECT * FROM consultas ORDER BY fecha_utc DESC LIMIT ?1", limite).Select(AConsulta).ToList();

    public long ContarConsultas() => (long)(_db.Escalar("SELECT COUNT(*) FROM consultas") ?? 0L);

    // ------------------------------------------------------------------ Bitácora

    public void Registrar(string tipo, string mensaje, string? rallyId = null, int? salto = null) =>
        _db.Ejecutar("INSERT INTO bitacora (fecha_utc, tipo, mensaje, rally_id, salto) VALUES (?1,?2,?3,?4,?5)",
            DateTime.UtcNow, tipo, mensaje, rallyId, salto);

    public List<EventoBitacora> ListarBitacora(int limite = 100) =>
        _db.Consultar("SELECT * FROM bitacora ORDER BY id DESC LIMIT ?1", limite)
            .Select(f => new EventoBitacora((long)f["id"]!, Fecha(f["fecha_utc"])!.Value, S(f["tipo"]), S(f["mensaje"]),
                f["rally_id"] as string, f["salto"] is long n ? (int)n : null)).ToList();

    // ------------------------------------------------------------------ Nodos conocidos

    public void GuardarNodo(NodoConocido n) => _db.Ejecutar("""
        INSERT INTO nodos (direccion, nodo_id, estado, visto_utc, cert_rsa_pem, cert_ecc_pem)
        VALUES (?1,?2,?3,?4,?5,?6)
        ON CONFLICT(direccion) DO UPDATE SET nodo_id=excluded.nodo_id, estado=excluded.estado,
          visto_utc=excluded.visto_utc,
          cert_rsa_pem=COALESCE(excluded.cert_rsa_pem, nodos.cert_rsa_pem),
          cert_ecc_pem=COALESCE(excluded.cert_ecc_pem, nodos.cert_ecc_pem);
        """, n.Direccion, n.NodoId, n.Estado, n.VistoUtc, n.CertificadoRsaPem, n.CertificadoEccPem);

    public List<NodoConocido> ListarNodos() =>
        _db.Consultar("SELECT * FROM nodos ORDER BY nodo_id").Select(ANodo).ToList();

    public NodoConocido? ObtenerNodo(string direccion) =>
        _db.Consultar("SELECT * FROM nodos WHERE direccion = ?1", direccion).Select(ANodo).FirstOrDefault();

    public void EliminarNodo(string direccion) => _db.Ejecutar("DELETE FROM nodos WHERE direccion = ?1", direccion);

    // ------------------------------------------------------------------ Ajustes

    public string? LeerAjuste(string clave) =>
        _db.Escalar("SELECT valor FROM ajustes WHERE clave = ?1", clave) as string;

    public void GuardarAjuste(string clave, string valor) => _db.Ejecutar(
        "INSERT INTO ajustes (clave, valor) VALUES (?1, ?2) ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor",
        clave, valor);

    // ------------------------------------------------------------------ Mapeo fila -> objeto

    private static string S(object? o) => o?.ToString() ?? "";
    private static long L(object? o) => o is long l ? l : 0;
    private static DateTime? Fecha(object? o) =>
        o is string s && DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d)
            ? d.ToUniversalTime() : null;

    private static Solicitud ASolicitud(Dictionary<string, object?> f) => new()
    {
        Id = S(f["id"]), PacketId = S(f["packet_id"]), NombreZip = S(f["nombre_zip"]), OrigenIp = S(f["origen_ip"]),
        NodoOrigen = S(f["nodo_origen"]), DireccionRespuesta = S(f["direccion_respuesta"]),
        AlgoritmoCodigo = S(f["algoritmo_codigo"]), Algoritmo = S(f["algoritmo"]), Modo = S(f["modo"]),
        NombreOriginal = S(f["nombre_original"]), TamanoOriginal = L(f["tamano_original"]), Sha256 = S(f["sha256"]),
        Verificacion = S(f["verificacion"]), DetalleJson = S(f["detalle_json"]), RutaZip = S(f["ruta_zip"]),
        Estado = S(f["estado"]), RecibidoUtc = Fecha(f["recibido_utc"]) ?? DateTime.MinValue,
        DecididoUtc = Fecha(f["decidido_utc"]), Salto = (int)L(f["salto"]), RallyId = S(f["rally_id"]),
    };

    private static Consulta AConsulta(Dictionary<string, object?> f) => new()
    {
        Id = S(f["id"]), SolicitudId = f["solicitud_id"] as string, PacketId = S(f["packet_id"]),
        NombreZip = S(f["nombre_zip"]), Origen = S(f["origen"]), NodoRemoto = S(f["nodo_remoto"]),
        Direccion = S(f["direccion"]), AlgoritmoCodigo = S(f["algoritmo_codigo"]), Modo = S(f["modo"]),
        NombreOriginal = S(f["nombre_original"]), TamanoOriginal = L(f["tamano_original"]), Sha256 = S(f["sha256"]),
        Verificacion = S(f["verificacion"]), RutaZip = S(f["ruta_zip"]),
        FechaUtc = Fecha(f["fecha_utc"]) ?? DateTime.MinValue, Salto = (int)L(f["salto"]), RallyId = S(f["rally_id"]),
        ResultadoEnvio = f["resultado_envio"] as string,
    };

    private static NodoConocido ANodo(Dictionary<string, object?> f) => new()
    {
        Direccion = S(f["direccion"]), NodoId = S(f["nodo_id"]), Estado = S(f["estado"]),
        VistoUtc = Fecha(f["visto_utc"]), CertificadoRsaPem = f["cert_rsa_pem"] as string,
        CertificadoEccPem = f["cert_ecc_pem"] as string,
    };
}
