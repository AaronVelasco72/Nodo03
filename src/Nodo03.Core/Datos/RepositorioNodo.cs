namespace Nodo03.Core.Datos;

// =====================================================================
//  Modelos (estándar v2.0, sección 15)
// =====================================================================

public static class EstadosSolicitud
{
    public const string Pendiente = "Pendiente";
    public const string Aceptada = "Aceptada";
    public const string Rechazada = "Rechazada";
}

/// <summary>Resultado de validación que muestra la bandeja (sección 15).</summary>
public static class Verificaciones
{
    public const string FirmaOk = "Firma OK";
    public const string Invalida = "Inválida";
    public const string NoConfirmado = "Remitente no confirmado";
}

/// <summary>Orígenes en Consultas (sección 15).</summary>
public static class OrigenesConsulta
{
    /// <summary>Creado por este nodo o recibido de un forward delegado.</summary>
    public const string Generado = "Generado";
    /// <summary>Aceptado de la bandeja.</summary>
    public const string Recibido = "Recibido";
    /// <summary>Devuelto por un inverse.</summary>
    public const string Resultado = "Resultado";
}

/// <summary>Paquete recibido en <c>POST /api/requests/receive</c>.</summary>
public sealed class Solicitud
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string PacketId { get; set; } = "";
    public string NombreZip { get; set; } = "";
    public string OrigenIp { get; set; } = "";
    public string NodoOrigen { get; set; } = "";
    public string NodoProductor { get; set; } = "";
    public string DireccionRespuesta { get; set; } = "";
    public string AlgoritmoCodigo { get; set; } = "";
    public string AlgoritmoNombre { get; set; } = "";
    public string Operacion { get; set; } = "";
    public string OperacionNombre { get; set; } = "";
    public string Modo { get; set; } = "";
    public string NombreOriginal { get; set; } = "";
    public long TamanoOriginal { get; set; }
    public string Sha256 { get; set; } = "";
    public string Verificacion { get; set; } = Verificaciones.FirmaOk;
    public string Detalle { get; set; } = "";
    public string RutaZip { get; set; } = "";
    public string Estado { get; set; } = EstadosSolicitud.Pendiente;
    public DateTime RecibidoUtc { get; set; } = DateTime.UtcNow;
    public DateTime? DecididoUtc { get; set; }
    public int Salto { get; set; }
    public string RallyId { get; set; } = "";
}

/// <summary>Registro de Consultas.</summary>
public sealed class Consulta
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? SolicitudId { get; set; }
    public string? ConsultaOrigenId { get; set; }
    public string PacketId { get; set; } = "";
    public string? RequestId { get; set; }
    public string NombreZip { get; set; } = "";
    public string Origen { get; set; } = OrigenesConsulta.Generado;
    public string NodoOrigen { get; set; } = "";
    public string NodoProductor { get; set; } = "";
    /// <summary>El otro lado: quien lo envió (Recibido) o a quién se envió por última vez.</summary>
    public string NodoRemoto { get; set; } = "";
    public string Direccion { get; set; } = "";
    public string AlgoritmoCodigo { get; set; } = "";
    public string Operacion { get; set; } = "";
    public string OperacionNombre { get; set; } = "";
    public string Modo { get; set; } = "";
    public string NombreOriginal { get; set; } = "";
    public long TamanoOriginal { get; set; }
    public string Sha256 { get; set; } = "";
    public string Verificacion { get; set; } = Verificaciones.FirmaOk;
    public string RutaZip { get; set; } = "";
    public DateTime FechaUtc { get; set; } = DateTime.UtcNow;
    public int Salto { get; set; }
    public string RallyId { get; set; } = "";
    public string? ResultadoEnvio { get; set; }
}

public sealed record EventoBitacora(long Id, DateTime FechaUtc, string Tipo, string Mensaje, string? RallyId, int? Salto);

/// <summary>Entrada del directorio local de nodos (sección 6.4).</summary>
public sealed class NodoConocido
{
    public string NodeId { get; set; } = "";
    public int Equipo { get; set; }
    public string Ip { get; set; } = "";
    public int HttpPort { get; set; }
    public int? HttpsPort { get; set; }
    /// <summary>Huella confirmada por el usuario (TOFU). Null = aún no confirmada.</summary>
    public string? HuellaFijada { get; set; }
    /// <summary>Huella que presenta el nodo ahora.</summary>
    public string? HuellaPresentada { get; set; }
    public string Algoritmos { get; set; } = "";
    /// <summary>beacon, scan o manual.</summary>
    public string Fuente { get; set; } = "manual";
    /// <summary>online u offline.</summary>
    public string Estado { get; set; } = "offline";
    public DateTime? VistoUtc { get; set; }
    /// <summary>La huella presentada es distinta de la fijada: NO se usa hasta que el usuario acepte.</summary>
    public bool Alerta { get; set; }

    public string Direccion => $"{Ip}:{HttpPort}";
    public bool Confiable => HuellaFijada is not null && !Alerta && HuellaFijada == HuellaPresentada;
    public string[] ListaAlgoritmos => Algoritmos.Split(',', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>Llave de algoritmo guardada por el dueño (sección 12).</summary>
public sealed class LlaveAlgoritmo
{
    public string KeyId { get; set; } = "";
    public string Algoritmo { get; set; } = "";
    public string PublicaSpkiBase64 { get; set; } = "";
    /// <summary>PKCS#8 CIFRADO (PEM). Nunca en claro.</summary>
    public string PrivadaPem { get; set; } = "";
    /// <summary>Lista separada por comas (options.allowedNodes) o vacío = cualquiera.</summary>
    public string Permitidos { get; set; } = "";
    public DateTime CreadaUtc { get; set; } = DateTime.UtcNow;
}

// =====================================================================
//  Repositorio
// =====================================================================

/// <summary>Operaciones de base de datos del nodo (SQLite).</summary>
public sealed class RepositorioNodo
{
    private readonly BaseDatos _db;

    public RepositorioNodo(BaseDatos db)
    {
        _db = db;
        CrearEsquema();
    }

    private void CrearEsquema()
    {
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS solicitudes (
              id TEXT PRIMARY KEY, packet_id TEXT NOT NULL, nombre_zip TEXT NOT NULL, origen_ip TEXT NOT NULL,
              nodo_origen TEXT NOT NULL, nodo_productor TEXT NOT NULL, direccion_respuesta TEXT NOT NULL,
              algoritmo_codigo TEXT NOT NULL, algoritmo_nombre TEXT NOT NULL, operacion TEXT NOT NULL,
              operacion_nombre TEXT NOT NULL, modo TEXT NOT NULL, nombre_original TEXT NOT NULL,
              tamano_original INTEGER NOT NULL, sha256 TEXT NOT NULL,
              verificacion TEXT NOT NULL CHECK (verificacion IN ('Firma OK','Inválida','Remitente no confirmado')),
              detalle TEXT NOT NULL, ruta_zip TEXT NOT NULL,
              estado TEXT NOT NULL CHECK (estado IN ('Pendiente','Aceptada','Rechazada')),
              recibido_utc TEXT NOT NULL, decidido_utc TEXT, salto INTEGER NOT NULL DEFAULT 0, rally_id TEXT NOT NULL DEFAULT ''
            );
            """);
        // packetId único entre los paquetes válidos (los inválidos se guardan solo como evidencia).
        _db.Ejecutar("CREATE UNIQUE INDEX IF NOT EXISTS ux_solicitudes_packet ON solicitudes(packet_id) WHERE verificacion <> 'Inválida';");
        _db.Ejecutar("CREATE INDEX IF NOT EXISTS ix_solicitudes_estado ON solicitudes(estado, recibido_utc);");
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS consultas (
              id TEXT PRIMARY KEY, solicitud_id TEXT UNIQUE, consulta_origen_id TEXT, packet_id TEXT NOT NULL,
              request_id TEXT, nombre_zip TEXT NOT NULL,
              origen TEXT NOT NULL CHECK (origen IN ('Generado','Recibido','Resultado')),
              nodo_origen TEXT NOT NULL, nodo_productor TEXT NOT NULL, nodo_remoto TEXT NOT NULL, direccion TEXT NOT NULL,
              algoritmo_codigo TEXT NOT NULL, operacion TEXT NOT NULL, operacion_nombre TEXT NOT NULL, modo TEXT NOT NULL,
              nombre_original TEXT NOT NULL, tamano_original INTEGER NOT NULL, sha256 TEXT NOT NULL,
              verificacion TEXT NOT NULL, ruta_zip TEXT NOT NULL, fecha_utc TEXT NOT NULL,
              salto INTEGER NOT NULL DEFAULT 0, rally_id TEXT NOT NULL DEFAULT '', resultado_envio TEXT
            );
            """);
        _db.Ejecutar("CREATE TABLE IF NOT EXISTS bitacora (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha_utc TEXT NOT NULL, tipo TEXT NOT NULL, mensaje TEXT NOT NULL, rally_id TEXT, salto INTEGER);");
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS nodos (
              node_id TEXT PRIMARY KEY, equipo INTEGER NOT NULL, ip TEXT NOT NULL, http_port INTEGER NOT NULL, https_port INTEGER,
              huella_fijada TEXT, huella_presentada TEXT, algoritmos TEXT NOT NULL, fuente TEXT NOT NULL,
              estado TEXT NOT NULL, visto_utc TEXT, alerta INTEGER NOT NULL DEFAULT 0
            );
            """);
        _db.Ejecutar("""
            CREATE TABLE IF NOT EXISTS llaves (
              key_id TEXT PRIMARY KEY, algoritmo TEXT NOT NULL, publica_spki TEXT NOT NULL,
              privada_pem TEXT NOT NULL, permitidos TEXT NOT NULL, creada_utc TEXT NOT NULL
            );
            """);
        _db.Ejecutar("CREATE TABLE IF NOT EXISTS peticiones (request_id TEXT PRIMARY KEY, fecha_utc TEXT NOT NULL);");
        _db.Ejecutar("CREATE TABLE IF NOT EXISTS ajustes (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);");
    }

    // ------------------------------------------------------------------ Solicitudes

    /// <summary>Inserta; false si el packetId ya existía (13.1 paso 14 → 409 E-DUPLICATE).</summary>
    public bool InsertarSolicitud(Solicitud s) => _db.Ejecutar("""
        INSERT OR IGNORE INTO solicitudes (id, packet_id, nombre_zip, origen_ip, nodo_origen, nodo_productor, direccion_respuesta,
          algoritmo_codigo, algoritmo_nombre, operacion, operacion_nombre, modo, nombre_original, tamano_original, sha256,
          verificacion, detalle, ruta_zip, estado, recibido_utc, decidido_utc, salto, rally_id)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23);
        """, s.Id, s.PacketId, s.NombreZip, s.OrigenIp, s.NodoOrigen, s.NodoProductor, s.DireccionRespuesta, s.AlgoritmoCodigo,
        s.AlgoritmoNombre, s.Operacion, s.OperacionNombre, s.Modo, s.NombreOriginal, s.TamanoOriginal, s.Sha256,
        s.Verificacion, s.Detalle, s.RutaZip, s.Estado, s.RecibidoUtc, s.DecididoUtc, s.Salto, s.RallyId) == 1;

    public bool ExistePaquete(string packetId) =>
        (long)(_db.Escalar("SELECT COUNT(*) FROM solicitudes WHERE packet_id = ?1 AND verificacion <> 'Inválida'", packetId) ?? 0L) > 0;

    public Solicitud? ObtenerSolicitud(string id) =>
        _db.Consultar("SELECT * FROM solicitudes WHERE id = ?1", id).Select(ASolicitud).FirstOrDefault();

    public Solicitud? ObtenerSolicitudPorPaquete(string packetId) =>
        _db.Consultar("SELECT * FROM solicitudes WHERE packet_id = ?1 AND verificacion <> 'Inválida'", packetId).Select(ASolicitud).FirstOrDefault();

    public List<Solicitud> ListarSolicitudes(string? estado = null, int limite = 500) =>
        (estado is null
            ? _db.Consultar("SELECT * FROM solicitudes ORDER BY recibido_utc DESC LIMIT ?1", limite)
            : _db.Consultar("SELECT * FROM solicitudes WHERE estado = ?1 ORDER BY recibido_utc DESC LIMIT ?2", estado, limite))
        .Select(ASolicitud).ToList();

    public long ContarPendientes() => (long)(_db.Escalar("SELECT COUNT(*) FROM solicitudes WHERE estado = 'Pendiente'") ?? 0L);

    /// <summary>Aceptar ATÓMICO: Pendiente → Aceptada + registro en Consultas en la misma transacción.</summary>
    public Consulta? Aceptar(string solicitudId) => _db.Transaccion(ejecutar =>
    {
        if (ejecutar("UPDATE solicitudes SET estado='Aceptada', decidido_utc=?2 WHERE id=?1 AND estado='Pendiente'",
                [solicitudId, DateTime.UtcNow]) == 0) return null;
        var s = ObtenerSolicitud(solicitudId)!;
        var c = new Consulta
        {
            SolicitudId = s.Id, PacketId = s.PacketId, NombreZip = s.NombreZip, Origen = OrigenesConsulta.Recibido,
            NodoOrigen = s.NodoOrigen, NodoProductor = s.NodoProductor, NodoRemoto = s.NodoOrigen, Direccion = s.DireccionRespuesta,
            AlgoritmoCodigo = s.AlgoritmoCodigo, Operacion = s.Operacion, OperacionNombre = s.OperacionNombre, Modo = s.Modo,
            NombreOriginal = s.NombreOriginal, TamanoOriginal = s.TamanoOriginal, Sha256 = s.Sha256, Verificacion = s.Verificacion,
            RutaZip = s.RutaZip, Salto = s.Salto, RallyId = s.RallyId,
        };
        ejecutar(SqlConsulta, ParamsConsulta(c));
        return c;
    });

    public bool Rechazar(string solicitudId) => _db.Ejecutar(
        "UPDATE solicitudes SET estado='Rechazada', decidido_utc=?2 WHERE id=?1 AND estado='Pendiente'", solicitudId, DateTime.UtcNow) == 1;

    // ------------------------------------------------------------------ Consultas

    private const string SqlConsulta = """
        INSERT INTO consultas (id, solicitud_id, consulta_origen_id, packet_id, request_id, nombre_zip, origen, nodo_origen,
          nodo_productor, nodo_remoto, direccion, algoritmo_codigo, operacion, operacion_nombre, modo, nombre_original,
          tamano_original, sha256, verificacion, ruta_zip, fecha_utc, salto, rally_id, resultado_envio)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24);
        """;

    private static object?[] ParamsConsulta(Consulta c) =>
    [
        c.Id, c.SolicitudId, c.ConsultaOrigenId, c.PacketId, c.RequestId, c.NombreZip, c.Origen, c.NodoOrigen, c.NodoProductor,
        c.NodoRemoto, c.Direccion, c.AlgoritmoCodigo, c.Operacion, c.OperacionNombre, c.Modo, c.NombreOriginal, c.TamanoOriginal,
        c.Sha256, c.Verificacion, c.RutaZip, c.FechaUtc, c.Salto, c.RallyId, c.ResultadoEnvio,
    ];

    public void InsertarConsulta(Consulta c) => _db.Ejecutar(SqlConsulta, ParamsConsulta(c));

    public void ActualizarEnvio(string consultaId, string nodoRemoto, string direccion, string resultado) =>
        _db.Ejecutar("UPDATE consultas SET nodo_remoto=?2, direccion=?3, resultado_envio=?4 WHERE id=?1", consultaId, nodoRemoto, direccion, resultado);

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
            .Select(f => new EventoBitacora((long)f["id"]!, Fecha(f["fecha_utc"]) ?? DateTime.MinValue, S(f["tipo"]), S(f["mensaje"]),
                f["rally_id"] as string, f["salto"] is long n ? (int)n : null)).ToList();

    // ------------------------------------------------------------------ Directorio de nodos

    public void GuardarNodo(NodoConocido n) => _db.Ejecutar("""
        INSERT INTO nodos (node_id, equipo, ip, http_port, https_port, huella_fijada, huella_presentada, algoritmos, fuente, estado, visto_utc, alerta)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
        ON CONFLICT(node_id) DO UPDATE SET equipo=excluded.equipo, ip=excluded.ip, http_port=excluded.http_port,
          https_port=excluded.https_port, huella_fijada=excluded.huella_fijada, huella_presentada=excluded.huella_presentada,
          algoritmos=excluded.algoritmos, fuente=excluded.fuente, estado=excluded.estado, visto_utc=excluded.visto_utc, alerta=excluded.alerta;
        """, n.NodeId, n.Equipo, n.Ip, n.HttpPort, n.HttpsPort, n.HuellaFijada, n.HuellaPresentada, n.Algoritmos, n.Fuente,
        n.Estado, n.VistoUtc, n.Alerta);

    public NodoConocido? ObtenerNodo(string nodeId) =>
        _db.Consultar("SELECT * FROM nodos WHERE node_id = ?1", nodeId).Select(ANodo).FirstOrDefault();

    public List<NodoConocido> ListarNodos() =>
        _db.Consultar("SELECT * FROM nodos ORDER BY node_id").Select(ANodo).ToList();

    public void EliminarNodo(string nodeId) => _db.Ejecutar("DELETE FROM nodos WHERE node_id = ?1", nodeId);

    // ------------------------------------------------------------------ Llaves keyId

    public void GuardarLlave(LlaveAlgoritmo k) => _db.Ejecutar(
        "INSERT INTO llaves (key_id, algoritmo, publica_spki, privada_pem, permitidos, creada_utc) VALUES (?1,?2,?3,?4,?5,?6)",
        k.KeyId, k.Algoritmo, k.PublicaSpkiBase64, k.PrivadaPem, k.Permitidos, k.CreadaUtc);

    public LlaveAlgoritmo? ObtenerLlave(string keyId) =>
        _db.Consultar("SELECT * FROM llaves WHERE key_id = ?1", keyId).Select(f => new LlaveAlgoritmo
        {
            KeyId = S(f["key_id"]), Algoritmo = S(f["algoritmo"]), PublicaSpkiBase64 = S(f["publica_spki"]),
            PrivadaPem = S(f["privada_pem"]), Permitidos = S(f["permitidos"]), CreadaUtc = Fecha(f["creada_utc"]) ?? DateTime.MinValue,
        }).FirstOrDefault();

    /// <summary>Lista de llaves (sin la privada).</summary>
    public List<LlaveAlgoritmo> ListarLlaves(int limite = 200) =>
        _db.Consultar("SELECT key_id, algoritmo, publica_spki, permitidos, creada_utc FROM llaves ORDER BY creada_utc DESC LIMIT ?1", limite)
            .Select(f => new LlaveAlgoritmo
            {
                KeyId = S(f["key_id"]), Algoritmo = S(f["algoritmo"]), PublicaSpkiBase64 = S(f["publica_spki"]),
                Permitidos = S(f["permitidos"]), CreadaUtc = Fecha(f["creada_utc"]) ?? DateTime.MinValue,
            }).ToList();

    public long ContarLlaves() => (long)(_db.Escalar("SELECT COUNT(*) FROM llaves") ?? 0L);

    // ------------------------------------------------------------------ Anti repetición de peticiones

    /// <summary>Registra un requestId; false si ya se había visto (409 E-DUPLICATE).</summary>
    public bool RegistrarPeticion(string requestId) =>
        _db.Ejecutar("INSERT OR IGNORE INTO peticiones (request_id, fecha_utc) VALUES (?1, ?2)", requestId, DateTime.UtcNow) == 1;

    // ------------------------------------------------------------------ Ajustes

    public string? LeerAjuste(string clave) => _db.Escalar("SELECT valor FROM ajustes WHERE clave = ?1", clave) as string;

    public void GuardarAjuste(string clave, string valor) => _db.Ejecutar(
        "INSERT INTO ajustes (clave, valor) VALUES (?1, ?2) ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor", clave, valor);

    // ------------------------------------------------------------------ Mapeo

    private static string S(object? o) => o?.ToString() ?? "";
    private static long L(object? o) => o is long l ? l : 0;
    private static DateTime? Fecha(object? o) =>
        o is string s && DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) ? d.ToUniversalTime() : null;

    private static Solicitud ASolicitud(Dictionary<string, object?> f) => new()
    {
        Id = S(f["id"]), PacketId = S(f["packet_id"]), NombreZip = S(f["nombre_zip"]), OrigenIp = S(f["origen_ip"]),
        NodoOrigen = S(f["nodo_origen"]), NodoProductor = S(f["nodo_productor"]), DireccionRespuesta = S(f["direccion_respuesta"]),
        AlgoritmoCodigo = S(f["algoritmo_codigo"]), AlgoritmoNombre = S(f["algoritmo_nombre"]), Operacion = S(f["operacion"]),
        OperacionNombre = S(f["operacion_nombre"]), Modo = S(f["modo"]), NombreOriginal = S(f["nombre_original"]),
        TamanoOriginal = L(f["tamano_original"]), Sha256 = S(f["sha256"]), Verificacion = S(f["verificacion"]),
        Detalle = S(f["detalle"]), RutaZip = S(f["ruta_zip"]), Estado = S(f["estado"]),
        RecibidoUtc = Fecha(f["recibido_utc"]) ?? DateTime.MinValue, DecididoUtc = Fecha(f["decidido_utc"]),
        Salto = (int)L(f["salto"]), RallyId = S(f["rally_id"]),
    };

    private static Consulta AConsulta(Dictionary<string, object?> f) => new()
    {
        Id = S(f["id"]), SolicitudId = f["solicitud_id"] as string, ConsultaOrigenId = f["consulta_origen_id"] as string,
        PacketId = S(f["packet_id"]), RequestId = f["request_id"] as string, NombreZip = S(f["nombre_zip"]), Origen = S(f["origen"]),
        NodoOrigen = S(f["nodo_origen"]), NodoProductor = S(f["nodo_productor"]), NodoRemoto = S(f["nodo_remoto"]),
        Direccion = S(f["direccion"]), AlgoritmoCodigo = S(f["algoritmo_codigo"]), Operacion = S(f["operacion"]),
        OperacionNombre = S(f["operacion_nombre"]), Modo = S(f["modo"]), NombreOriginal = S(f["nombre_original"]),
        TamanoOriginal = L(f["tamano_original"]), Sha256 = S(f["sha256"]), Verificacion = S(f["verificacion"]),
        RutaZip = S(f["ruta_zip"]), FechaUtc = Fecha(f["fecha_utc"]) ?? DateTime.MinValue, Salto = (int)L(f["salto"]),
        RallyId = S(f["rally_id"]), ResultadoEnvio = f["resultado_envio"] as string,
    };

    private static NodoConocido ANodo(Dictionary<string, object?> f) => new()
    {
        NodeId = S(f["node_id"]), Equipo = (int)L(f["equipo"]), Ip = S(f["ip"]), HttpPort = (int)L(f["http_port"]),
        HttpsPort = f["https_port"] is long h ? (int)h : null, HuellaFijada = f["huella_fijada"] as string,
        HuellaPresentada = f["huella_presentada"] as string, Algoritmos = S(f["algoritmos"]), Fuente = S(f["fuente"]),
        Estado = S(f["estado"]), VistoUtc = Fecha(f["visto_utc"]), Alerta = L(f["alerta"]) == 1,
    };
}
