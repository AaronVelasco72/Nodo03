using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>Error que se le muestra tal cual al usuario (400 en la API local).</summary>
public sealed class ErrorOperacionException(string mensaje) : Exception(mensaje);

/// <summary>Lo que regresa una operación forward/inverse a la interfaz.</summary>
public sealed record ResultadoOperacion(
    Consulta Consulta, string Ejecutor, bool Delegado, byte[]? Original = null, Verificacion? Verificacion = null);

/// <summary>Contenido a procesar en un forward.</summary>
public sealed record EntradaForward(
    string Codigo, byte[] Contenido, string Modo, string NombreArchivo,
    Dictionary<string, string> Opciones, Dictionary<string, string>? Secretos, string? KeyId, byte[]? Cover = null);

/// <summary>
/// ROL SOLICITANTE: ejecuta cualquiera de los 21 algoritmos. Si es propio (RSA, ECC) lo hace
/// aquí mismo; si no, se lo pide a su dueño con <c>/api/crypto/*</c> (secciones 11.2 y 11.4).
/// </summary>
/// <remarks>
/// <code>
/// forward:  propio → ProveedorLocal          ajeno → dueño fijado y en línea
///           secretos → sobre CC-ENV-1 para el dueño; request firmada RSA-PSS
///           respuesta 200 zip (o 202 jobId → /api/jobs) → se valida (13.1) → Consultas "Generado"
/// inverse:  paquete result → se abre el sobre con mi llave
///           llave (keyRef) mía → ProveedorLocal + paquete result idéntico al remoto (11.5)
///           ajena → se reempaqueta (9.6) para refrescar la fecha y se manda al dueño
///           → result validado → abro resultEnvelope → Consultas "Resultado"
/// </code>
/// </remarks>
public sealed class ServicioSolicitante(
    IdentidadNodo yo, ProveedorLocal proveedor, RepositorioNodo repo, AlmacenPaquetes almacen, ClienteNodos cliente,
    ServicioDirectorio directorio, AjustesNodo ajustes, DireccionPropia direccion, BusEventos bus)
{
    // ------------------------------------------------------------------ forward

    public async Task<ResultadoOperacion> Forward(EntradaForward e, CancellationToken ct = default,
        int salto = 0, string? rallyId = null, string? consultaOrigen = null, string? nodoForzado = null)
    {
        var alg = Diccionario.PorCodigo(e.Codigo) ?? throw new ErrorOperacionException($"'{e.Codigo}' no está en la tabla 4.1.");
        if (e.Contenido.Length == 0) throw new ErrorOperacionException("No hay contenido que procesar.");
        var opciones = new Dictionary<string, string>(e.Opciones, StringComparer.Ordinal);
        if (Diccionario.Implementados.Contains(alg.Codigo) && (salto > 0 || rallyId is not null))
        {
            opciones["hop"] = salto.ToString();
            if (rallyId is not null) opciones["rallyId"] = rallyId;
        }

        // --- Propio (11.5) ---
        if (nodoForzado is null && proveedor.Provee(alg.Codigo))
        {
            if (!ajustes.Habilitado(alg.Codigo)) throw new ErrorOperacionException($"{alg.Codigo} está deshabilitado en Ajustes.");
            PaqueteGenerado p;
            try { p = proveedor.Forward(new PeticionForward(alg.Codigo, e.Contenido, e.Modo, e.NombreArchivo, e.KeyId, opciones, null, yo.NodoId), direccion.Obtener()); }
            catch (ErrorProtocolo x) { throw new ErrorOperacionException($"{x.Codigo}: {x.Message}"); }
            var c = Registrar(p.Zip, p.NombreZip, p.Manifiesto, OrigenesConsulta.Generado, "generados", Verificaciones.FirmaOk, yo.NodoId, salto, rallyId, consultaOrigen);
            repo.Registrar("forward", $"{alg.Codigo} {alg.Forward} local → {p.NombreZip} (keyId {p.Manifiesto.KeyRef?.KeyId})", c.RallyId, salto);
            return new ResultadoOperacion(c, yo.NodoId, false);
        }

        // --- Delegado (11.2) ---
        var nodo = Proveedor(alg, nodoForzado);
        var archivos = new List<(string, string, string, byte[])> { ("payload", e.NombreArchivo, ModosCarga.Mime(e.NombreArchivo, e.Modo), e.Contenido) };
        if (e.Cover is { Length: > 0 }) archivos.Add(("cover", "cover" + (alg.Codigo == "LSBSTEGO" ? ".png" : ".bin"), "application/octet-stream", e.Cover));
        var (leido, zip, nombre, requestId, verificacion) = await Delegar(nodo, alg, Operaciones.Forward, e.Modo, e.NombreArchivo,
            opciones, e.Secretos, e.KeyId, archivos, ct);
        if (leido.Manifiesto.PacketType != TiposPaquete.Package)
            throw new ErrorOperacionException($"{nodo.NodeId} respondió un paquete '{leido.Manifiesto.PacketType}' a un forward.");
        var consulta = Registrar(zip, nombre, leido.Manifiesto, OrigenesConsulta.Generado, "generados", verificacion, nodo.NodeId, salto, rallyId, consultaOrigen, requestId);
        repo.Registrar("forward", $"{alg.Codigo} {alg.Forward} delegado a {nodo.NodeId} → {nombre}", consulta.RallyId, salto);
        return new ResultadoOperacion(consulta, nodo.NodeId, true);
    }

    // ------------------------------------------------------------------ inverse

    public async Task<ResultadoOperacion> Inverse(string consultaId, Dictionary<string, string>? secretos, CancellationToken ct = default,
        string? nodoForzado = null)
    {
        var c = repo.ObtenerConsulta(consultaId) ?? throw new ErrorOperacionException("No existe ese registro.");
        var leido = EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip));
        var m = leido.Manifiesto;

        // Un resultado ya trae el original cifrado PARA MÍ: solo se abre el sobre.
        if (m.PacketType == TiposPaquete.Result)
        {
            try { return new ResultadoOperacion(c, yo.NodoId, false, ProveedorLocal.AbrirResultado(leido, yo), m.Verification); }
            catch (ErrorProtocolo x) { throw new ErrorOperacionException($"{x.Codigo}: {x.Message}"); }
        }
        var alg = Diccionario.PorCodigo(m.AlgorithmCode) ?? throw new ErrorOperacionException($"'{m.AlgorithmCode}' no está en la tabla 4.1.");
        var dueno = nodoForzado ?? (alg.UsaKeyId ? m.KeyRef?.OwnerNode : null);

        // --- Propio: la llave es mía ---
        if ((dueno ?? alg.NodoDueno) == yo.NodoId && proveedor.Provee(alg.Codigo))
        {
            byte[] original;
            PaqueteGenerado r;
            try
            {
                original = proveedor.Inverse(leido, yo.NodoId);
                r = proveedor.EmpaquetarResultado(original, m, yo.Certificado, yo.NodoId, null, direccion.Obtener());
            }
            catch (ErrorProtocolo x) { throw new ErrorOperacionException($"{x.Codigo}: {x.Message}"); }
            var res = Registrar(r.Zip, r.NombreZip, r.Manifiesto, OrigenesConsulta.Resultado, "resultados", Verificaciones.FirmaOk,
                yo.NodoId, c.Salto, c.RallyId, c.Id);
            repo.Registrar("inverse", $"{alg.Codigo} {alg.Inverse} local de {c.NombreZip} → {r.NombreZip}", c.RallyId, c.Salto);
            return new ResultadoOperacion(res, yo.NodoId, false, original, r.Manifiesto.Verification);
        }

        // --- Delegado (11.4): se reempaqueta para que la fecha esté dentro de ±10 min ---
        var nodo = Proveedor(alg, dueno);
        var fresco = proveedor.Reempaquetar(leido, direccion.Obtener());
        var (resultado, zip, nombre, requestId, verificacion) = await Delegar(nodo, alg, Operaciones.Inverse, m.PayloadMode,
            m.OriginalFileName, new Dictionary<string, string>(StringComparer.Ordinal), secretos, m.KeyRef?.KeyId,
            [("package", fresco.NombreZip, "application/zip", fresco.Zip)], ct);
        var rm = resultado.Manifiesto;
        if (rm.PacketType != TiposPaquete.Result || rm.RequestId != requestId)
            throw new ErrorOperacionException($"{nodo.NodeId} no devolvió un 'result' para esta petición.");
        byte[] plano;
        try { plano = ProveedorLocal.AbrirResultado(resultado, yo); }
        catch (ErrorProtocolo x) { throw new ErrorOperacionException($"No pude abrir el resultado de {nodo.NodeId}: {x.Codigo} {x.Message}"); }
        var consulta = Registrar(zip, nombre, rm, OrigenesConsulta.Resultado, "resultados", verificacion, nodo.NodeId, c.Salto, c.RallyId, c.Id, requestId);
        repo.Registrar("inverse", $"{alg.Codigo} {alg.Inverse} delegado a {nodo.NodeId} de {c.NombreZip} → {nombre}", c.RallyId, c.Salto);
        return new ResultadoOperacion(consulta, nodo.NodeId, true, plano, rm.Verification);
    }

    // ------------------------------------------------------------------ internos

    private NodoConocido Proveedor(AlgoritmoOficial alg, string? nodoForzado)
    {
        var (nodo, motivo) = directorio.Proveedor(alg, nodoForzado);
        return nodo ?? throw new ErrorOperacionException($"{alg.Codigo} no disponible: {motivo}");
    }

    /// <summary>Arma, firma y manda la petición; espera el zip y lo valida.</summary>
    private async Task<(PaqueteLeido Leido, byte[] Zip, string Nombre, string RequestId, string Verificacion)> Delegar(
        NodoConocido nodo, AlgoritmoOficial alg, string operacion, string modo, string nombreArchivo,
        Dictionary<string, string> opciones, Dictionary<string, string>? secretos, string? keyId,
        List<(string Parte, string Nombre, string Tipo, byte[] Bytes)> archivos, CancellationToken ct)
    {
        using var certProveedor = await directorio.CertificadoConfiable(nodo, ct);
        var peticion = new PeticionCripto
        {
            RequesterNode = yo.NodoId, TargetNode = nodo.NodeId, AlgorithmCode = alg.Codigo, Operation = operacion,
            PayloadMode = ModosCarga.Normalizar(modo), OriginalFileName = nombreArchivo, Options = opciones, KeyId = keyId,
        };

        // Secretos → sobre CC-ENV-1 para el proveedor (AAD = requestId). Nunca en claro.
        var limpios = secretos?.Where(kv => !string.IsNullOrEmpty(kv.Value)).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        if (limpios is { Count: > 0 })
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(limpios);
            try { peticion.Secrets = SobreCc.Cerrar(json, certProveedor, nodo.NodeId, peticion.RequestId, cifradoAparte: false, out _); }
            finally { CryptographicOperations.ZeroMemory(json); }
        }
        else if (alg.Llave == TipoLlave.Secreta)
            throw new ErrorOperacionException($"{alg.Codigo} necesita {string.Join(", ", alg.Secretos)} (se cifra para {nodo.NodeId} en un sobre CC-ENV-1).");

        var bytes = JsonSerializer.SerializeToUtf8Bytes(peticion, PeticionCripto.Json);
        var firma = Convert.ToBase64String(yo.Firmar(bytes));
        var r = await cliente.Cripto(nodo.Direccion, operacion, bytes, firma, yo.CertificadoPem, archivos, peticion.RequestId, ct);
        if (r.Codigo == (int)HttpStatusCode.Accepted)
        {
            bus.Publicar("trabajo", new { nodo = nodo.NodeId, algoritmo = alg.Codigo, operacion, mensaje = "El proveedor respondió 202; esperando el trabajo…" });
            r = await cliente.EsperarTrabajo(nodo.Direccion, r, peticion.RequestId, ct);
        }
        if (!r.EsZip)
        {
            repo.Registrar("error", $"{alg.Codigo} {operacion} en {nodo.NodeId} falló: {r}");
            throw new ErrorOperacionException(r.Codigo == 0
                ? $"No se pudo conectar con {nodo.NodeId} ({nodo.Direccion}). ¿Está encendido y en la misma red?"
                : $"{nodo.NodeId} respondió {r}");
        }

        // El zip que regresa se valida como cualquier paquete recibido (13.1) y debe venir del proveedor.
        PaqueteLeido leido;
        string verificacion;
        try
        {
            leido = EmpaquetadorZip.Leer(r.Cuerpo);
            var info = ValidadorPaquete.Validar(leido, DateTime.UtcNow);
            if (leido.Manifiesto.SourceNode != nodo.NodeId || leido.Manifiesto.ProducerNode != nodo.NodeId)
                throw new ErrorProtocolo("E-SIGNATURE", $"El paquete no lo firmó {nodo.NodeId}.");
            verificacion = directorio.ConfianzaDe(nodo.NodeId, info.Huella);
        }
        catch (ErrorProtocolo x) { throw new ErrorOperacionException($"El paquete que devolvió {nodo.NodeId} no pasó la validación: {x.Codigo} {x.Message}"); }
        var nombre = r.NombreArchivo is { } n && NombrePaquete.EsValido(n) ? n
            : NombrePaquete.Construir(leido.Manifiesto.PacketType, leido.Manifiesto.SourceNode, leido.Manifiesto.AlgorithmCode,
                leido.Manifiesto.TimestampUtc, leido.Manifiesto.EncryptedSha256);
        return (leido, r.Cuerpo, nombre, peticion.RequestId, verificacion);
    }

    /// <summary>Guarda el zip y lo registra en Consultas.</summary>
    public Consulta Registrar(byte[] zip, string nombreZip, Manifiesto m, string origen, string carpeta, string verificacion,
        string remoto, int salto = 0, string? rallyId = null, string? consultaOrigen = null, string? requestId = null)
    {
        var c = new Consulta
        {
            ConsultaOrigenId = consultaOrigen, PacketId = m.PacketId, RequestId = requestId ?? m.RequestId, NombreZip = nombreZip,
            Origen = origen, NodoOrigen = m.SourceNode, NodoProductor = m.ProducerNode, NodoRemoto = remoto,
            Direccion = "", AlgoritmoCodigo = m.AlgorithmCode, Operacion = m.Operation, OperacionNombre = m.OperationName,
            Modo = m.PayloadMode, NombreOriginal = m.OriginalFileName, TamanoOriginal = m.OriginalSizeBytes,
            Sha256 = m.EncryptedSha256, Verificacion = verificacion, Salto = salto,
            RallyId = rallyId ?? m.Parametro("rallyId") ?? m.PacketId,
        };
        c.RutaZip = almacen.Guardar(carpeta, c.Id, nombreZip, zip);
        repo.InsertarConsulta(c);
        bus.Publicar("consulta", new { id = c.Id, origen, zip = nombreZip, algoritmo = c.AlgoritmoCodigo });
        return c;
    }
}
