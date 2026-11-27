using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Servicios;

/// <summary>Petición de forward ya validada (venga de la red o de la propia interfaz).</summary>
public sealed record PeticionForward(
    string AlgorithmCode, byte[] Payload, string PayloadMode, string OriginalFileName,
    string? KeyId, IReadOnlyDictionary<string, string> Options, string? RequestId, string RequesterNode);

/// <summary>Paquete listo (package o result).</summary>
public sealed record PaqueteGenerado(string NombreZip, byte[] Zip, Manifiesto Manifiesto);

/// <summary>
/// ROL PROVEEDOR: ejecuta RSA y ECC (los algoritmos del Equipo 3) y arma los paquetes v2.0.
/// Lo usan tanto <c>/api/crypto/*</c> (peticiones de otros nodos) como la interfaz propia
/// (sección 11.5: el resultado local debe ser idéntico en formato al remoto).
/// </summary>
public sealed class ProveedorLocal(IdentidadNodo yo, GestorLlaves llaves)
{
    /// <summary>Opciones públicas que aceptan RSA y ECC en <c>options</c>.</summary>
    public static readonly string[] OpcionesValidas = ["allowedNodes", "hop", "rallyId"];

    public bool Provee(string codigo) => Diccionario.ProvistosPor(yo.Equipo).Any(a => a.Codigo == codigo);

    /// <summary><c>forward</c> = cifrar. Devuelve un paquete <c>package</c> firmado por este nodo.</summary>
    public PaqueteGenerado Forward(PeticionForward p, string sourceIp)
    {
        var alg = Diccionario.PorCodigo(p.AlgorithmCode);
        if (alg is null || !Provee(alg.Codigo))
            throw new ErrorProtocolo("E-ALGORITHM-NOT-PROVIDED", $"{yo.NodoId} no provee {p.AlgorithmCode}.");
        var desconocidas = p.Options.Keys.Except(OpcionesValidas).ToList();
        if (desconocidas.Count > 0)
            throw new ErrorProtocolo("E-PARAMS", $"Opciones no válidas para {alg.Codigo}: {string.Join(", ", desconocidas)}.");
        if (p.KeyId is not null && !Identificadores.KeyId().IsMatch(p.KeyId))
            throw new ErrorProtocolo("E-PARAMS", "keyId con formato inválido.");

        // Llave: reutilizar (con permiso) o generar.
        var permitidos = p.Options.GetValueOrDefault("allowedNodes")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Datos.LlaveAlgoritmo llave;
        if (p.KeyId is null) llave = llaves.Crear(alg.Codigo, permitidos);
        else
        {
            llave = llaves.Obtener(p.KeyId, alg.Codigo);
            llaves.VerificarPermiso(llave, p.RequesterNode);
        }

        (byte[] datos, Dictionary<string, string> parametros) r;
        string nombre;
        if (alg.Codigo == Diccionario.Rsa)
        {
            using var pub = GestorLlaves.PublicaRsa(llave);
            r = CifradorRsa.Cifrar(p.Payload, pub, llave.KeyId);
            nombre = CifradorRsa.Nombre;
        }
        else
        {
            r = CifradorEcc.Cifrar(p.Payload, GestorLlaves.PublicaEc(llave), llave.KeyId);
            nombre = CifradorEcc.Nombre;
        }
        foreach (var extra in new[] { "hop", "rallyId" })
            if (p.Options.TryGetValue(extra, out var v)) r.parametros[extra] = v;

        var modo = ModosCarga.Normalizar(p.PayloadMode);
        var nombreArchivo = string.IsNullOrWhiteSpace(p.OriginalFileName) ? "mensaje.txt" : Path.GetFileName(p.OriginalFileName);
        var m = new Manifiesto
        {
            PacketType = TiposPaquete.Package,
            RequestId = p.RequestId,
            SourceNode = yo.NodoId, SourceTeam = yo.Equipo, SourceIp = sourceIp, ProducerNode = yo.NodoId,
            TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow),
            AlgorithmId = alg.Id, AlgorithmCode = alg.Codigo, AlgorithmName = nombre,
            Operation = Operaciones.Forward, OperationName = alg.Forward,
            PayloadMode = modo, OriginalFileName = nombreArchivo,
            OriginalExtension = Path.GetExtension(nombreArchivo).ToLowerInvariant(),
            OriginalSizeBytes = p.Payload.LongLength, ContentType = ModosCarga.Mime(nombreArchivo, modo),
            KeyRef = new RefLlave(llave.KeyId, yo.NodoId),
            PublicParameters = r.parametros,
        };
        return Sellar(m, r.datos);
    }

    /// <summary><c>inverse</c> = descifrar un paquete RSA/ECC producido con una llave de este nodo.</summary>
    public byte[] Inverse(PaqueteLeido p, string solicitante)
    {
        var m = p.Manifiesto;
        if (!Provee(m.AlgorithmCode))
            throw new ErrorProtocolo("E-ALGORITHM-NOT-PROVIDED", $"{yo.NodoId} no provee {m.AlgorithmCode}.");
        if (m.PacketType != TiposPaquete.Package || m.Operation != Operaciones.Forward)
            throw new ErrorProtocolo("E-REQUEST", "inverse requiere un paquete 'package' producido por un forward.");
        var keyId = m.Parametro("keyId") ?? m.KeyRef?.KeyId
            ?? throw new ErrorProtocolo("E-PARAMS", "El paquete no trae keyId.");
        if (m.KeyRef is { } kr && (kr.OwnerNode != yo.NodoId || kr.KeyId != keyId))
            throw new ErrorProtocolo("E-KEY-NOT-FOUND", $"El keyId pertenece a {kr.OwnerNode}.");
        var llave = llaves.Obtener(keyId, m.AlgorithmCode);
        llaves.VerificarPermiso(llave, solicitante);
        try
        {
            if (m.AlgorithmCode == Diccionario.Rsa)
            {
                using var priv = llaves.PrivadaRsa(llave);
                return CifradorRsa.Descifrar(p.Datos, m.PublicParameters, priv);
            }
            using var ec = llaves.PrivadaEc(llave);
            return CifradorEcc.Descifrar(p.Datos, m.PublicParameters, ec);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new ErrorProtocolo("E-PARAMS", "No se pudo descifrar con los parámetros del paquete: " + ex.Message);
        }
    }

    /// <summary>
    /// Arma el paquete <c>result</c> de un inverse: el original va en resultado.enc cifrado con
    /// CC-ENV-1 para el SOLICITANTE (AAD = packetId del resultado).
    /// </summary>
    public PaqueteGenerado EmpaquetarResultado(byte[] original, Manifiesto paquete, X509Certificate2 certSolicitante,
        string nodoSolicitante, string? requestId, string sourceIp)
    {
        var alg = Diccionario.PorCodigo(paquete.AlgorithmCode)!;
        var m = new Manifiesto
        {
            PacketType = TiposPaquete.Result,
            RequestId = requestId,
            SourceNode = yo.NodoId, SourceTeam = yo.Equipo, SourceIp = sourceIp, ProducerNode = yo.NodoId,
            TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow),
            AlgorithmId = alg.Id, AlgorithmCode = alg.Codigo, AlgorithmName = paquete.AlgorithmName,
            Operation = Operaciones.Inverse, OperationName = alg.Inverse,
            PayloadMode = paquete.PayloadMode, OriginalFileName = paquete.OriginalFileName,
            OriginalExtension = paquete.OriginalExtension, OriginalSizeBytes = original.LongLength,
            ContentType = paquete.ContentType, KeyRef = paquete.KeyRef,
            PublicParameters = new(StringComparer.Ordinal),
        };
        var sobre = SobreCc.Cerrar(original, certSolicitante, nodoSolicitante, m.PacketId, cifradoAparte: true, out var cifrado);
        m.ResultEnvelope = sobre.SinCifrado();
        return Sellar(m, cifrado);
    }

    /// <summary>Abre un paquete <c>result</c> dirigido a este nodo y devuelve el original.</summary>
    public static byte[] AbrirResultado(PaqueteLeido resultado, IdentidadNodo yo)
    {
        var m = resultado.Manifiesto;
        if (m.PacketType != TiposPaquete.Result || m.ResultEnvelope is null)
            throw new ErrorProtocolo("E-MANIFEST", "El paquete no es un resultado con resultEnvelope.");
        return m.ResultEnvelope.Abrir(yo, m.PacketId, resultado.Datos);
    }

    /// <summary>
    /// Reenvío (9.6): conserva datos.enc, publicParameters, keyRef, producerNode y algoritmo;
    /// genera nuevo packetId y timestampUtc; pone este nodo como sourceNode, su certificado y su firma.
    /// </summary>
    public PaqueteGenerado Reempaquetar(PaqueteLeido p, string sourceIp)
    {
        var m = p.Manifiesto.Clonar();
        m.PacketId = Identificadores.NuevoUuid();
        m.TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow);
        m.SourceNode = yo.NodoId;
        m.SourceTeam = yo.Equipo;
        m.SourceIp = sourceIp;
        m.CamposExtra = null;
        return Sellar(m, p.Datos);
    }

    /// <summary>Completa huellas y tamaños, firma y arma el zip con su nombre oficial.</summary>
    private PaqueteGenerado Sellar(Manifiesto m, byte[] datos)
    {
        m.EncryptedSha256 = Huellas.Sha256Hex(datos);
        m.EncryptedSizeBytes = datos.LongLength;
        FirmaManifiesto.Firmar(m, yo);
        var zip = EmpaquetadorZip.Crear(datos, yo.CertificadoPem, m);
        return new PaqueteGenerado(NombrePaquete.Construir(m.PacketType, m.SourceNode, m.AlgorithmCode, m.TimestampUtc, m.EncryptedSha256), zip, m);
    }
}
