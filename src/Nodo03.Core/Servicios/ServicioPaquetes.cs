using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Servicios;

/// <summary>Contenido en claro: lo que el usuario cargó (o lo que sale al descifrar).</summary>
/// <param name="Bytes">Bytes del texto (UTF-8), imagen o archivo.</param>
/// <param name="Modo">"text", "image" o "file".</param>
/// <param name="NombreArchivo">Nombre original (para texto se usa "mensaje.txt").</param>
public sealed record ContenidoPlano(byte[] Bytes, string Modo, string NombreArchivo);

/// <summary>Paquete listo para enviarse o descargarse.</summary>
public sealed record PaqueteGenerado(string NombreZip, byte[] Zip, Manifiesto Manifiesto);

/// <summary>Se lanza al intentar descifrar un paquete que fue cifrado para OTRO nodo.</summary>
public sealed class DestinatarioIncorrectoException(string mensaje) : Exception(mensaje);

/// <summary>
/// Caso de uso central del Modo Emisor y del ping-pong:
/// <c>Armar</c> = cifrar + manifiesto + firma + zip; <c>Abrir</c> = descifrar un paquete recibido.
/// </summary>
public static class ServicioPaquetes
{
    /// <summary>Nombre de los campos extra que el Nodo 03 agrega a publicParameters para el ping-pong.</summary>
    public const string ParamSalto = "hop";
    public const string ParamRally = "rallyId";

    /// <summary>
    /// Construye un paquete completo según el estándar.
    /// </summary>
    /// <param name="contenido">Lo que se va a cifrar.</param>
    /// <param name="codigo">"RSA" o "ECC".</param>
    /// <param name="certificadoDestino">Certificado del destinatario (su llave pública cifra; solo él descifra).</param>
    /// <param name="yo">Identidad del nodo emisor (firma el manifiesto).</param>
    /// <param name="direccionPropia">"IP:Puerto" del emisor, va en sourceIp (a donde regresa la pelota).</param>
    /// <param name="salto">Número de rebote en el ping-pong (0 = saque inicial).</param>
    /// <param name="rallyId">Id que agrupa todos los rebotes de una misma pelota.</param>
    /// <param name="ahoraUtc">Inyectable para pruebas.</param>
    public static PaqueteGenerado Armar(ContenidoPlano contenido, string codigo, X509Certificate2 certificadoDestino,
        IdentidadNodo yo, string direccionPropia, int salto = 0, string? rallyId = null, DateTime? ahoraUtc = null)
    {
        // Tipo de llave del destino debe coincidir con el algoritmo elegido.
        var tipoDestino = IdentidadNodo.TipoDeLlave(certificadoDestino);
        if (tipoDestino != codigo)
            throw new InvalidOperationException(
                $"Para cifrar con {codigo} se necesita un certificado {codigo} del destino, y el recibido es {tipoDestino ?? "desconocido"}.");

        // 1) Cifrar
        var resultado = Cifradores.Para(codigo).Cifrar(contenido.Bytes, certificadoDestino);

        // 2) Marca de tiempo truncada a segundos (formato del estándar, sin milisegundos)
        var t = ahoraUtc ?? DateTime.UtcNow;
        t = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, DateTimeKind.Utc);

        // 3) Manifiesto
        var m = new Manifiesto
        {
            SourceNode = yo.NodoId,
            SourceIp = direccionPropia,
            TimestampUtc = t.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            Algorithm = resultado.NombreAlgoritmo,
            AlgorithmCode = codigo,
            PayloadMode = ModosCarga.Normalizar(contenido.Modo),
            OriginalFileName = contenido.NombreArchivo,
            OriginalExtension = Path.GetExtension(contenido.NombreArchivo).ToLowerInvariant(),
            OriginalSizeBytes = contenido.Bytes.LongLength,
            EncryptedSha256 = Huellas.Sha256Hex(resultado.Datos),
            PublicParameters = resultado.ParametrosPublicos,
            CertificateThumbprintSha256 = yo.Huella(codigo),
        };
        m.PublicParameters[ParamSalto] = salto;
        m.PublicParameters[ParamRally] = rallyId ?? m.PacketId;

        // 4) Firma (requiere sha, huella y fecha ya puestos)
        FirmaManifiesto.Firmar(m, yo, codigo);

        // 5) Zip + nombre oficial
        var zip = EmpaquetadorZip.Crear(resultado.Datos, yo.CertificadoPem(codigo), m);
        var nombre = NombrePaquete.Construir(yo.NodoId, codigo, t, m.EncryptedSha256);
        return new PaqueteGenerado(nombre, zip, m);
    }

    /// <summary>
    /// Descifra un paquete recibido con la llave privada de este nodo.
    /// </summary>
    /// <exception cref="NotSupportedException">El algoritmo no es RSA ni ECC.</exception>
    /// <exception cref="DestinatarioIncorrectoException">Fue cifrado para la llave de otro nodo.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Llave incorrecta o datos alterados.</exception>
    public static ContenidoPlano Abrir(PaqueteLeido paquete, IdentidadNodo yo)
    {
        var m = paquete.Manifiesto;
        if (!CodigosAlgoritmo.LoImplementaEsteNodo(m.AlgorithmCode))
            throw new NotSupportedException($"El Nodo 03 no implementa '{m.AlgorithmCode}'; solo puede validarlo y archivarlo.");

        var destino = m.Parametro("recipientThumbprintSha256");
        if (destino is not null && !yo.EsMiHuella(destino))
            throw new DestinatarioIncorrectoException(
                $"Este paquete fue cifrado para otro certificado ({destino[..Math.Min(12, destino.Length)]}…), no para {yo.NodoId}.");

        var plano = Cifradores.Para(m.AlgorithmCode).Descifrar(paquete.DatosEnc, m.PublicParameters, yo);
        var nombre = string.IsNullOrWhiteSpace(m.OriginalFileName) ? "contenido" + m.OriginalExtension : m.OriginalFileName;
        return new ContenidoPlano(plano, ModosCarga.Normalizar(m.PayloadMode), nombre);
    }
}
