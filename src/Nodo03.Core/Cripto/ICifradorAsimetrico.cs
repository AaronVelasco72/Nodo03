using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Contrato común de los dos algoritmos del Equipo 3 (RSA y ECC).
/// </summary>
/// <remarks>
/// Ambos son ASIMÉTRICOS: se cifra con la llave PÚBLICA del destinatario (sacada de su
/// certificado) y solo el destinatario, con su llave PRIVADA, puede descifrar.
/// Esto es lo que hace posible el ping-pong: cuando el nodo B recibe la pelota, la
/// descifra con SU llave privada y la vuelve a cifrar con la llave pública que viene en
/// el <c>certificado.pem</c> del paquete que le mandó A.
/// </remarks>
public interface ICifradorAsimetrico
{
    /// <summary>Código corto oficial ("RSA" o "ECC").</summary>
    string Codigo { get; }

    /// <summary>Cifra <paramref name="plano"/> para el dueño de <paramref name="certificadoDestino"/>.</summary>
    /// <returns>Bytes para datos.enc + parámetros públicos para manifest.json.</returns>
    ResultadoCifrado Cifrar(ReadOnlySpan<byte> plano, X509Certificate2 certificadoDestino);

    /// <summary>Descifra datos.enc usando la llave privada de <paramref name="identidad"/>.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Si la llave no corresponde o los datos fueron alterados (el tag GCM no cuadra).
    /// </exception>
    byte[] Descifrar(byte[] cifrado, JsonObject parametrosPublicos, IdentidadNodo identidad);
}

/// <summary>Salida de un cifrado.</summary>
/// <param name="Datos">Contenido de datos.enc.</param>
/// <param name="ParametrosPublicos">Lo que va en "publicParameters" (nada secreto).</param>
/// <param name="NombreAlgoritmo">Valor para el campo "algorithm" del manifiesto.</param>
public sealed record ResultadoCifrado(byte[] Datos, JsonObject ParametrosPublicos, string NombreAlgoritmo);

/// <summary>Fábrica: devuelve el cifrador según el código corto.</summary>
public static class Cifradores
{
    private static readonly CifradorRsa Rsa = new();
    private static readonly CifradorEcc Ecc = new();

    /// <summary>Cifrador para "RSA" o "ECC"; lanza <see cref="NotSupportedException"/> para otros.</summary>
    public static ICifradorAsimetrico Para(string codigo) => codigo switch
    {
        Protocolo.CodigosAlgoritmo.Rsa => Rsa,
        Protocolo.CodigosAlgoritmo.Ecc => Ecc,
        _ => throw new NotSupportedException(
            $"El algoritmo '{codigo}' no está implementado en el Nodo 03 (solo RSA y ECC)."),
    };
}
