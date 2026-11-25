namespace Nodo03.Core.Protocolo;

/// <summary>
/// Catálogo de los 21 códigos cortos oficiales de la tabla 1.1 de la propuesta del grupo.
/// </summary>
/// <remarks>
/// <para>
/// El código corto aparece en DOS lugares y debe ser idéntico en ambos:
///   1) En el nombre del .zip:  NODO03_<b>RSA</b>_20261124_201500_9F86D081.zip
///   2) En manifest.json:       "algorithmCode": "RSA"
/// </para>
/// <para>
/// El Nodo 03 sabe CIFRAR y DESCIFRAR solo <see cref="Rsa"/> y <see cref="Ecc"/>
/// (los que le tocaron al Equipo 3). Los demás códigos se conocen únicamente para
/// poder VALIDAR y ARCHIVAR paquetes de otros equipos: la verificación del SHA-256 y
/// de la firma X.509 es igual sin importar el algoritmo con el que se cifró datos.enc.
/// </para>
/// </remarks>
public static class CodigosAlgoritmo
{
    /// <summary>Asimétrico RSA (RSA-OAEP / RSA-PSS). Implementado por el Equipo 3.</summary>
    public const string Rsa = "RSA";

    /// <summary>Curva elíptica (ECDH / ECIES / ECDSA). Implementado por el Equipo 3.</summary>
    public const string Ecc = "ECC";

    /// <summary>
    /// Tabla completa: código corto -> descripción. Se usa para mostrar nombres legibles
    /// en la interfaz y para avisar cuando otro equipo manda un código que no existe.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Oficiales =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["AESGCM"] = "Simétrico por bloques · AES-GCM",
            ["DES"] = "Simétrico legado · DES",
            ["TRIPLEDES"] = "Simétrico legado · Triple DES",
            ["CHACHA20"] = "Flujo AEAD · ChaCha20-Poly1305",
            ["RSA"] = "Asimétrico · RSA-OAEP / RSA-PSS",
            ["ECC"] = "Curva elíptica · ECDH / ECIES / ECDSA",
            ["DIFFIEHELLMAN"] = "Acuerdo de claves · Diffie-Hellman",
            ["CAESAR"] = "Clásico · César",
            ["VIGENERE"] = "Clásico polialfabético · Vigenère",
            ["XORASM"] = "Bajo nivel · XOR en registro",
            ["LSBSTEGO"] = "Esteganografía · LSB en PNG/BMP",
            ["EUCLIDESAFFINE"] = "Teoría de números · Euclides / Afín",
            ["MILLERRABIN"] = "Primalidad · Miller–Rabin",
            ["FISHERYATES"] = "Transposición · Fisher–Yates",
            ["HASHSHA"] = "Integridad · SHA-256 / SHA-512 / SHA-3",
            ["HMACSHA256"] = "Autenticación · HMAC-SHA256",
            ["DIGITALSIG"] = "Autenticidad · Firma digital",
            ["QUANTUMPQC"] = "Poscuántica · BB84 + ML-KEM",
            ["DFTSPECTRAL"] = "Señales · DFT / IDFT",
            ["LAGRANGESHAMIR"] = "Umbral · Shamir en GF(256)",
            ["LORENZSZ40"] = "Electromecánico · Lorenz SZ40/42",
        };

    /// <summary>¿El código existe en la tabla oficial? (sensible a mayúsculas, como exige la propuesta)</summary>
    public static bool EsOficial(string? codigo) => codigo is not null && Oficiales.ContainsKey(codigo);

    /// <summary>¿Este nodo puede descifrar paquetes con ese código?</summary>
    public static bool LoImplementaEsteNodo(string? codigo) => codigo is Rsa or Ecc;

    /// <summary>Descripción legible o el propio código si es desconocido.</summary>
    public static string Describir(string? codigo) =>
        codigo is not null && Oficiales.TryGetValue(codigo, out var d) ? d : (codigo ?? "desconocido");
}
