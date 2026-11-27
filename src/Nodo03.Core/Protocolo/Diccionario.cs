namespace Nodo03.Core.Protocolo;

/// <summary>Tipo de llave que usa cada algoritmo (columna "Tipo de llave" de la tabla 4.1).</summary>
public enum TipoLlave { Ninguna, Secreta, SecretaOpcional, KeyId }

/// <summary>Una fila de la tabla 4.1 (con los secretos mínimos de la tabla 4.2).</summary>
/// <param name="Id">algorithmId 1–21.</param>
/// <param name="Codigo">algorithmCode oficial.</param>
/// <param name="Nombre">Nombre descriptivo.</param>
/// <param name="Categoria">Categoría.</param>
/// <param name="Equipo">Equipo dueño o null si está reservado (17–21).</param>
/// <param name="Forward">Significado de forward (ej. "cifrar").</param>
/// <param name="Inverse">Significado de inverse (ej. "descifrar").</param>
/// <param name="Llave">Tipo de llave.</param>
/// <param name="Secretos">Nombres de los secretos que viajan en el sobre CC-ENV-1.</param>
public sealed record AlgoritmoOficial(int Id, string Codigo, string Nombre, string Categoria, int? Equipo,
    string Forward, string Inverse, TipoLlave Llave, string[] Secretos)
{
    /// <summary>nodeId del dueño según la tabla, ej. "EQ03"; null si está reservado.</summary>
    public string? NodoDueno => Equipo is int e ? Identificadores.NodoDeEquipo(e) : null;

    public bool UsaKeyId => Llave == TipoLlave.KeyId;

    /// <summary>Nombre legible de la operación.</summary>
    public string NombreOperacion(string operacion) => operacion == Operaciones.Forward ? Forward : Inverse;
}

/// <summary>Valores de <c>operation</c>.</summary>
public static class Operaciones
{
    public const string Forward = "forward";
    public const string Inverse = "inverse";
    public static bool EsValida(string? o) => o is Forward or Inverse;
}

/// <summary>
/// Diccionario oficial de equipos y algoritmos (sección 4.1 del estándar v2.0).
/// Al Equipo 3 (EQ03) le corresponden RSA (#5) y ECC (#6).
/// </summary>
public static class Diccionario
{
    public const string Rsa = "RSA";
    public const string Ecc = "ECC";

    public static readonly IReadOnlyList<AlgoritmoOficial> Todos =
    [
        new(1, "AESGCM", "AES-256-GCM / AES-128-GCM", "Simétrico por bloques", 1, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(2, "DES", "DES 56-bit", "Simétrico legado", 1, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(3, "TRIPLEDES", "Triple DES / 3DES", "Simétrico legado", 2, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(4, "CHACHA20", "ChaCha20-Poly1305", "Simétrico de flujo (AEAD)", 2, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(5, Rsa, "RSA-OAEP / RSA-PSS", "Asimétrico", 3, "cifrar", "descifrar", TipoLlave.KeyId, []),
        new(6, Ecc, "ECDH / ECIES / ECDSA", "Asimétrico (curva elíptica)", 3, "cifrar", "descifrar", TipoLlave.KeyId, []),
        new(7, "DIFFIEHELLMAN", "Diffie-Hellman", "Acuerdo de claves", 4, "cifrar", "descifrar", TipoLlave.KeyId, []),
        new(8, "CAESAR", "Cifrado César", "Clásico", 4, "cifrar", "descifrar", TipoLlave.Secreta, ["shift"]),
        new(9, "VIGENERE", "Cifrado Vigenère", "Clásico polialfabético", 5, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(10, "XORASM", "XOR en registro (WREG/ROL/ROR)", "Bajo nivel", 5, "cifrar", "descifrar", TipoLlave.Secreta, ["key"]),
        new(11, "LSBSTEGO", "Esteganografía LSB en PNG/BMP", "Esteganografía", 6, "ocultar", "extraer", TipoLlave.SecretaOpcional, ["password"]),
        new(12, "EUCLIDESAFFINE", "Euclides extendido / Afín", "Teoría de números", 6, "cifrar", "descifrar", TipoLlave.Secreta, ["a", "b"]),
        new(13, "MILLERRABIN", "Miller–Rabin + cifrado modular", "Primalidad", 7, "cifrar", "descifrar", TipoLlave.KeyId, []),
        new(14, "FISHERYATES", "Permutación Fisher–Yates", "Transposición", 7, "permutar", "restaurar", TipoLlave.Secreta, ["seed"]),
        new(15, "HASHSHA", "SHA-256 / SHA-512 / SHA-3", "Integridad", 8, "calcular hash", "verificar", TipoLlave.Ninguna, []),
        new(16, "HMACSHA256", "HMAC-SHA256 / HMAC-SHA512", "Autenticación", 8, "calcular MAC", "verificar", TipoLlave.Secreta, ["key"]),
        new(17, "DIGITALSIG", "Firma digital RSA-PSS / ECDSA", "Autenticidad", null, "firmar", "verificar", TipoLlave.KeyId, []),
        new(18, "QUANTUMPQC", "QKD BB84 + PQC (ML-KEM / LWE)", "Poscuántica", null, "cifrar", "descifrar", TipoLlave.KeyId, []),
        new(19, "DFTSPECTRAL", "Transformada discreta de Fourier", "Señales", null, "transformar", "invertir", TipoLlave.SecretaOpcional, ["key"]),
        new(20, "LAGRANGESHAMIR", "Shamir en GF(256)", "Umbral", null, "dividir", "reconstruir", TipoLlave.Ninguna, []),
        new(21, "LORENZSZ40", "Lorenz SZ40/42", "Flujo electromecánico", null, "cifrar", "descifrar", TipoLlave.Secreta, ["wheelStarts"]),
    ];

    private static readonly Dictionary<string, AlgoritmoOficial> PorCodigoMapa = Todos.ToDictionary(a => a.Codigo, StringComparer.Ordinal);

    /// <summary>Algoritmos que ESTE programa sabe ejecutar localmente.</summary>
    public static readonly IReadOnlySet<string> Implementados = new HashSet<string>(StringComparer.Ordinal) { Rsa, Ecc };

    public static AlgoritmoOficial? PorCodigo(string? codigo) =>
        codigo is not null && PorCodigoMapa.TryGetValue(codigo, out var a) ? a : null;

    public static AlgoritmoOficial? PorId(int id) => Todos.FirstOrDefault(a => a.Id == id);

    /// <summary>¿algorithmId y algorithmCode existen y coinciden? (validación 7 de la sección 13.1)</summary>
    public static bool Coinciden(int id, string? codigo) => PorId(id) is { } a && a.Codigo == codigo;

    /// <summary>Algoritmos que provee un nodo: los que la tabla le asigna y este programa implementa.</summary>
    public static IReadOnlyList<AlgoritmoOficial> ProvistosPor(int equipo) =>
        Todos.Where(a => a.Equipo == equipo && Implementados.Contains(a.Codigo)).ToList();
}
