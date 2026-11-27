using System.Security.Cryptography;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Servicios;

/// <summary>
/// Llaves de algoritmo identificadas por <c>keyId</c> (sección 12 del estándar v2.0).
/// </summary>
/// <remarks>
/// <para>En v2.0 quien cifra con RSA o ECC NO usa la llave del destinatario: le pide al DUEÑO del
/// algoritmo (EQ03) que cifre con una llave que él genera y guarda. Para descifrar, cualquier nodo
/// le manda el paquete al dueño (<c>/api/crypto/inverse</c>) y este usa la privada del keyId.</para>
/// <code>
/// forward sin keyId → se genera un par nuevo: EQ03-KEY-&lt;uuid&gt;
/// forward con keyId → se reutiliza
/// inverse           → se toma el keyId del manifiesto (keyRef)
/// options.allowedNodes = "EQ01,EQ05" → solo esos nodos pueden usar la llave
/// </code>
/// <para>Las privadas se guardan en la base como PKCS#8 CIFRADO con la contraseña del nodo:
/// nunca en claro y nunca salen del nodo.</para>
/// </remarks>
public sealed class GestorLlaves(RepositorioNodo repo, IdentidadNodo yo, string contrasena)
{
    private static readonly PbeParameters Cifrado = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    /// <summary>Genera y guarda un par nuevo para RSA (2048) o ECC (P-256).</summary>
    public LlaveAlgoritmo Crear(string algoritmo, IEnumerable<string>? permitidos = null)
    {
        var llave = new LlaveAlgoritmo
        {
            KeyId = $"{yo.NodoId}-KEY-{Identificadores.NuevoUuid()}",
            Algoritmo = algoritmo,
            Permitidos = string.Join(',', permitidos ?? []),
        };
        if (algoritmo == Diccionario.Rsa)
        {
            using var rsa = RSA.Create(2048);
            llave.PublicaSpkiBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            llave.PrivadaPem = rsa.ExportEncryptedPkcs8PrivateKeyPem(contrasena, Cifrado);
        }
        else if (algoritmo == Diccionario.Ecc)
        {
            using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            llave.PublicaSpkiBase64 = Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo());
            llave.PrivadaPem = ec.ExportEncryptedPkcs8PrivateKeyPem(contrasena, Cifrado);
        }
        else throw new ErrorProtocolo("E-ALGORITHM-NOT-PROVIDED", $"{yo.NodoId} no genera llaves para {algoritmo}.");
        repo.GuardarLlave(llave);
        return llave;
    }

    /// <summary>Busca la llave; E-KEY-NOT-FOUND si no existe o es de otro algoritmo.</summary>
    public LlaveAlgoritmo Obtener(string keyId, string algoritmo)
    {
        var k = repo.ObtenerLlave(keyId);
        if (k is null || k.Algoritmo != algoritmo)
            throw new ErrorProtocolo("E-KEY-NOT-FOUND", $"No existe el keyId {keyId} para {algoritmo} en {yo.NodoId}.");
        return k;
    }

    /// <summary>E-KEY-FORBIDDEN si la llave está restringida y el solicitante no está en la lista.</summary>
    public void VerificarPermiso(LlaveAlgoritmo k, string solicitante)
    {
        if (string.IsNullOrWhiteSpace(k.Permitidos) || solicitante == yo.NodoId) return;
        if (!k.Permitidos.Split(',', StringSplitOptions.TrimEntries).Contains(solicitante))
            throw new ErrorProtocolo("E-KEY-FORBIDDEN", $"El keyId {k.KeyId} no permite a {solicitante}.");
    }

    public static RSA PublicaRsa(LlaveAlgoritmo k)
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(k.PublicaSpkiBase64), out _);
        return rsa;
    }

    public static ECParameters PublicaEc(LlaveAlgoritmo k)
    {
        using var ec = ECDiffieHellman.Create();
        ec.ImportSubjectPublicKeyInfo(Convert.FromBase64String(k.PublicaSpkiBase64), out _);
        return ec.ExportParameters(false);
    }

    public RSA PrivadaRsa(LlaveAlgoritmo k)
    {
        var rsa = RSA.Create();
        rsa.ImportFromEncryptedPem(k.PrivadaPem, contrasena);
        return rsa;
    }

    public ECDiffieHellman PrivadaEc(LlaveAlgoritmo k)
    {
        var ec = ECDiffieHellman.Create();
        ec.ImportFromEncryptedPem(k.PrivadaPem, contrasena);
        return ec;
    }
}
