using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Pruebas.Utilidades;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Identidad X.509 del nodo (sección 7) y firma RSA-PSS (8.2).</summary>
public sealed class IdentidadTests
{
    [Fact]
    public void Certificado_CumpleLaSeccion7()
    {
        var c = Identidades.Eq03.Certificado;
        Assert.Equal("CN=EQ03, OU=Equipo 03, O=Centro de Ciberseguridad, C=MX", c.Subject);
        Assert.Equal(c.Subject, c.Issuer);                                    // autofirmado
        Assert.Equal("1.2.840.113549.1.1.11", c.SignatureAlgorithm.Value);    // sha256WithRSAEncryption
        using var rsa = c.GetRSAPublicKey()!;
        Assert.Equal(2048, rsa.KeySize);
        Assert.InRange((c.NotAfter - c.NotBefore).TotalDays, 364.9, 365.1);
        Assert.True(c.GetSerialNumber().Length >= 8);                         // ≥ 64 bits
        var uso = c.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;
        Assert.Equal(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, uso);
        Assert.Matches(Identificadores.Huella(), Identidades.Eq03.Huella);    // SHA-256 DER, MAYÚSCULAS
        Assert.Equal(Convert.ToHexString(SHA256.HashData(c.RawData)), Identidades.Eq03.Huella);
        Assert.Null(IdentidadNodo.ProblemaCertificado(c, "EQ03", DateTime.UtcNow));
        Assert.NotNull(IdentidadNodo.ProblemaCertificado(c, "EQ05", DateTime.UtcNow)); // CN distinto
    }

    [Fact]
    public void Identidad_SeGuardaCifrada_YSeRecarga()
    {
        var carpeta = Path.Combine(Path.GetTempPath(), "nodo03-id-" + Guid.NewGuid().ToString("N"));
        try
        {
            var a = IdentidadNodo.CargarOCrear(carpeta, 3, "clave");
            var b = IdentidadNodo.CargarOCrear(carpeta, 3, "clave");
            Assert.Equal(a.Huella, b.Huella);
            var privada = File.ReadAllText(Path.Combine(carpeta, "identidad.key.pem"));
            Assert.Contains("ENCRYPTED PRIVATE KEY", privada);                 // nunca en claro
            // Si cambia el equipo, se genera una identidad nueva con el CN correcto.
            Assert.Equal("EQ13", IdentidadNodo.CargarOCrear(carpeta, 13, "clave").NodoId);
        }
        finally { try { Directory.Delete(carpeta, true); } catch (IOException) { } }
    }

    [Fact]
    public void FirmaRsaPss_SeVerifica_YDetectaCambios()
    {
        var datos = "2.0|package|..."u8.ToArray();
        var firma = Identidades.Eq03.Firmar(datos);
        Assert.True(FirmaManifiesto.VerificarBytes(datos, firma, Identidades.Eq03.Certificado));
        Assert.False(FirmaManifiesto.VerificarBytes("2.0|package|.,."u8.ToArray(), firma, Identidades.Eq03.Certificado));
        Assert.False(FirmaManifiesto.VerificarBytes(datos, firma, Identidades.Eq05.Certificado));
        // PSS es probabilístico (sal aleatoria de 32 bytes): dos firmas del mismo texto son distintas.
        Assert.NotEqual(firma, Identidades.Eq03.Firmar(datos));
    }
}

/// <summary>Sobre híbrido CC-ENV-1 (sección 8.3).</summary>
public sealed class SobreTests
{
    [Fact]
    public void Sobre_SoloLoAbreElDestinatario_ConLaMismaAad()
    {
        var secreto = """{"key":"q83vEj=="}"""u8.ToArray();
        var s = SobreCc.Cerrar(secreto, Identidades.Eq05.Certificado, "EQ05", "req-1", cifradoAparte: false, out _);
        Assert.Equal("CC-ENV-1", s.Envelope);
        Assert.Equal(Identidades.Eq05.Huella, s.RecipientThumbprintSha256);
        Assert.Equal(12, Convert.FromBase64String(s.NonceBase64).Length);
        Assert.Equal(16, Convert.FromBase64String(s.TagBase64).Length);
        Assert.Equal(256, Convert.FromBase64String(s.WrappedKeyBase64).Length);
        Assert.Equal(secreto, s.Abrir(Identidades.Eq05, "req-1"));

        Assert.Equal("E-ENV-RECIPIENT", Assert.Throws<ErrorProtocolo>(() => s.Abrir(Identidades.Eq07, "req-1")).Codigo);
        Assert.Equal("E-ENV-DECRYPT", Assert.Throws<ErrorProtocolo>(() => s.Abrir(Identidades.Eq05, "req-2")).Codigo);
    }

    [Fact]
    public void SobreDeResultado_NoLlevaCiphertext()
    {
        var s = SobreCc.Cerrar(new byte[1000], Identidades.Eq05.Certificado, "EQ05", "pkt", cifradoAparte: true, out var cifrado);
        Assert.Null(s.CiphertextBase64);
        Assert.Equal(1000, cifrado.Length);
        Assert.DoesNotContain("ciphertextBase64", System.Text.Json.JsonSerializer.Serialize(s), StringComparison.Ordinal);
        Assert.Equal(new byte[1000], s.Abrir(Identidades.Eq05, "pkt", cifrado));
    }
}

/// <summary>RSA (#5) y ECC (#6) con llaves keyId (secciones 4.2 y 12).</summary>
public sealed class CifradoresTests
{
    [Fact]
    public void Rsa_ParametrosDeLaTabla42_YSeRecupera()
    {
        using var rsa = RSA.Create(2048);
        var plano = RandomNumberGenerator.GetBytes(1024 * 1024);           // 1 MB, como una imagen
        var (datos, p) = CifradorRsa.Cifrar(plano, rsa, "EQ03-KEY-x");
        Assert.Equal(new[] { "keyId", "nonceBase64", "scheme", "tagBase64", "wrappedKeyBase64" }, p.Keys.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal("RSA-OAEP-SHA256+A256GCM", p["scheme"]);
        Assert.Equal(plano.Length, datos.Length);                         // GCM no agrega relleno
        Assert.Equal(plano, CifradorRsa.Descifrar(datos, p, rsa));
        datos[100] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => CifradorRsa.Descifrar(datos, p, rsa));
    }

    [Fact]
    public void Ecc_ParametrosDeLaTabla42_YSeRecupera()
    {
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var plano = Encoding.UTF8.GetBytes("¡Hola, ECIES con P-256!");
        var (datos, p) = CifradorEcc.Cifrar(plano, ec.ExportParameters(false), "EQ03-KEY-y");
        foreach (var k in new[] { "keyId", "curve", "scheme", "ephemeralPublicKeyBase64", "nonceBase64", "tagBase64" })
            Assert.True(p.ContainsKey(k), k);
        Assert.Equal("P-256", p["curve"]);
        Assert.Equal("ECIES", p["scheme"]);
        Assert.Equal(plano, CifradorEcc.Descifrar(datos, p, ec));
        using var otra = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.ThrowsAny<CryptographicException>(() => CifradorEcc.Descifrar(datos, p, otra));
    }

    [Fact]
    public void MismoMensaje_DosCifrados_SonDistintos()
    {
        using var rsa = RSA.Create(2048);
        var a = CifradorRsa.Cifrar("igual"u8, rsa, "k").Datos;
        var b = CifradorRsa.Cifrar("igual"u8, rsa, "k").Datos;
        Assert.NotEqual(a, b);
    }
}

/// <summary>ProveedorLocal: forward/inverse con keyId, resultado CC-ENV-1 y reenvío 9.6.</summary>
public sealed class ProveedorTests : IDisposable
{
    private readonly Laboratorio _lab = new();

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECC")]
    public void ForwardSinKeyId_GeneraLlave_EInverseRecupera(string codigo)
    {
        var p = _lab.Forward(codigo, "mensaje secreto");
        var m = p.Manifiesto;
        Assert.Matches(Identificadores.KeyId(), m.KeyRef!.KeyId);
        Assert.StartsWith("EQ03-KEY-", m.KeyRef.KeyId);
        Assert.Equal("EQ03", m.KeyRef.OwnerNode);
        Assert.Equal(m.KeyRef.KeyId, m.Parametro("keyId"));
        Assert.Equal("cifrar", m.OperationName);
        Assert.Equal(codigo == "RSA" ? 5 : 6, m.AlgorithmId);
        Assert.True(NombrePaquete.EsValido(p.NombreZip));
        var original = _lab.Proveedor.Inverse(EmpaquetadorZip.Leer(p.Zip), "EQ05");
        Assert.Equal("mensaje secreto", Encoding.UTF8.GetString(original));
    }

    [Fact]
    public void ForwardConKeyId_ReutilizaLaLlave()
    {
        var a = _lab.Forward();
        var b = _lab.Forward(keyId: a.Manifiesto.KeyRef!.KeyId);
        Assert.Equal(a.Manifiesto.KeyRef.KeyId, b.Manifiesto.KeyRef!.KeyId);
        Assert.Equal(1, _lab.Repo.ContarLlaves());
    }

    [Fact]
    public void KeyIdDesconocido_EKeyNotFound() =>
        Assert.Equal("E-KEY-NOT-FOUND", Assert.Throws<ErrorProtocolo>(() => _lab.Forward(keyId: "EQ03-KEY-00000000-0000-4000-8000-000000000000")).Codigo);

    [Fact]
    public void AllowedNodes_RestringeQuienUsaLaLlave()
    {
        var p = _lab.Forward(opciones: new() { ["allowedNodes"] = "EQ05" });
        var leido = EmpaquetadorZip.Leer(p.Zip);
        Assert.Equal("hola", Encoding.UTF8.GetString(_lab.Proveedor.Inverse(leido, "EQ05")));
        Assert.Equal("E-KEY-FORBIDDEN", Assert.Throws<ErrorProtocolo>(() => _lab.Proveedor.Inverse(leido, "EQ07")).Codigo);
        Assert.Equal("E-KEY-FORBIDDEN", Assert.Throws<ErrorProtocolo>(() =>
            _lab.Forward(keyId: p.Manifiesto.KeyRef!.KeyId, solicitante: "EQ07")).Codigo);
    }

    [Fact]
    public void OpcionDesconocida_EParams() =>
        Assert.Equal("E-PARAMS", Assert.Throws<ErrorProtocolo>(() => _lab.Forward(opciones: new() { ["keySizeBits"] = "4096" })).Codigo);

    [Fact]
    public void AlgoritmoAjeno_EAlgorithmNotProvided() =>
        Assert.Equal("E-ALGORITHM-NOT-PROVIDED", Assert.Throws<ErrorProtocolo>(() => _lab.Forward("AESGCM")).Codigo);

    [Fact]
    public void Resultado_VaCifradoParaElSolicitante()
    {
        var p = _lab.Forward(texto: "para EQ05");
        var original = _lab.Proveedor.Inverse(EmpaquetadorZip.Leer(p.Zip), "EQ05");
        var r = _lab.Proveedor.EmpaquetarResultado(original, p.Manifiesto, Identidades.Eq05.Certificado, "EQ05", Identificadores.NuevoUuid(), "127.0.0.1:5003");
        Assert.StartsWith("RES_EQ03_RSA_", r.NombreZip);
        var leido = EmpaquetadorZip.Leer(r.Zip);
        Assert.Equal("result", leido.Manifiesto.PacketType);
        Assert.Equal("inverse", leido.Manifiesto.Operation);
        Assert.Equal("descifrar", leido.Manifiesto.OperationName);
        Assert.Empty(leido.Manifiesto.PublicParameters);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", leido.Manifiesto.PublicParametersSha256);
        Assert.Null(leido.Manifiesto.ResultEnvelope!.CiphertextBase64);
        ValidadorPaquete.Validar(leido, DateTime.UtcNow);
        Assert.Equal("para EQ05", Encoding.UTF8.GetString(ProveedorLocal.AbrirResultado(leido, Identidades.Eq05)));
        Assert.Equal("E-ENV-RECIPIENT", Assert.Throws<ErrorProtocolo>(() => ProveedorLocal.AbrirResultado(leido, Identidades.Eq07)).Codigo);
    }

    [Fact]
    public void Reempaquetar_CumpleLaSeccion96()
    {
        var p = _lab.Forward();
        var original = EmpaquetadorZip.Leer(p.Zip);
        var r = new ProveedorLocal(Identidades.Eq05, _lab.Llaves).Reempaquetar(original, "10.0.0.5:5005");
        var n = EmpaquetadorZip.Leer(r.Zip);
        // 1. se conserva
        Assert.Equal(original.Datos, n.Datos);
        Assert.Equal(original.Manifiesto.PublicParameters, n.Manifiesto.PublicParameters);
        Assert.Equal(original.Manifiesto.KeyRef, n.Manifiesto.KeyRef);
        Assert.Equal("EQ03", n.Manifiesto.ProducerNode);
        Assert.Equal(original.Manifiesto.AlgorithmCode, n.Manifiesto.AlgorithmCode);
        // 2 y 3. cambia
        Assert.NotEqual(original.Manifiesto.PacketId, n.Manifiesto.PacketId);
        Assert.Equal("EQ05", n.Manifiesto.SourceNode);
        Assert.Equal(5, n.Manifiesto.SourceTeam);
        Assert.Equal("10.0.0.5:5005", n.Manifiesto.SourceIp);
        Assert.Contains("CN=EQ05", IdentidadNodo.LeerPem(n.CertificadoPem).Subject);
        Assert.StartsWith("EQ05_RSA_", r.NombreZip);
        // 4. firma nueva y válida; y el dueño todavía lo puede descifrar
        ValidadorPaquete.Validar(n, DateTime.UtcNow);
        Assert.Equal("hola", Encoding.UTF8.GetString(_lab.Proveedor.Inverse(n, "EQ05")));
    }

    public void Dispose() => _lab.Dispose();
}
