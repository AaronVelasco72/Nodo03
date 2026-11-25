using System.Security.Cryptography;
using System.Text;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Pruebas.Utilidades;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Pruebas del cifrador RSA (algoritmo #5).</summary>
public class CifradorRsaTests
{
    private readonly CifradorRsa _rsa = new();

    [Fact]
    public void FraseCorta_UsaRsaDirecto_YSeRecupera()
    {
        var plano = Encoding.UTF8.GetBytes("CURP VERA040101HDFLMR09");
        var r = _rsa.Cifrar(plano, Identidades.B.CertificadoRsa);

        Assert.Equal(CifradorRsa.EsquemaDirecto, r.ParametrosPublicos["scheme"]!.ToString());
        Assert.Equal(256, r.Datos.Length); // RSA-2048 siempre produce 256 bytes
        Assert.Equal(plano, _rsa.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.B));
    }

    [Fact]
    public void ArchivoGrande_UsaHibridoRsaAes_YSeRecupera()
    {
        var plano = RandomNumberGenerator.GetBytes(1024 * 1024); // 1 MB, como una imagen
        var r = _rsa.Cifrar(plano, Identidades.B.CertificadoRsa);

        Assert.Equal(CifradorRsa.EsquemaHibrido, r.ParametrosPublicos["scheme"]!.ToString());
        Assert.Equal(plano.Length, r.Datos.Length); // GCM no agrega relleno
        Assert.Equal(plano, _rsa.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.B));
    }

    [Theory]
    [InlineData(190, CifradorRsa.EsquemaDirecto)]   // límite exacto de OAEP-SHA256 con 2048 bits
    [InlineData(191, CifradorRsa.EsquemaHibrido)]   // un byte más ya no cabe
    public void ElLimiteDe190BytesDecideElEsquema(int bytes, string esperado)
    {
        var r = _rsa.Cifrar(new byte[bytes], Identidades.B.CertificadoRsa);
        Assert.Equal(esperado, r.ParametrosPublicos["scheme"]!.ToString());
    }

    [Fact]
    public void MismoMensaje_DosCifrados_SonDistintos()
    {
        // OAEP es probabilístico: protege contra que alguien adivine el mensaje comparando cifrados.
        var plano = Encoding.UTF8.GetBytes("mismo mensaje");
        var r1 = _rsa.Cifrar(plano, Identidades.B.CertificadoRsa);
        var r2 = _rsa.Cifrar(plano, Identidades.B.CertificadoRsa);
        Assert.NotEqual(r1.Datos, r2.Datos);
    }

    [Theory]
    [InlineData(20)]
    [InlineData(5000)]
    public void OtroNodo_NoPuedeDescifrar(int bytes)
    {
        var r = _rsa.Cifrar(new byte[bytes], Identidades.B.CertificadoRsa);
        Assert.ThrowsAny<CryptographicException>(() => _rsa.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.Intruso));
    }

    [Fact]
    public void DatosAlterados_SonDetectadosPorElTagGcm()
    {
        var r = _rsa.Cifrar(new byte[4096], Identidades.B.CertificadoRsa);
        r.Datos[100] ^= 1; // un solo bit
        Assert.ThrowsAny<CryptographicException>(() => _rsa.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.B));
    }

    [Fact]
    public void ParametrosPublicos_NoContienenSecretos()
    {
        var r = _rsa.Cifrar(new byte[4096], Identidades.B.CertificadoRsa);
        var json = r.ParametrosPublicos.ToJsonString();
        Assert.DoesNotContain("private", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        // La llave AES solo viaja CIFRADA con RSA (256 bytes), nunca en claro (32 bytes).
        Assert.Equal(256, Convert.FromBase64String(r.ParametrosPublicos["encryptedKeyBase64"]!.ToString()).Length);
    }

    [Fact]
    public void CertificadoEc_NoSirveParaRsa()
    {
        Assert.ThrowsAny<CryptographicException>(() => _rsa.Cifrar(new byte[10], Identidades.B.CertificadoEcc));
    }
}

/// <summary>Pruebas del cifrador ECC / ECIES (algoritmo #6).</summary>
public class CifradorEccTests
{
    private readonly CifradorEcc _ecc = new();

    [Theory]
    [InlineData(1)]
    [InlineData(190)]
    [InlineData(300_000)]
    public void CifraYDescifra_CualquierTamano(int bytes)
    {
        var plano = RandomNumberGenerator.GetBytes(bytes);
        var r = _ecc.Cifrar(plano, Identidades.B.CertificadoEcc);
        Assert.Equal(CifradorEcc.Esquema, r.ParametrosPublicos["scheme"]!.ToString());
        Assert.Equal(plano, _ecc.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.B));
    }

    [Fact]
    public void CadaEnvio_UsaUnaLlaveEfimeraNueva()
    {
        var r1 = _ecc.Cifrar(new byte[16], Identidades.B.CertificadoEcc);
        var r2 = _ecc.Cifrar(new byte[16], Identidades.B.CertificadoEcc);
        Assert.NotEqual(r1.ParametrosPublicos["ephemeralPublicKeyBase64"]!.ToString(),
                        r2.ParametrosPublicos["ephemeralPublicKeyBase64"]!.ToString());
        Assert.NotEqual(r1.Datos, r2.Datos);
    }

    [Fact]
    public void LlaveEfimera_EsSubjectPublicKeyInfoP256()
    {
        var r = _ecc.Cifrar(new byte[16], Identidades.B.CertificadoEcc);
        using var ec = ECDiffieHellman.Create();
        ec.ImportSubjectPublicKeyInfo(Convert.FromBase64String(r.ParametrosPublicos["ephemeralPublicKeyBase64"]!.ToString()), out _);
        Assert.Equal(256, ec.KeySize);
    }

    [Fact]
    public void OtroNodo_NoPuedeDescifrar()
    {
        var r = _ecc.Cifrar(new byte[64], Identidades.B.CertificadoEcc);
        Assert.ThrowsAny<CryptographicException>(() => _ecc.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.Intruso));
    }

    [Fact]
    public void DatosOTagAlterados_SonDetectados()
    {
        var r = _ecc.Cifrar(new byte[64], Identidades.B.CertificadoEcc);
        r.Datos[0] ^= 0x80;
        Assert.ThrowsAny<CryptographicException>(() => _ecc.Descifrar(r.Datos, r.ParametrosPublicos, Identidades.B));
    }

    [Fact]
    public void CertificadoRsa_NoSirveParaEcc()
    {
        Assert.ThrowsAny<CryptographicException>(() => _ecc.Cifrar(new byte[10], Identidades.B.CertificadoRsa));
    }
}

/// <summary>Pruebas de la firma del manifiesto.</summary>
public class FirmaManifiestoTests
{
    [Theory]
    [InlineData(CodigosAlgoritmo.Rsa, FirmaManifiesto.AlgoritmoRsa)]
    [InlineData(CodigosAlgoritmo.Ecc, FirmaManifiesto.AlgoritmoEcc)]
    public void FirmaPropia_SeVerificaConElCertificado(string codigo, string algoritmo)
    {
        var p = Fabrica.Paquete(codigo);
        Assert.Equal(algoritmo, p.Manifiesto.SignatureAlgorithm);
        var r = FirmaManifiesto.Verificar(p.Manifiesto, Identidades.A.Certificado(codigo));
        Assert.True(r.Valida, r.Detalle);
    }

    [Fact]
    public void FirmaEcdsa_SeEmiteEnDer()
    {
        // DER empieza con 0x30 (SEQUENCE); r||s mediría exactamente 64 bytes.
        var firma = Convert.FromBase64String(Fabrica.Paquete(CodigosAlgoritmo.Ecc).Manifiesto.ManifestSignatureBase64);
        Assert.Equal(0x30, firma[0]);
    }

    [Fact]
    public void FirmaEcdsaFormatoP1363_DeOtroLenguaje_TambienSeAcepta()
    {
        var m = Fabrica.Paquete(CodigosAlgoritmo.Ecc).Manifiesto;
        using var ec = Identidades.A.CrearEcdsaPrivada();
        m.ManifestSignatureBase64 = Convert.ToBase64String(ec.SignData(
            Encoding.UTF8.GetBytes(FirmaManifiesto.CadenaAFirmar(m)), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.True(FirmaManifiesto.Verificar(m, Identidades.A.CertificadoEcc).Valida);
    }

    [Fact]
    public void FirmaSobreManifiestoCanonico_TambienSeAcepta()
    {
        var p = Fabrica.Paquete(CodigosAlgoritmo.Rsa);
        var json = p.Manifiesto.ABytes();
        using var rsa = Identidades.A.CrearRsaPrivada();
        p.Manifiesto.ManifestSignatureBase64 = Convert.ToBase64String(
            rsa.SignData(FirmaManifiesto.FormaCanonica(json)!, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var r = FirmaManifiesto.Verificar(p.Manifiesto, Identidades.A.CertificadoRsa, p.Manifiesto.ABytes());
        Assert.True(r.Valida, r.Detalle);
        Assert.Contains("canónico", r.Detalle);
    }

    [Fact]
    public void CambiarLaFecha_InvalidaLaFirma()
    {
        var m = Fabrica.Paquete().Manifiesto;
        m.TimestampUtc = "2030-01-01T00:00:00Z";
        Assert.False(FirmaManifiesto.Verificar(m, Identidades.A.CertificadoRsa).Valida);
    }

    [Fact]
    public void CertificadoDeOtroNodo_NoVerifica()
    {
        var m = Fabrica.Paquete().Manifiesto;
        Assert.False(FirmaManifiesto.Verificar(m, Identidades.Intruso.CertificadoRsa).Valida);
    }

    [Theory]
    [InlineData("")]
    [InlineData("esto-no-es-base64!!")]
    public void FirmaVaciaOBasura_EsInvalida(string firma)
    {
        var m = Fabrica.Paquete().Manifiesto;
        m.ManifestSignatureBase64 = firma;
        Assert.False(FirmaManifiesto.Verificar(m, Identidades.A.CertificadoRsa).Valida);
    }
}
