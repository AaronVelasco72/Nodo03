using System.Text;
using System.Text.RegularExpressions;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Pruebas.Utilidades;
using Nodo03.Web;
using Nodo03.Web.Endpoints;
using Nodo03.Web.Servicios;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Nomenclatura del .zip (sección 1).</summary>
public class NombrePaqueteTests
{
    [Fact]
    public void ReproduceElEjemploDeLaPropuesta()
    {
        var nombre = NombrePaquete.Construir("NODO-01", "AESGCM",
            new DateTime(2026, 11, 16, 21, 20, 0, DateTimeKind.Utc),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        Assert.Equal("NODO01_AESGCM_20261116_212000_9F86D081.zip", nombre);
    }

    [Theory]
    [InlineData("NODO01_AESGCM_20261116_212000_9F86D081.zip", true)]
    [InlineData("CELULA03_RSA_20261124_101500_ABCDEF12.zip", true)]
    [InlineData("NODO-01_RSA_20261124_101500_ABCDEF12.zip", false)]  // guion en el nodo
    [InlineData("NODO01_rsa_20261124_101500_ABCDEF12.zip", false)]   // algoritmo en minúsculas
    [InlineData("NODO01_RSA_20261124_101500_abcdef12.zip", false)]   // SHA8 en minúsculas
    [InlineData("NODO01_RSA_2026112_101500_ABCDEF12.zip", false)]    // fecha incompleta
    [InlineData("NODO01_RSA_20261124_101500_ABCDEF12.rar", false)]
    public void ValidaElFormato(string nombre, bool valido) => Assert.Equal(valido, NombrePaquete.EsValido(nombre));

    [Fact]
    public void TryParse_ExtraeLasPartes()
    {
        Assert.True(NombrePaquete.TryParse("NODO03_ECC_20261124_101500_ABCDEF12.zip", out var p));
        Assert.Equal("NODO03", p.Nodo);
        Assert.Equal("ECC", p.Algoritmo);
        Assert.Equal("ABCDEF12", p.Sha8);
    }
}

/// <summary>Estructura del .zip y lectura segura (sección 2).</summary>
public class EmpaquetadorZipTests
{
    [Fact]
    public void ElZipTieneExactamenteLosTresArchivos()
    {
        var p = Fabrica.Paquete();
        var leido = EmpaquetadorZip.Leer(p.Zip);
        Assert.Equal(Huellas.Sha256Hex(leido.DatosEnc), leido.Manifiesto.EncryptedSha256);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", Encoding.ASCII.GetString(leido.CertificadoPem));
    }

    [Fact]
    public void NoEsZip_EsMalformado() =>
        Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(Encoding.UTF8.GetBytes("hola, no soy un zip")));

    [Theory]
    [InlineData(EmpaquetadorZip.ArchivoDatos)]
    [InlineData(EmpaquetadorZip.ArchivoCertificado)]
    [InlineData(EmpaquetadorZip.ArchivoManifiesto)]
    public void FaltaUnArchivo_EsMalformado(string quitar)
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a.Remove(quitar));
        var ex = Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip));
        Assert.Contains(quitar, ex.Message);
    }

    [Fact]
    public void ArchivoDeMas_EsMalformado()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a["virus.exe"] = [0x4D, 0x5A]);
        Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip));
    }

    [Fact]
    public void Subcarpetas_SonRechazadas_ProtegeContraZipSlip()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a =>
        {
            a["../../datos.enc"] = a[EmpaquetadorZip.ArchivoDatos];
            a.Remove(EmpaquetadorZip.ArchivoDatos);
        });
        var ex = Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip));
        Assert.Contains("subcarpetas", ex.Message);
    }

    [Fact]
    public void ManifiestoQueNoEsJson_EsMalformado()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a[EmpaquetadorZip.ArchivoManifiesto] = "{ roto"u8.ToArray());
        Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip));
    }

    [Fact]
    public void ManifiestoSinFirma_EsMalformado()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a =>
            a[EmpaquetadorZip.ArchivoManifiesto] = """{"packetId":"x","timestampUtc":"2026-01-01T00:00:00Z"}"""u8.ToArray());
        var ex = Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip));
        Assert.Contains("manifestSignatureBase64", ex.Message);
    }

    [Fact]
    public void BombaZip_EsCortadaPorElLimiteDescomprimido()
    {
        // 5 MB de ceros comprimen a pocos KB; con tope de 1 MB el lector debe detenerse.
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a[EmpaquetadorZip.ArchivoDatos] = new byte[5 * 1024 * 1024]);
        Assert.True(zip.Length < 200 * 1024);
        Assert.Throws<PaqueteMalformadoException>(() => EmpaquetadorZip.Leer(zip, maxBytesPorArchivo: 1024 * 1024));
    }

    [Fact]
    public void CamposDesconocidosDeOtrosEquipos_SeConservan()
    {
        var json = """{"packetId":"p","timestampUtc":"t","encryptedSha256":"a","certificateThumbprintSha256":"b","manifestSignatureBase64":"c","teamColor":"azul"}""";
        var m = Manifiesto.DesdeBytes(Encoding.UTF8.GetBytes(json));
        Assert.Contains("teamColor", Encoding.UTF8.GetString(m.ABytes()));
    }
}

/// <summary>Validación criptográfica de paquetes recibidos.</summary>
public class ValidadorPaqueteTests
{
    [Theory]
    [InlineData(CodigosAlgoritmo.Rsa)]
    [InlineData(CodigosAlgoritmo.Ecc)]
    public void PaqueteLegitimo_EsX509Ok(string codigo)
    {
        var p = Fabrica.Paquete(codigo);
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(p.Zip), p.NombreZip);
        Assert.True(v.Valido, string.Join("; ", v.Errores));
        Assert.Equal("X.509 OK", v.Etiqueta);
        Assert.Empty(v.Avisos);
    }

    [Fact]
    public void DatosAlterados_FallaIntegridad()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a[EmpaquetadorZip.ArchivoDatos][0] ^= 1);
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(zip));
        Assert.False(v.IntegridadOk);
        Assert.Equal("Inválida", v.Etiqueta);
    }

    [Fact]
    public void CertificadoSustituido_FallaHuellaYFirma()
    {
        // Un atacante cambia certificado.pem por el suyo para hacerse pasar por A.
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a =>
            a[EmpaquetadorZip.ArchivoCertificado] = Encoding.ASCII.GetBytes(Identidades.Intruso.CertificadoPem("RSA")));
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(zip));
        Assert.False(v.HuellaOk);
        Assert.False(v.FirmaOk);
    }

    [Fact]
    public void IntrusoRefirmaConSuLlave_PeroLaHuellaYaNoEsLaDeA()
    {
        // Paquete armado y firmado completo por el intruso: es VÁLIDO criptográficamente,
        // pero la huella del certificado delata que NO es del Nodo A. Por eso se muestra la huella.
        var p = Fabrica.Paquete(emisor: Identidades.Intruso);
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(p.Zip));
        Assert.True(v.Valido);
        Assert.NotEqual(Identidades.A.Huella("RSA"), v.Certificado!.Huella);
    }

    [Fact]
    public void CertificadoQueNoEsPem_EsInvalido()
    {
        var zip = Fabrica.Modificar(Fabrica.Paquete().Zip, a => a[EmpaquetadorZip.ArchivoCertificado] = "no soy un certificado"u8.ToArray());
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(zip));
        Assert.False(v.Valido);
    }

    [Fact]
    public void NombreFueraDeFormato_SoloGeneraAviso()
    {
        var p = Fabrica.Paquete();
        var v = ValidadorPaquete.Validar(EmpaquetadorZip.Leer(p.Zip), "mi paquete.zip");
        Assert.True(v.Valido);
        Assert.Contains(v.Avisos, a => a.Contains("no sigue"));
    }
}

/// <summary>Caso de uso Armar/Abrir.</summary>
public class ServicioPaquetesTests
{
    [Fact]
    public void Manifiesto_CumpleElEsquemaDeLaSeccion21()
    {
        var p = Fabrica.Paquete(CodigosAlgoritmo.Ecc, "hola", direccion: "192.168.1.14:5000");
        var m = p.Manifiesto;
        Assert.Equal("1.0", m.Version);
        Assert.True(Guid.TryParse(m.PacketId, out _));
        Assert.Equal("NODO-A", m.SourceNode);
        Assert.Equal("192.168.1.14:5000", m.SourceIp);
        Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"), m.TimestampUtc);
        Assert.Equal("ECC", m.AlgorithmCode);
        Assert.Equal("text", m.PayloadMode);
        Assert.Equal(".txt", m.OriginalExtension);
        Assert.Equal(4, m.OriginalSizeBytes);
        Assert.Matches(new Regex("^[0-9a-f]{64}$"), m.EncryptedSha256);
        Assert.Matches(new Regex("^[0-9A-F]{64}$"), m.CertificateThumbprintSha256);
        Assert.True(NombrePaquete.EsValido(p.NombreZip));
        Assert.Contains("_ECC_", p.NombreZip);
    }

    [Fact]
    public void ElDestinatarioCorrecto_RecuperaElContenido()
    {
        var p = Fabrica.Paquete(CodigosAlgoritmo.Rsa, "secreto ñandú 🔐");
        var plano = ServicioPaquetes.Abrir(EmpaquetadorZip.Leer(p.Zip), Identidades.B);
        Assert.Equal("secreto ñandú 🔐", Encoding.UTF8.GetString(plano.Bytes));
        Assert.Equal("mensaje.txt", plano.NombreArchivo);
    }

    [Fact]
    public void OtroNodo_RecibeErrorClaroDeDestinatario()
    {
        var p = Fabrica.Paquete();
        Assert.Throws<DestinatarioIncorrectoException>(() => ServicioPaquetes.Abrir(EmpaquetadorZip.Leer(p.Zip), Identidades.Intruso));
    }

    [Fact]
    public void AlgoritmoDeOtroEquipo_NoSeIntentaDescifrar()
    {
        var p = Fabrica.Paquete();
        var leido = EmpaquetadorZip.Leer(p.Zip);
        leido.Manifiesto.AlgorithmCode = "VIGENERE";
        Assert.Throws<NotSupportedException>(() => ServicioPaquetes.Abrir(leido, Identidades.B));
    }

    [Fact]
    public void CertificadoDeTipoEquivocado_SeRechazaAntesDeCifrar() =>
        Assert.Throws<InvalidOperationException>(() =>
            ServicioPaquetes.Armar(Fabrica.Texto("x"), CodigosAlgoritmo.Ecc, Identidades.B.CertificadoRsa, Identidades.A, "x:1"));
}

/// <summary>Identidad persistente del nodo.</summary>
public class IdentidadNodoTests
{
    [Fact]
    public void SeGuardaYSeRecarga_ConLaMismaHuella()
    {
        var carpeta = Path.Combine(Path.GetTempPath(), "nodo03-id-" + Guid.NewGuid().ToString("N"));
        try
        {
            var primera = IdentidadNodo.CargarOCrear(carpeta, "NODO-X", "clave");
            var segunda = IdentidadNodo.CargarOCrear(carpeta, "NODO-X", "clave");
            Assert.Equal(primera.Huella("RSA"), segunda.Huella("RSA"));
            Assert.Equal(primera.Huella("ECC"), segunda.Huella("ECC"));
            // La llave privada en disco está CIFRADA.
            Assert.Contains("ENCRYPTED PRIVATE KEY", File.ReadAllText(Path.Combine(carpeta, "rsa.key.pem")));
        }
        finally { Directory.Delete(carpeta, true); }
    }

    [Fact]
    public void ContrasenaIncorrecta_NoAbreLasLlaves()
    {
        var carpeta = Path.Combine(Path.GetTempPath(), "nodo03-id-" + Guid.NewGuid().ToString("N"));
        try
        {
            IdentidadNodo.CargarOCrear(carpeta, "NODO-X", "buena");
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                IdentidadNodo.CargarOCrear(carpeta, "NODO-X", "mala"));
        }
        finally { Directory.Delete(carpeta, true); }
    }

    [Fact]
    public void Certificados_DeclaranElUsoCorrectoDeLaLlave()
    {
        var ku = Identidades.A.CertificadoEcc.Extensions
            .OfType<System.Security.Cryptography.X509Certificates.X509KeyUsageExtension>().Single();
        Assert.True(ku.KeyUsages.HasFlag(System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyAgreement));
        Assert.Contains("CN=NODO-A ECC", Identidades.A.CertificadoEcc.Subject);
        Assert.Equal("RSA", IdentidadNodo.TipoDeLlave(Identidades.A.CertificadoRsa));
        Assert.Equal("ECC", IdentidadNodo.TipoDeLlave(Identidades.A.CertificadoEcc));
    }
}

/// <summary>Utilidades de red y seguridad del nodo web.</summary>
public class UtilidadesWebTests
{
    [Theory]
    [InlineData("192.168.1.14:5000", "http://192.168.1.14:5000/")]
    [InlineData("192.168.1.14", "http://192.168.1.14:5000/")]
    [InlineData("  http://10.0.0.5:8080/  ", "http://10.0.0.5:8080/")]
    [InlineData("localhost:5001", "http://localhost:5001/")]
    public void UrlBase_NormalizaLoQueEscribeElUsuario(string entrada, string esperado) =>
        Assert.Equal(esperado, ClienteNodos.UrlBase(entrada).ToString());

    [Theory]
    [InlineData("../../windows/system32/evil.dll", "evil.dll")]
    [InlineData("..\\..\\x.zip", "x.zip")]
    [InlineData("a:b*c?.zip", "a_b_c_.zip")]
    [InlineData("..", "paquete.zip")]
    public void NombreSeguro_NoPermiteRutas(string entrada, string esperado) =>
        Assert.Equal(esperado, AlmacenPaquetes.NombreSeguro(entrada));

    [Fact]
    public void SoloLoopback_EsConsideradoLocal()
    {
        Assert.True(LocalEndpoints.EsLocal(System.Net.IPAddress.Loopback));
        Assert.True(LocalEndpoints.EsLocal(System.Net.IPAddress.IPv6Loopback));
        Assert.False(LocalEndpoints.EsLocal(System.Net.IPAddress.Parse("192.168.1.20")));
    }

    [Fact]
    public void HuellasIguales_EsTolerantesAFormato()
    {
        Assert.True(Huellas.HuellasIguales("a1:b2:c3", "A1B2C3"));
        Assert.False(Huellas.HuellasIguales("", ""));
        Assert.False(Huellas.HuellasIguales("A1B2", "A1B3"));
    }

    [Fact]
    public void Opciones_LimiteEnBytes()
    {
        Assert.Equal(50L * 1024 * 1024, new OpcionesNodo().LimiteZipBytes);
    }
}
