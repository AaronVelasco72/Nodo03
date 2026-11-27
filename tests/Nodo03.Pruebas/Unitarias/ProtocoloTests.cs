using System.IO.Compression;
using System.Text;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Pruebas.Utilidades;

namespace Nodo03.Pruebas.Unitarias;

/// <summary>Reglas del estándar v2.0 que no dependen de la red: identificadores, tabla 4.1, 8.4, 8.5, 9.2 y 13.1.</summary>
public sealed class ProtocoloTests
{
    // ------------------------------------------------------------------ 3. Identificadores

    [Fact]
    public void NodeId_EsEQMasDosDigitos()
    {
        Assert.Equal("EQ03", Identificadores.NodoDeEquipo(3));
        Assert.Equal("EQ13", Identificadores.NodoDeEquipo(13));
        Assert.Equal(8, Identificadores.EquipoDeNodo("EQ08"));
        Assert.Null(Identificadores.EquipoDeNodo("NODO-03"));
        Assert.Null(Identificadores.EquipoDeNodo("eq03"));        // sensible a mayúsculas
        Assert.Matches(Identificadores.Uuid4(), Identificadores.NuevoUuid());
        Assert.Matches(Identificadores.Timestamp(), Identificadores.FormatoFecha(DateTime.UtcNow));
    }

    [Fact]
    public void Ventana_EsDeMasMenosDiezMinutos()
    {
        var ahora = new DateTime(2026, 11, 25, 15, 47, 0, DateTimeKind.Utc);
        Assert.True(Identificadores.DentroDeVentana("2026-11-25T15:37:00Z", ahora));
        Assert.True(Identificadores.DentroDeVentana("2026-11-25T15:57:00Z", ahora));
        Assert.False(Identificadores.DentroDeVentana("2026-11-25T15:36:59Z", ahora));
        Assert.False(Identificadores.DentroDeVentana("2026-11-25T15:57:01Z", ahora));
        Assert.False(Identificadores.DentroDeVentana("ayer", ahora));
    }

    // ------------------------------------------------------------------ 4.1 Diccionario

    [Fact]
    public void Diccionario_Tiene21Algoritmos_YElEquipo3TieneRsaYEcc()
    {
        Assert.Equal(21, Diccionario.Todos.Count);
        Assert.Equal(Enumerable.Range(1, 21), Diccionario.Todos.Select(a => a.Id));
        Assert.True(Diccionario.Coinciden(5, "RSA"));
        Assert.True(Diccionario.Coinciden(6, "ECC"));
        Assert.False(Diccionario.Coinciden(5, "ECC"));
        Assert.False(Diccionario.Coinciden(22, "RSA"));
        Assert.Equal(new[] { "RSA", "ECC" }, Diccionario.ProvistosPor(3).Select(a => a.Codigo));
        Assert.Empty(Diccionario.ProvistosPor(13));                       // el nodo de demo EQ13 no provee nada
        Assert.Equal("EQ08", Diccionario.PorCodigo("HASHSHA")!.NodoDueno);
        Assert.Null(Diccionario.PorCodigo("DIGITALSIG")!.NodoDueno);     // reservado
        Assert.True(Diccionario.PorCodigo("RSA")!.UsaKeyId);
        Assert.Equal("ocultar", Diccionario.PorCodigo("LSBSTEGO")!.NombreOperacion(Operaciones.Forward));
    }

    // ------------------------------------------------------------------ 8.5 Parámetros canónicos

    [Fact]
    public void ParametrosCanonicos_EjemploDelEstandar()
    {
        var p = new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-256", ["digestHex"] = "ab12" };
        Assert.Equal("digestHex=ab12\nhashAlgorithm=SHA-256", ParametrosCanonicos.Texto(p));
        Assert.Equal(Huellas.Sha256Hex(Encoding.UTF8.GetBytes("digestHex=ab12\nhashAlgorithm=SHA-256")), ParametrosCanonicos.Hash(p));
    }

    [Fact]
    public void ParametrosCanonicos_Vacio_EsElHashDeLaCadenaVacia()
    {
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ParametrosCanonicos.Hash(new Dictionary<string, string>()));
    }

    [Fact]
    public void ParametrosCanonicos_OrdenaPorBytesUtf8_NoPorCultura()
    {
        // Ordinal de bytes: 'Z'(5A) < 'a'(61) < 'z'(7A) < 'é'(C3 A9). Una comparación "cultural" pondría 'a' antes que 'Z'.
        var p = new Dictionary<string, string> { ["é"] = "4", ["a"] = "2", ["z"] = "3", ["Z"] = "1" };
        Assert.Equal("Z=1\na=2\nz=3\né=4", ParametrosCanonicos.Texto(p));
    }

    // ------------------------------------------------------------------ 8.4 Cadena de firma

    [Fact]
    public void CadenaDeFirma_TieneLosOnceCamposEnOrden()
    {
        var m = new Manifiesto
        {
            PacketType = "package", PacketId = "550e8400-e29b-41d4-a716-446655440000", SourceNode = "EQ08", ProducerNode = "EQ08",
            AlgorithmCode = "HASHSHA", Operation = "forward", TimestampUtc = "2026-11-25T15:47:00Z",
            EncryptedSha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            PublicParametersSha256 = "3b2c", CertificateThumbprintSha256 = "A1B2",
        };
        Assert.Equal("2.0|package|550e8400-e29b-41d4-a716-446655440000|EQ08|EQ08|HASHSHA|forward|2026-11-25T15:47:00Z|" +
                     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|3b2c|A1B2", FirmaManifiesto.Cadena(m));
    }

    // ------------------------------------------------------------------ 9.2 Nombres

    [Fact]
    public void Nombres_PackageYResult()
    {
        Assert.Equal("EQ08_HASHSHA_20261125_154700_9F86D081.zip",
            NombrePaquete.Construir("package", "EQ08", "HASHSHA", "2026-11-25T15:47:00Z", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        Assert.Equal("RES_EQ01_AESGCM_20261125_160210_ABCDEF01.zip",
            NombrePaquete.Construir("result", "EQ01", "AESGCM", "2026-11-25T16:02:10Z", "abcdef0123"));
        Assert.True(NombrePaquete.EsValido("RES_EQ01_AESGCM_20261125_160210_ABCDEF01.zip"));
        Assert.False(NombrePaquete.EsValido("NODO-03_RSA_20261125_160210_ABCDEF01.zip"));
    }

    // ------------------------------------------------------------------ 9.5 Manifiesto

    [Fact]
    public void Manifiesto_EscribeTodosLosCamposObligatorios_AunqueSeanNull()
    {
        var p = Fabrica.Lab.Forward();
        using var doc = System.Text.Json.JsonDocument.Parse(EmpaquetadorZip.Leer(p.Zip).ManifiestoJson);
        foreach (var campo in Manifiesto.Obligatorios.Append("verification").Append("resultEnvelope"))
            Assert.True(doc.RootElement.TryGetProperty(campo, out _), campo);
        Assert.Equal("2.0", doc.RootElement.GetProperty("version").GetString());
        Assert.Equal(5, doc.RootElement.GetProperty("algorithmId").GetInt32());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, doc.RootElement.GetProperty("requestId").ValueKind);
    }

    [Fact]
    public void Manifiesto_CamposDesconocidos_SeIgnoran()
    {
        var p = Fabrica.Paquete();
        var zip = Fabrica.CambiarManifiesto(p.Zip, j => j["extensionDeOtroEquipo"] = "x");
        var leido = EmpaquetadorZip.Leer(zip);
        ValidadorPaquete.Validar(leido, DateTime.UtcNow); // no lanza: la firma no cubre campos extra
    }

    // ------------------------------------------------------------------ 13.1 Validaciones (código exacto)

    private static string Falla(byte[] zip)
    {
        var r = ValidadorPaquete.Revisar(zip, DateTime.UtcNow);
        Assert.False(r.Valido, "se esperaba que fallara");
        return r.Codigo!;
    }

    [Fact]
    public void PaqueteValido_PasaLasCatorce()
    {
        var r = ValidadorPaquete.Revisar(Fabrica.Paquete().Zip, DateTime.UtcNow);
        Assert.True(r.Valido, r.Detalle);
        Assert.Equal("EQ05", r.Manifiesto!.SourceNode);
        Assert.Equal("EQ03", r.Manifiesto.ProducerNode);
        Assert.Contains("CN=EQ05", r.Certificado!.Sujeto);
    }

    [Fact]
    public void NoEsZip_EZipInvalid() => Assert.Equal("E-ZIP-INVALID", Falla("esto no es un zip"u8.ToArray()));

    [Fact]
    public void CuatroArchivos_EZipStructure() =>
        Assert.Equal("E-ZIP-STRUCTURE", Falla(Fabrica.Modificar(Fabrica.Paquete().Zip, a => a["extra.txt"] = [1])));

    [Fact]
    public void Carpeta_EZipStructure() =>
        Assert.Equal("E-ZIP-STRUCTURE", Falla(Fabrica.Modificar(Fabrica.Paquete().Zip, a => { a["sub/datos.enc"] = a["datos.enc"]; a.Remove("datos.enc"); })));

    [Fact]
    public void ZipBomba_EZipBomb()
    {
        var p = Fabrica.Paquete();
        // 30 MB de ceros comprimen a ~30 KB: razón > 100:1.
        var zip = Fabrica.Modificar(p.Zip, a => a["datos.enc"] = new byte[30 * 1024 * 1024]);
        Assert.Equal("E-ZIP-BOMB", Falla(zip));
    }

    [Fact]
    public void FaltaCampo_EManifest() =>
        Assert.Equal("E-MANIFEST", Falla(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j.Remove("producerNode"))));

    [Fact]
    public void ParametroNoCadena_EManifest() =>
        Assert.Equal("E-MANIFEST", Falla(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j["publicParameters"]!["keyId"] = 5)));

    [Fact]
    public void Version1_EVersion() =>
        Assert.Equal("E-VERSION", Falla(Fabrica.Refirmar(Fabrica.Paquete().Zip, m => m.Version = "1.0", Identidades.Eq05)));

    [Fact]
    public void IdYCodigoNoCoinciden_EAlgorithm() =>
        Assert.Equal("E-ALGORITHM", Falla(Fabrica.Refirmar(Fabrica.Paquete().Zip, m => m.AlgorithmId = 6, Identidades.Eq05)));

    [Fact]
    public void DatosAlterados_EHash() =>
        Assert.Equal("E-HASH", Falla(Fabrica.Modificar(Fabrica.Paquete().Zip, a => a["datos.enc"][0] ^= 1)));

    [Fact]
    public void ParametrosAlterados_EParamsHash() =>
        Assert.Equal("E-PARAMS-HASH", Falla(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j["publicParameters"]!["scheme"] = "otro")));

    [Fact]
    public void CertificadoDeOtroNodo_ECert()
    {
        // EQ07 firma un manifiesto que dice venir de EQ05: el CN no coincide con sourceNode.
        var zip = Fabrica.Refirmar(Fabrica.Paquete().Zip, _ => { }, Identidades.Eq07);
        Assert.Equal("E-CERT", Falla(zip));
    }

    [Fact]
    public void HuellaNoCoincide_ECertThumbprint() =>
        Assert.Equal("E-CERT-THUMBPRINT", Falla(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j["certificateThumbprintSha256"] = new string('A', 64))));

    [Fact]
    public void CampoFirmadoAlterado_ESignature() =>
        // producerNode está en la cadena 8.4: cambiarlo sin volver a firmar rompe la firma.
        Assert.Equal("E-SIGNATURE", Falla(Fabrica.CambiarManifiesto(Fabrica.Paquete().Zip, j => j["producerNode"] = "EQ07")));

    [Fact]
    public void FechaVieja_ETimestamp() =>
        Assert.Equal("E-TIMESTAMP", Falla(Fabrica.Refirmar(Fabrica.Paquete().Zip,
            m => m.TimestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow.AddMinutes(-11)), Identidades.Eq05)));

    [Fact]
    public void Deflate_YStore_SeAceptanAmbos()
    {
        var p = Fabrica.Paquete();
        var archivos = new Dictionary<string, byte[]>();
        using (var z = new ZipArchive(new MemoryStream(p.Zip)))
            foreach (var e in z.Entries) { using var s = e.Open(); using var ms = new MemoryStream(); s.CopyTo(ms); archivos[e.FullName] = ms.ToArray(); }
        Assert.True(ValidadorPaquete.Revisar(Fabrica.ZipCon(archivos, CompressionLevel.NoCompression), DateTime.UtcNow).Valido);
        Assert.True(ValidadorPaquete.Revisar(Fabrica.ZipCon(archivos, CompressionLevel.SmallestSize), DateTime.UtcNow).Valido);
    }
}
