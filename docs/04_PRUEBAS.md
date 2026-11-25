# 4. Pruebas

## 4.1 Cómo ejecutarlas

```bash
dotnet test                                   # todas
dotnet test --filter "FullyQualifiedName~Concurrencia"   # solo concurrencia
dotnet test --logger "console;verbosity=detailed"        # con el nombre de cada prueba
```

En Visual Studio aparecen en el **Explorador de pruebas**.

## 4.2 Estrategia

| Nivel | Carpeta | Qué valida | Cómo |
| --- | --- | --- | --- |
| Unitarias | `Unitarias/` | Cada pieza aislada: cifradores, firma, nombre del zip, lector de zip, validador, identidad, base de datos, utilidades | Identidades en memoria, sin red |
| Integración | `Integracion/` | El protocolo HTTP completo y el flujo entre nodos | Se levantan **nodos reales** (Kestrel) en puertos aleatorios de `127.0.0.1`, cada uno con su carpeta temporal, y se comunican por HTTP igual que en la LAN |
| Concurrencia | `Concurrencia/` | Que no haya condiciones de carrera | Decenas de peticiones simultáneas con `Task.WhenAll` / `Parallel.ForEachAsync` y comprobación de que el resultado es el mismo que en serie |
| Interoperabilidad | `herramientas/` | Que otro lenguaje entienda los paquetes | Scripts en Python verifican firmas y descifran RSA directo, RSA híbrido y ECIES generados por el nodo .NET |

## 4.3 Cómo se validó la concurrencia

| Riesgo | Mecanismo en el código | Prueba |
| --- | --- | --- |
| Muchos paquetes al mismo tiempo agotan memoria | `SemaphoreSlim` limita validaciones simultáneas a 2 × núcleos | `Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde` |
| Un emisor reintenta y llegan copias simultáneas | Índice `UNIQUE(packet_id)` + `INSERT OR IGNORE`; la copia perdedora borra su zip | `VeinticincoCopias_DelMismoPaquete_SoloSeRegistraUna` (1 registro, 1 archivo) |
| Doble clic en Aceptar, o usuario y ping-pong automático a la vez | `UPDATE … WHERE estado='Pendiente'` + inserción en Consultas dentro de la misma transacción | `VeinteClicsEnAceptar_AlMismoTiempo_SoloUnoGana` (1×200, 19×409, 1 consulta) |
| Aceptar y rechazar al mismo tiempo | El mismo `WHERE` atómico | `AceptarYRechazar_AlMismoTiempo_QuedaUnSoloEstadoFinal` |
| `RSA`/`ECDsa` compartidos entre hilos | Cada operación crea su instancia desde los parámetros de la llave | `DoscientasOperacionesCripto_ConLaMismaIdentidad_EnParalelo` |
| `SQLITE_BUSY` por escrituras simultáneas | Modo WAL, `busy_timeout` y candado de escritura del proceso | `BaseDeDatos_CienEscriturasParalelas_SinErroresDeBloqueo` |
| Dos nodos enviándose al mismo tiempo en ambas direcciones | `HttpClient` único, servicios sin estado mutable compartido | `DosNodos_EnviandoseALaVez_EnAmbasDirecciones` (15 + 15) |
| Ping-pong automático que nunca termina | Cola `Channel` + límite `MaxRebotes` | `PingPongAutomatico_SeDetieneEnElMaximoDeRebotes` |
| Navegador lento bloquea las alertas | Canal acotado por suscriptor con descarte del más viejo | (diseño) |

## 4.4 Resultado

Las 110 pruebas pasan. La suite completa se ejecutó tres veces seguidas sin fallas (las de concurrencia son las que podrían ser intermitentes si hubiera una carrera).

```text
Total: 110  Pasan: 110  Fallan: 0
```

**CifradorEccTests** (8)

- ✔ `CadaEnvio_UsaUnaLlaveEfimeraNueva` · 2 ms
- ✔ `CertificadoRsa_NoSirveParaEcc` · 0 ms
- ✔ `CifraYDescifra_CualquierTamano(1)` · 296 ms
- ✔ `CifraYDescifra_CualquierTamano(190)` · 3 ms
- ✔ `CifraYDescifra_CualquierTamano(300000)` · 82 ms
- ✔ `DatosOTagAlterados_SonDetectados` · 6 ms
- ✔ `LlaveEfimera_EsSubjectPublicKeyInfoP256` · 1 ms
- ✔ `OtroNodo_NoPuedeDescifrar` · 249 ms

**CifradorRsaTests** (10)

- ✔ `ArchivoGrande_UsaHibridoRsaAes_YSeRecupera` · 226 ms
- ✔ `CertificadoEc_NoSirveParaRsa` · 0 ms
- ✔ `DatosAlterados_SonDetectadosPorElTagGcm` · 3 ms
- ✔ `ElLimiteDe190BytesDecideElEsquema(190, RSA-OAEP-SHA256)` · 0 ms
- ✔ `ElLimiteDe190BytesDecideElEsquema(191, RSA-OAEP-SHA256+AES-256-G…)` · 0 ms
- ✔ `FraseCorta_UsaRsaDirecto_YSeRecupera` · 298 ms
- ✔ `MismoMensaje_DosCifrados_SonDistintos` · 0 ms
- ✔ `OtroNodo_NoPuedeDescifrar(20)` · 104 ms
- ✔ `OtroNodo_NoPuedeDescifrar(5000)` · 6 ms
- ✔ `ParametrosPublicos_NoContienenSecretos` · 11 ms

**ConcurrenciaTests** (7)

- ✔ `AceptarYRechazar_AlMismoTiempo_QuedaUnSoloEstadoFinal` · 1401 ms
- ✔ `BaseDeDatos_CienEscriturasParalelas_SinErroresDeBloqueo` · 1069 ms
- ✔ `Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde` · 1541 ms
- ✔ `DoscientasOperacionesCripto_ConLaMismaIdentidad_EnParalelo` · 2524 ms
- ✔ `DosNodos_EnviandoseALaVez_EnAmbasDirecciones` · 3758 ms
- ✔ `VeinteClicsEnAceptar_AlMismoTiempo_SoloUnoGana` · 1880 ms
- ✔ `VeinticincoCopias_DelMismoPaquete_SoloSeRegistraUna` · 1288 ms

**EmpaquetadorZipTests** (11)

- ✔ `ArchivoDeMas_EsMalformado` · 6 ms
- ✔ `BombaZip_EsCortadaPorElLimiteDescomprimido` · 10 ms
- ✔ `CamposDesconocidosDeOtrosEquipos_SeConservan` · 4 ms
- ✔ `ElZipTieneExactamenteLosTresArchivos` · 301 ms
- ✔ `FaltaUnArchivo_EsMalformado(certificado.pem)` · 9 ms
- ✔ `FaltaUnArchivo_EsMalformado(datos.enc)` · 8 ms
- ✔ `FaltaUnArchivo_EsMalformado(manifest.json)` · 2 ms
- ✔ `ManifiestoQueNoEsJson_EsMalformado` · 4 ms
- ✔ `ManifiestoSinFirma_EsMalformado` · 4 ms
- ✔ `NoEsZip_EsMalformado` · 3 ms
- ✔ `Subcarpetas_SonRechazadas_ProtegeContraZipSlip` · 3 ms

**FirmaManifiestoTests** (9)

- ✔ `CambiarLaFecha_InvalidaLaFirma` · 3 ms
- ✔ `CertificadoDeOtroNodo_NoVerifica` · 2 ms
- ✔ `FirmaEcdsa_SeEmiteEnDer` · 1 ms
- ✔ `FirmaEcdsaFormatoP1363_DeOtroLenguaje_TambienSeAcepta` · 1 ms
- ✔ `FirmaPropia_SeVerificaConElCertificado(ECC, ECDSA-P256-SHA256)` · 1 ms
- ✔ `FirmaPropia_SeVerificaConElCertificado(RSA, RSA-PSS-SHA256)` · 438 ms
- ✔ `FirmaSobreManifiestoCanonico_TambienSeAcepta` · 14 ms
- ✔ `FirmaVaciaOBasura_EsInvalida()` · 2 ms
- ✔ `FirmaVaciaOBasura_EsInvalida(esto-no-es-base64!!)` · 2 ms

**FlujoEntreNodosTests** (12)

- ✔ `DestinoApagado_DevuelveMensajeClaroSinTronar` · 1001 ms
- ✔ `EmisorNoPuedeDescifrarLoQueEnvio_SoloElDestino` · 1300 ms
- ✔ `Imagen_ECC_LlegaIdenticaByteAByte` · 3022 ms
- ✔ `PingPongAutomatico_SeDetieneEnElMaximoDeRebotes(ECC)` · 1402 ms
- ✔ `PingPongAutomatico_SeDetieneEnElMaximoDeRebotes(RSA)` · 1682 ms
- ✔ `PingPongManual_BRebotaYADescifraElMismoMensaje` · 1702 ms
- ✔ `Rechazar_NoGuardaEnConsultas` · 2985 ms
- ✔ `ReenviarATercero_ConservaLaFirmaDelEmisorOriginal` · 1541 ms
- ✔ `SoloGenerar_CreaZipDescargableConNombreOficial` · 1348 ms
- ✔ `Texto_DeANodoB_SeAceptaYSeDescifraIgual(ECC, CURP VERA040101HDFLMR09 ·…)` · 3027 ms
- ✔ `Texto_DeANodoB_SeAceptaYSeDescifraIgual(RSA, Frase corta)` · 2206 ms
- ✔ `Texto_DeANodoB_SeAceptaYSeDescifraIgual(RSA, Frase larga que supera lo…)` · 3532 ms

**IdentidadNodoTests** (3)

- ✔ `Certificados_DeclaranElUsoCorrectoDeLaLlave` · 1 ms
- ✔ `ContrasenaIncorrecta_NoAbreLasLlaves` · 2927 ms
- ✔ `SeGuardaYSeRecarga_ConLaMismaHuella` · 1685 ms

**NombrePaqueteTests** (9)

- ✔ `ReproduceElEjemploDeLaPropuesta` · 14 ms
- ✔ `TryParse_ExtraeLasPartes` · 0 ms
- ✔ `ValidaElFormato(CELULA03_RSA_20261124_101…, True)` · 0 ms
- ✔ `ValidaElFormato(NODO-01_RSA_20261124_1015…, False)` · 0 ms
- ✔ `ValidaElFormato(NODO01_AESGCM_20261116_21…, True)` · 22 ms
- ✔ `ValidaElFormato(NODO01_RSA_2026112_101500…, False)` · 0 ms
- ✔ `ValidaElFormato(NODO01_rsa_20261124_10150…, False)` · 0 ms
- ✔ `ValidaElFormato(NODO01_RSA_20261124_10150…, False)` · 0 ms
- ✔ `ValidaElFormato(NODO01_RSA_20261124_10150…, False)` · 0 ms

**ProtocoloHttpTests** (13)

- ✔ `Certificado_SePublicaEnPem(ECC)` · 2144 ms
- ✔ `Certificado_SePublicaEnPem(RSA)` · 903 ms
- ✔ `FaltaCertificado_400` · 1600 ms
- ✔ `FirmaFalsificada_422` · 1411 ms
- ✔ `MasGrandeQueElLimite_413` · 590 ms
- ✔ `MismoPaqueteDosVeces_EsIdempotente` · 702 ms
- ✔ `NodoQueNoAceptaPaquetes_503` · 756 ms
- ✔ `NoEsZip_400` · 1544 ms
- ✔ `PaqueteValido_202_YQuedaPendiente` · 1533 ms
- ✔ `ShaAlterado_422_YQuedaRechazadaComoInvalida` · 1941 ms
- ✔ `SinMultipart_400` · 1872 ms
- ✔ `Status_RespondeElFormatoDelEstandar` · 1280 ms
- ✔ `Verificador_ReportaSinRegistrar` · 849 ms

**RepositorioTests** (5)

- ✔ `Aceptar_MueveAConsultas_UnaSolaVez` · 33 ms
- ✔ `Ajustes_YNodos_SePersisten` · 22 ms
- ✔ `PacketIdDuplicado_NoSeInsertaDosVeces` · 58 ms
- ✔ `Rechazar_NoEntraAConsultas` · 22 ms
- ✔ `TextoConAcentosYComillas_SeGuardaIntacto_SinInyeccionSql` · 21 ms

**ServicioPaquetesTests** (5)

- ✔ `AlgoritmoDeOtroEquipo_NoSeIntentaDescifrar` · 9 ms
- ✔ `CertificadoDeTipoEquivocado_SeRechazaAntesDeCifrar` · 0 ms
- ✔ `ElDestinatarioCorrecto_RecuperaElContenido` · 14 ms
- ✔ `Manifiesto_CumpleElEsquemaDeLaSeccion21` · 5 ms
- ✔ `OtroNodo_RecibeErrorClaroDeDestinatario` · 3 ms

**UtilidadesWebTests** (11)

- ✔ `HuellasIguales_EsTolerantesAFormato` · 0 ms
- ✔ `NombreSeguro_NoPermiteRutas(.., paquete.zip)` · 0 ms
- ✔ `NombreSeguro_NoPermiteRutas(../../windows/system32/ev…, evil.dll)` · 4 ms
- ✔ `NombreSeguro_NoPermiteRutas(..\..\x.zip, x.zip)` · 0 ms
- ✔ `NombreSeguro_NoPermiteRutas(a:b*c?.zip, a_b_c_.zip)` · 0 ms
- ✔ `Opciones_LimiteEnBytes` · 0 ms
- ✔ `SoloLoopback_EsConsideradoLocal` · 1 ms
- ✔ `UrlBase_NormalizaLoQueEscribeElUsuario(  http://10.0.0.5:8080/  , http://10.0.0.5:8080/)` · 0 ms
- ✔ `UrlBase_NormalizaLoQueEscribeElUsuario(192.168.1.14, http://192.168.1.14:5000/)` · 0 ms
- ✔ `UrlBase_NormalizaLoQueEscribeElUsuario(192.168.1.14:5000, http://192.168.1.14:5000/)` · 1 ms
- ✔ `UrlBase_NormalizaLoQueEscribeElUsuario(localhost:5001, http://localhost:5001/)` · 2 ms

**ValidadorPaqueteTests** (7)

- ✔ `CertificadoQueNoEsPem_EsInvalido` · 7 ms
- ✔ `CertificadoSustituido_FallaHuellaYFirma` · 10 ms
- ✔ `DatosAlterados_FallaIntegridad` · 5 ms
- ✔ `IntrusoRefirmaConSuLlave_PeroLaHuellaYaNoEsLaDeA` · 7 ms
- ✔ `NombreFueraDeFormato_SoloGeneraAviso` · 8 ms
- ✔ `PaqueteLegitimo_EsX509Ok(ECC)` · 4 ms
- ✔ `PaqueteLegitimo_EsX509Ok(RSA)` · 299 ms

## 4.5 Interoperabilidad (Python)

```text
$ python herramientas/verificar_paquete.py NODO05_ECC_20261125_023548_6562734C.zip
  [OK] estructura: 3 archivos en la raíz
  [OK] SHA-256 datos.enc = 6562734c4c3a706c…
  [OK] huella del certificado = 4F102210C99169AF…  (CN=NODO-05 ECC,OU=Equipo 3,…)
  [OK] firma válida: ECDSA-SHA256 (DER)
  => X.509 OK  · algoritmo ECC · modo text

$ python herramientas/descifrar_paquete.py <paquete RSA directo> rsa.key.pem ****
CURP VERA040101HDFLMR09 — consulta tipo RENAPO para la célula 3
$ python herramientas/descifrar_paquete.py <paquete ECC imagen> ecc.key.pem ****
Guardado en descifrado_credencial.png (3738 bytes)
$ python herramientas/descifrar_paquete.py <paquete RSA híbrido> rsa.key.pem ****
Guardado en descifrado_verificar_paquete.py (5565 bytes)
```
