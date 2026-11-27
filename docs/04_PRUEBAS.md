# 4. Pruebas (estándar v2.0)

## 4.1 Cómo ejecutarlas

```bash
dotnet test                                                  # todas (102)
dotnet test --filter "FullyQualifiedName~Concurrencia"       # solo concurrencia
dotnet test --filter "FullyQualifiedName~Integracion"        # nodos reales por HTTP y UDP
dotnet test --logger "console;verbosity=detailed"            # con el nombre de cada prueba
```

En Visual Studio aparecen en el **Explorador de pruebas**.

## 4.2 Estrategia

| Nivel | Carpeta | Qué valida | Cómo |
| --- | --- | --- | --- |
| Unitarias | `Unitarias/` | Identificadores, tabla 4.1, cadena 8.4, hash canónico 8.5 (con el ejemplo del estándar), nombres 9.2, cada código de error de 13.1, certificado de la sección 7, RSA-PSS, `CC-ENV-1`, RSA/ECC, `keyId`, `allowedNodes`, resultado y reenvío 9.6, base de datos | Identidades en memoria y una base SQLite temporal |
| Integración | `Integracion/` | API del estándar por HTTP, errores `problem+json`, trabajos 202, delegación EQ13 → EQ03, bandeja, ping-pong automático y manual, TOFU y alerta de huella, escaneo, anuncio UDP real | Se levantan **nodos reales** (Kestrel) en puertos aleatorios de `127.0.0.1`; la prueba hace de "otro equipo" (EQ05) firmando sus peticiones |
| Concurrencia | `Concurrencia/` | Que no haya condiciones de carrera | Decenas de peticiones simultáneas (`Task.WhenAll` / `Parallel.ForEachAsync`) y comprobación de que el resultado es el mismo que en serie |
| Interoperabilidad | `herramientas/` | Que otro lenguaje entienda al nodo | `cliente_v2.py` (Python) genera su identidad, firma la petición, valida el paquete y abre el `CC-ENV-1`; `verificar_paquete.py` aplica 13.1 |

## 4.3 Cómo se validó la concurrencia

| Riesgo | Mecanismo en el código | Prueba |
| --- | --- | --- |
| Muchos paquetes a la vez agotan memoria | `SemaphoreSlim` por nodo (2 × núcleos) | `Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde` |
| Copias simultáneas del mismo paquete | Índice `UNIQUE(packet_id)` + `INSERT OR IGNORE`; la copia perdedora borra su zip | `VeinticincoCopias_…_ElRestoEs409` (1×202, 24×409, 1 archivo) |
| Doble clic en Aceptar o usuario + ping-pong a la vez | `UPDATE … WHERE estado='Pendiente'` + inserción en Consultas en la misma transacción | `VeinteClicsEnAceptar_…` (1×200, 19×409) y `AceptarYRechazar_…` |
| Más de 10 `/api/crypto/*` a la vez (13.3) | `SemaphoreSlim(10)` por nodo con `Wait(0)` → `503 E-BUSY` | `TreintaPeticionesCripto_Simultaneas_LimiteDe10_…` (y cada forward genera su propio `keyId` sin choques) |
| Una llave `keyId` usada desde muchos hilos | Cada operación importa su propia instancia de RSA/ECDH | `DoscientasOperacionesCripto_ConLaMismaLlave_EnParalelo` |
| `SQLITE_BUSY` por escrituras simultáneas | WAL, `busy_timeout` y candado de escritura | `BaseDeDatos_CienEscriturasParalelas_…` |
| Dos nodos delegando y enviándose a la vez | `HttpClient` único y servicios sin estado mutable compartido | `DosNodos_DelegandoYEnviando_EnAmbasDirecciones` (8 + 8) |
| Ping-pong que nunca termina | Cola `Channel` + `MaxRebotes` | `PingPongAutomatico_RebotaHastaElLimite` (saltos 0‒4 exactos) |

## 4.4 Resultado

```text
Total: 102  Pasan: 102  Fallan: 0
```

La suite se corrió varias veces seguidas sin fallas. En el desarrollo, la de concurrencia encontró un problema real: el
límite de 10 peticiones era `static` y se compartía entre nodos del mismo proceso; se corrigió para que sea por nodo.

### Unitarias

**CifradoresTests** (3)

- ✔ `Ecc_ParametrosDeLaTabla42_YSeRecupera`
- ✔ `MismoMensaje_DosCifrados_SonDistintos`
- ✔ `Rsa_ParametrosDeLaTabla42_YSeRecupera`

**IdentidadTests** (3)

- ✔ `Certificado_CumpleLaSeccion7`
- ✔ `FirmaRsaPss_SeVerifica_YDetectaCambios`
- ✔ `Identidad_SeGuardaCifrada_YSeRecarga`

**ProtocoloTests** (26)

- ✔ `CadenaDeFirma_TieneLosOnceCamposEnOrden`
- ✔ `CampoFirmadoAlterado_ESignature`
- ✔ `Carpeta_EZipStructure`
- ✔ `CertificadoDeOtroNodo_ECert`
- ✔ `CuatroArchivos_EZipStructure`
- ✔ `DatosAlterados_EHash`
- ✔ `Deflate_YStore_SeAceptanAmbos`
- ✔ `Diccionario_Tiene21Algoritmos_YElEquipo3TieneRsaYEcc`
- ✔ `FaltaCampo_EManifest`
- ✔ `FechaVieja_ETimestamp`
- ✔ `HuellaNoCoincide_ECertThumbprint`
- ✔ `IdYCodigoNoCoinciden_EAlgorithm`
- ✔ `Manifiesto_CamposDesconocidos_SeIgnoran`
- ✔ `Manifiesto_EscribeTodosLosCamposObligatorios_AunqueSeanNull`
- ✔ `NoEsZip_EZipInvalid`
- ✔ `NodeId_EsEQMasDosDigitos`
- ✔ `Nombres_PackageYResult`
- ✔ `PaqueteValido_PasaLasCatorce`
- ✔ `ParametroNoCadena_EManifest`
- ✔ `ParametrosAlterados_EParamsHash`
- ✔ `ParametrosCanonicos_EjemploDelEstandar`
- ✔ `ParametrosCanonicos_OrdenaPorBytesUtf8_NoPorCultura`
- ✔ `ParametrosCanonicos_Vacio_EsElHashDeLaCadenaVacia`
- ✔ `Ventana_EsDeMasMenosDiezMinutos`
- ✔ `Version1_EVersion`
- ✔ `ZipBomba_EZipBomb`

**ProveedorTests** (9)

- ✔ `AlgoritmoAjeno_EAlgorithmNotProvided`
- ✔ `AllowedNodes_RestringeQuienUsaLaLlave`
- ✔ `ForwardConKeyId_ReutilizaLaLlave`
- ✔ `ForwardSinKeyId_GeneraLlave_EInverseRecupera(ECC)`
- ✔ `ForwardSinKeyId_GeneraLlave_EInverseRecupera(RSA)`
- ✔ `KeyIdDesconocido_EKeyNotFound`
- ✔ `OpcionDesconocida_EParams`
- ✔ `Reempaquetar_CumpleLaSeccion96`
- ✔ `Resultado_VaCifradoParaElSolicitante`

**RepositorioTests** (9)

- ✔ `Aceptar_MueveAConsultas_UnaSolaVez`
- ✔ `Ajustes_SePersisten`
- ✔ `Directorio_GuardaHuellaFijadaYAlerta`
- ✔ `Llaves_SeListanSinLaPrivada`
- ✔ `PacketIdDuplicado_NoSeInsertaDosVeces`
- ✔ `PaquetesInvalidos_SeGuardanComoEvidencia_SinBloquearAlValido`
- ✔ `Rechazar_NoEntraAConsultas`
- ✔ `RequestId_SoloSeAceptaUnaVez`
- ✔ `TextoConAcentosYComillas_SeGuardaIntacto_SinInyeccionSql`

**SobreTests** (2)

- ✔ `SobreDeResultado_NoLlevaCiphertext`
- ✔ `Sobre_SoloLoAbreElDestinatario_ConLaMismaAad`


### Integracion

**DescubrimientoUdpTests** (4)

- ✔ `AnuncioConHuellaFalsa_NoSeDaDeAlta`
- ✔ `AnuncioPropio_CabeEnUnKilobyte`
- ✔ `AnuncioUdp_DaDeAltaAlNodo_TrasVerificarloPorHttp`
- ✔ `Interpretar_IgnoraPropiosYMalFormados`

**FlujoEntreNodosTests** (9)

- ✔ `AlgoritmoDeOtroEquipo_SinDueno_NoDisponible`
- ✔ `Escaneo_EncuentraAlOtroNodo`
- ✔ `ForwardDelegado_Bandeja_Aceptar_InverseLocal(ECC)`
- ✔ `ForwardDelegado_Bandeja_Aceptar_InverseLocal(RSA)`
- ✔ `HuellaCambia_SeAlerta_YNoSeUsaHastaReconfirmar`
- ✔ `Imagen_ViajaIntacta`
- ✔ `PingPongAutomatico_RebotaHastaElLimite`
- ✔ `ReboteManual_RegresaLaPelota`
- ✔ `SinConfirmarHuella_ElAlgoritmoNoEstaDisponible`

**ProtocoloHttpTests** (28)

- ✔ `Algorithms_PublicaElPerfilDeRsaYEcc`
- ✔ `AlgoritmoDeOtroEquipo_404_EAlgorithmNotProvided`
- ✔ `AllowedNodes_OtroNodoNoPuedeDescifrar_403`
- ✔ `Bandeja_CuatroArchivos_400_EZipStructure`
- ✔ `Bandeja_FechaVieja_422_ETimestamp`
- ✔ `Bandeja_FijadoConOtraHuella_403_ECertUntrusted`
- ✔ `Bandeja_FirmaAlterada_422_ESignature`
- ✔ `Bandeja_HashAlterado_422_EHash_QuedaComoEvidencia`
- ✔ `Bandeja_MuyGrande_413_ESize`
- ✔ `Bandeja_NoAceptando_503_EBusy`
- ✔ `Bandeja_PaqueteValido_202_YRemitenteNoConfirmado`
- ✔ `Bandeja_RemitenteFijado_FirmaOk`
- ✔ `Bandeja_Repetido_409_EDuplicate_ConProblemJson`
- ✔ `Bandeja_SinMultipart_415`
- ✔ `CertificadoNoEsDelSolicitante_422_ECert`
- ✔ `EncabezadosXcc_EnLasRespuestas`
- ✔ `FaltaPayload_400_ERequest`
- ✔ `FirmaDeLaPeticionAlterada_401`
- ✔ `ForwardEInverseRemotos_RegresanElOriginalCifradoParaElSolicitante(ECC)`
- ✔ `ForwardEInverseRemotos_RegresanElOriginalCifradoParaElSolicitante(RSA)`
- ✔ `Inverse_ConPaqueteSinReenviar_TambienFunciona`
- ✔ `KeyIdDesconocido_404`
- ✔ `Keys_DevuelveSoloLaPublica`
- ✔ `PeticionVieja_422_ETimestamp`
- ✔ `RequestIdRepetido_409`
- ✔ `SobreParaOtroNodo_401_EEnvRecipient`
- ✔ `Status_DiceEQ03_Puerto_AlgoritmosYHuella`
- ✔ `TargetNodeEquivocado_400_ERequest`

**TrabajosAsincronosTests** (1)

- ✔ `TopeSincrono_Responde202_YElResultadoSoloLoBajaElSolicitante`


### Concurrencia

**ConcurrenciaTests** (8)

- ✔ `AceptarYRechazar_AlMismoTiempo_QuedaUnSoloEstadoFinal`
- ✔ `BaseDeDatos_CienEscriturasParalelas_SinErroresDeBloqueo`
- ✔ `Cincuenta_PaquetesDistintos_AlMismoTiempo_NingunoSePierde`
- ✔ `DosNodos_DelegandoYEnviando_EnAmbasDirecciones`
- ✔ `DoscientasOperacionesCripto_ConLaMismaLlave_EnParalelo`
- ✔ `TreintaPeticionesCripto_Simultaneas_LimiteDe10_SinErroresRaros`
- ✔ `VeinteClicsEnAceptar_AlMismoTiempo_SoloUnoGana`
- ✔ `VeinticincoCopias_DelMismoPaquete_SoloSeRegistraUna_ElRestoEs409`
