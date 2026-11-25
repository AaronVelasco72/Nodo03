using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>A quién se le cifra el contenido.</summary>
public enum DestinatarioCifrado
{
    /// <summary>Al propio Nodo 03 (para generar un archivo de prueba o mandarlo a un equipo que solo valida).</summary>
    Propio,
    /// <summary>Al nodo de la dirección indicada: se pide su certificado por /api/certificate.</summary>
    Remoto,
    /// <summary>Al dueño de un certificado .pem que el usuario sube.</summary>
    Pem,
}

/// <summary>Petición de la pantalla "Enviar".</summary>
public sealed record PeticionEnvio(
    ContenidoPlano Contenido, string Codigo, DestinatarioCifrado Destinatario,
    string? Direccion, string? CertificadoPem, bool SoloGenerar);

/// <summary>Lo que se le muestra al usuario después de enviar/generar.</summary>
public sealed record ResultadoEnvio(
    bool Ok, string Mensaje, string? ConsultaId = null, string? NombreZip = null,
    string? Sha256 = null, int? CodigoHttp = null);

/// <summary>Error de negocio que se muestra tal cual al usuario (HTTP 400/409 en la API local).</summary>
public sealed class ErrorEnvioException(string mensaje) : Exception(mensaje);

/// <summary>
/// MODO EMISOR: arma paquetes y los manda a otros nodos. También implementa
/// "Reenviar" y "Rebotar" (ping-pong) desde Consultas.
/// </summary>
public sealed class ServicioEnvio(
    IdentidadNodo identidad, RepositorioNodo repo, AlmacenPaquetes almacen, ClienteNodos cliente,
    BusEventos bus, AjustesNodo ajustes, DireccionPropia direccionPropia, ILogger<ServicioEnvio> log)
{
    /// <summary>Flujo completo de la pantalla Enviar.</summary>
    public async Task<ResultadoEnvio> Enviar(PeticionEnvio p, CancellationToken ct = default)
    {
        if (!CodigosAlgoritmo.LoImplementaEsteNodo(p.Codigo))
            throw new ErrorEnvioException($"El Nodo 03 solo cifra con RSA o ECC (pediste '{p.Codigo}').");
        if (p.Contenido.Bytes.Length == 0)
            throw new ErrorEnvioException("No hay contenido que cifrar.");
        if (!p.SoloGenerar && string.IsNullOrWhiteSpace(p.Direccion))
            throw new ErrorEnvioException("Falta la dirección IP:Puerto del destino.");

        // 1) ¿Con qué llave pública se cifra?
        var certDestino = await ResolverCertificado(p, ct);

        // 2) Armar paquete (cifrar + firmar + zip)
        var paquete = ServicioPaquetes.Armar(p.Contenido, p.Codigo, certDestino, identidad, direccionPropia.Obtener());

        // 3) Guardar y registrar en Consultas
        var consulta = RegistrarSalida(paquete, p.SoloGenerar ? OrigenesConsulta.Generado : OrigenesConsulta.Enviado,
            p.SoloGenerar ? "" : p.Direccion!.Trim(), NodoDe(p), salto: 0);

        if (p.SoloGenerar)
        {
            repo.Registrar("generado", $"Se generó {paquete.NombreZip} ({p.Codigo})", consulta.RallyId, 0);
            return new ResultadoEnvio(true, "Paquete generado. Ya lo puedes descargar.", consulta.Id,
                paquete.NombreZip, paquete.Manifiesto.EncryptedSha256);
        }

        // 4) Enviar por IP
        var respuesta = await EnviarYRegistrar(consulta, paquete, p.Direccion!, ct);
        return new ResultadoEnvio(respuesta.Exitoso,
            respuesta.Exitoso ? "Entregado: el destino lo puso en su bandeja de Solicitudes." : MensajeFallo(respuesta),
            consulta.Id, paquete.NombreZip, paquete.Manifiesto.EncryptedSha256, respuesta.Codigo);
    }

    /// <summary>
    /// Reenvía el .zip TAL CUAL (sin re-cifrar) a otra IP. La firma sigue siendo la del emisor
    /// original, por eso el tercer nodo puede verificar quién lo creó.
    /// </summary>
    public async Task<ResultadoEnvio> Reenviar(string consultaId, string direccion, CancellationToken ct = default)
    {
        var c = repo.ObtenerConsulta(consultaId) ?? throw new ErrorEnvioException("No existe ese registro.");
        var bytes = almacen.Leer(c.RutaZip);
        var r = await cliente.EnviarPaquete(direccion, c.NombreZip, bytes, identidad.NodoId, c.PacketId, ct);
        repo.Registrar("reenvio", $"Reenvío de {c.NombreZip} a {direccion}: {r}", c.RallyId, c.Salto);
        bus.Publicar("envio", new { zip = c.NombreZip, destino = direccion, resultado = r.ToString(), ok = r.Exitoso });
        return new ResultadoEnvio(r.Exitoso, r.Exitoso ? "Reenviado." : MensajeFallo(r), c.Id, c.NombreZip, c.Sha256, r.Codigo);
    }

    /// <summary>
    /// PING-PONG: descifra la pelota con MI llave privada, la vuelve a cifrar con la llave
    /// pública del certificado que vino en el paquete, y la regresa a manifest.sourceIp.
    /// </summary>
    public async Task<ResultadoEnvio> Rebotar(string consultaId, CancellationToken ct = default)
    {
        var c = repo.ObtenerConsulta(consultaId) ?? throw new ErrorEnvioException("No existe ese registro.");
        if (c.Origen != OrigenesConsulta.Recibido)
            throw new ErrorEnvioException("Solo se puede rebotar una pelota que se RECIBIÓ.");
        if (!ajustes.PuedeDescifrar(c.AlgoritmoCodigo))
            throw new ErrorEnvioException($"El descifrado de {c.AlgoritmoCodigo} está deshabilitado en Ajustes.");

        var leido = EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip));
        var m = leido.Manifiesto;
        if (string.IsNullOrWhiteSpace(m.SourceIp))
            throw new ErrorEnvioException("El paquete no indica sourceIp: no hay a dónde regresarlo.");

        // 1) Descifrar con mi llave privada
        ContenidoPlano plano;
        try
        {
            plano = ServicioPaquetes.Abrir(leido, identidad);
        }
        catch (Exception ex) when (ex is DestinatarioIncorrectoException or NotSupportedException or CryptographicException)
        {
            throw new ErrorEnvioException("No se pudo descifrar la pelota: " + ex.Message);
        }

        // 2) Re-cifrar para el emisor, con SU certificado (viene dentro del zip)
        using var certEmisor = IdentidadNodo.LeerCertificadoPem(leido.CertificadoPem);
        var salto = c.Salto + 1;
        var paquete = ServicioPaquetes.Armar(plano, m.AlgorithmCode, certEmisor, identidad,
            direccionPropia.Obtener(), salto, c.RallyId);

        // 3) Regresarla
        var consulta = RegistrarSalida(paquete, OrigenesConsulta.Enviado, m.SourceIp, m.SourceNode, salto);
        var r = await EnviarYRegistrar(consulta, paquete, m.SourceIp, ct, esRebote: true);
        return new ResultadoEnvio(r.Exitoso,
            r.Exitoso ? $"Pelota regresada a {m.SourceNode} (rebote #{salto})." : MensajeFallo(r),
            consulta.Id, paquete.NombreZip, paquete.Manifiesto.EncryptedSha256, r.Codigo);
    }

    // ------------------------------------------------------------------ privados

    private async Task<X509Certificate2> ResolverCertificado(PeticionEnvio p, CancellationToken ct)
    {
        switch (p.Destinatario)
        {
            case DestinatarioCifrado.Propio:
                return identidad.Certificado(p.Codigo);

            case DestinatarioCifrado.Pem:
                try
                {
                    var cert = IdentidadNodo.LeerCertificadoPem(p.CertificadoPem ?? "");
                    if (IdentidadNodo.TipoDeLlave(cert) != p.Codigo)
                        throw new ErrorEnvioException($"El certificado subido no es de tipo {p.Codigo}.");
                    return cert;
                }
                catch (CryptographicException)
                {
                    throw new ErrorEnvioException("El archivo subido no es un certificado PEM válido.");
                }

            default: // Remoto
                var direccion = p.Direccion ?? throw new ErrorEnvioException("Falta la dirección del destino.");
                var pem = await cliente.ObtenerCertificado(direccion, p.Codigo, ct);
                if (pem is null)
                {
                    // Plan B: certificado guardado en el directorio de nodos.
                    var conocido = repo.ObtenerNodo(direccion.Trim());
                    pem = p.Codigo == CodigosAlgoritmo.Rsa ? conocido?.CertificadoRsaPem : conocido?.CertificadoEccPem;
                }
                if (pem is null)
                    throw new ErrorEnvioException(
                        $"El destino no publicó su certificado {p.Codigo} en /api/certificate. Sube su .pem o cifra 'para mí'.");
                return IdentidadNodo.LeerCertificadoPem(pem);
        }
    }

    private Consulta RegistrarSalida(PaqueteGenerado paquete, string origen, string direccion, string nodoRemoto, int salto)
    {
        var m = paquete.Manifiesto;
        var c = new Consulta
        {
            PacketId = m.PacketId, NombreZip = paquete.NombreZip, Origen = origen, NodoRemoto = nodoRemoto,
            Direccion = direccion, AlgoritmoCodigo = m.AlgorithmCode, Modo = m.PayloadMode,
            NombreOriginal = m.OriginalFileName, TamanoOriginal = m.OriginalSizeBytes, Sha256 = m.EncryptedSha256,
            Verificacion = "X.509 OK", Salto = salto,
            RallyId = m.Parametro(ServicioPaquetes.ParamRally) ?? m.PacketId,
        };
        c.RutaZip = almacen.Guardar("enviados", c.Id, paquete.NombreZip, paquete.Zip);
        repo.InsertarConsulta(c);
        return c;
    }

    private async Task<RespuestaEnvio> EnviarYRegistrar(Consulta c, PaqueteGenerado paquete, string direccion,
        CancellationToken ct, bool esRebote = false)
    {
        var r = await cliente.EnviarPaquete(direccion, paquete.NombreZip, paquete.Zip, identidad.NodoId,
            paquete.Manifiesto.PacketId, ct);
        repo.ActualizarResultadoEnvio(c.Id, r.ToString());

        var tipo = esRebote ? "rebote" : "envio";
        repo.Registrar(tipo, $"{paquete.NombreZip} → {direccion}: {r}", c.RallyId, c.Salto);
        bus.Publicar(tipo, new
        {
            zip = paquete.NombreZip, destino = direccion, resultado = r.ToString(), ok = r.Exitoso,
            salto = c.Salto, rallyId = c.RallyId, algoritmo = c.AlgoritmoCodigo,
        });
        log.LogInformation("{Tipo} {Zip} a {Destino}: {Resultado}", tipo, paquete.NombreZip, direccion, r);
        return r;
    }

    private string NodoDe(PeticionEnvio p) => p.Destinatario switch
    {
        DestinatarioCifrado.Propio when p.SoloGenerar => identidad.NodoId,
        _ => repo.ObtenerNodo(p.Direccion?.Trim() ?? "")?.NodoId ?? (p.Direccion ?? ""),
    };

    private static string MensajeFallo(RespuestaEnvio r) => r.Codigo switch
    {
        0 => $"No se pudo conectar con el destino ({r.Cuerpo}). ¿Está encendido y en la misma red?",
        400 => "El destino dijo 400: paquete malformado. " + r.Cuerpo,
        413 => "El destino dijo 413: el paquete excede su límite.",
        422 => "El destino dijo 422: no pudo verificar integridad o firma. " + r.Cuerpo,
        503 => "El destino no está aceptando paquetes (503).",
        _ => $"El destino respondió {r}.",
    };
}
