using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;

namespace Nodo03.Web.Servicios;

/// <summary>Anuncio UDP <c>CC-BEACON</c> (sección 6.1).</summary>
public sealed record Anuncio(
    string Type, string ProtocolVersion, string NodeId, int TeamNumber, string Ip, int HttpPort, int? HttpsPort,
    string Status, string[] Algorithms, string CertificateThumbprintSha256, string TimestampUtc);

/// <summary>Resultado de dar de alta / refrescar un nodo.</summary>
public sealed record ResultadoAlta(bool Ok, string Mensaje, NodoConocido? Nodo);

/// <summary>
/// DIRECTORIO LOCAL DE NODOS (secciones 6.3 y 6.4): alta por anuncio UDP, escaneo HTTP o
/// alta manual, confianza en el primer uso (TOFU) y alerta si cambia la huella.
/// </summary>
/// <remarks>
/// <code>
/// 1. Fuente: beacon | scan | manual
/// 2. GET /api/status + GET /api/certificate
/// 3. nodeId = CN del certificado, huella = la anunciada
/// 4. El usuario CONFIRMA la huella → queda fijada (huella_fijada)
/// 5. Si luego presenta otra huella → alerta = true y el nodo NO se usa hasta reconfirmar
/// </code>
/// </remarks>
public sealed class ServicioDirectorio(
    RepositorioNodo repo, ClienteNodos cliente, OpcionesNodo opciones, IdentidadNodo yo, BusEventos bus, ILogger<ServicioDirectorio> log)
{
    /// <summary>Un nodo pasa a offline tras 90 s sin anuncio ni respuesta (6.1).</summary>
    public static readonly TimeSpan LimiteOffline = TimeSpan.FromSeconds(90);

    /// <summary>Evita verificar el mismo nodo varias veces a la vez cuando llegan anuncios seguidos.</summary>
    private readonly ConcurrentDictionary<string, byte> _enCurso = new();
    private readonly SemaphoreSlim _escaneo = new(1, 1);

    // ------------------------------------------------------------------ Alta

    /// <summary>
    /// Verifica un nodo por HTTP (pasos 2 y 3 de 6.3) y lo guarda. Sirve para las tres fuentes.
    /// </summary>
    public async Task<ResultadoAlta> Verificar(string ip, int puerto, string fuente, string? huellaAnunciada = null, CancellationToken ct = default)
    {
        var direccion = $"{ip}:{puerto}";
        var estado = await cliente.Estado(direccion, fuente == "scan" ? TimeSpan.FromMilliseconds(500) : TimeSpan.FromSeconds(3), ct);
        if (estado is null) return new(false, $"{direccion} no respondió GET /api/status.", null);
        if (estado.ProtocolVersion != Identificadores.VersionProtocolo || !Identificadores.NodeId().IsMatch(estado.NodeId ?? ""))
            return new(false, $"{direccion} no es un nodo v2.0 (protocolVersion={estado.ProtocolVersion}, nodeId={estado.NodeId}).", null);
        if (estado.NodeId == opciones.NodoId)
            return new(false, "Ese es este mismo nodo.", null);

        var pem = await cliente.Certificado(direccion, ct);
        if (pem is null) return new(false, $"{estado.NodeId} no entregó GET /api/certificate.", null);
        string huella;
        try
        {
            using var cert = IdentidadNodo.LeerPem(pem);
            if (IdentidadNodo.ProblemaCertificado(cert, estado.NodeId!, DateTime.UtcNow) is { } problema)
                return new(false, $"Certificado de {estado.NodeId} inválido: {problema}", null);
            huella = Huellas.HuellaCertificado(cert);
        }
        catch (CryptographicException) { return new(false, $"{estado.NodeId} entregó un certificado ilegible.", null); }

        if (!string.Equals(huella, estado.CertificateThumbprintSha256, StringComparison.Ordinal) ||
            (huellaAnunciada is not null && huella != huellaAnunciada))
            return new(false, $"La huella del certificado de {estado.NodeId} no coincide con la anunciada.", null);

        var previo = repo.ObtenerNodo(estado.NodeId!);
        var nodo = previo ?? new NodoConocido { NodeId = estado.NodeId!, Fuente = fuente };
        nodo.Equipo = estado.TeamNumber;
        nodo.Ip = ip;
        nodo.HttpPort = puerto;
        nodo.HttpsPort = estado.HttpsPort;
        nodo.Algoritmos = string.Join(',', (estado.Algorithms ?? []).Select(a => a.AlgorithmCode));
        nodo.HuellaPresentada = huella;
        nodo.Estado = "online";
        nodo.VistoUtc = DateTime.UtcNow;
        if (previo is null || fuente == "manual") nodo.Fuente = fuente;

        var cambio = nodo.HuellaFijada is not null && nodo.HuellaFijada != huella;
        if (cambio && !nodo.Alerta)
        {
            repo.Registrar("alerta", $"¡{nodo.NodeId} presenta una huella DISTINTA a la confirmada! No se usará hasta que la aceptes.");
            bus.Publicar("alerta", new { nodeId = nodo.NodeId, mensaje = $"{nodo.NodeId} cambió de certificado" });
        }
        nodo.Alerta = cambio;
        repo.GuardarNodo(nodo);
        if (previo is null)
        {
            repo.Registrar("directorio", $"Nuevo nodo {nodo.NodeId} en {direccion} (fuente: {fuente}). Confirma su huella.");
            bus.Publicar("nodo", new { nodeId = nodo.NodeId, direccion, nuevo = true });
        }
        return new(true, cambio ? "La huella cambió: confírmala de nuevo." : "Nodo verificado.", nodo);
    }

    /// <summary>Alta manual "IP:puerto" (6.3: DEBE existir siempre).</summary>
    public Task<ResultadoAlta> AltaManual(string direccion, CancellationToken ct = default)
    {
        var url = ClienteNodos.UrlBase(direccion);
        return Verificar(url.Host, url.Port, "manual", null, ct);
    }

    /// <summary>Paso 4 de 6.3: el usuario confirma la huella presentada → queda fijada.</summary>
    public NodoConocido? Confirmar(string nodeId)
    {
        var n = repo.ObtenerNodo(nodeId);
        if (n?.HuellaPresentada is null) return null;
        n.HuellaFijada = n.HuellaPresentada;
        n.Alerta = false;
        repo.GuardarNodo(n);
        repo.Registrar("directorio", $"Huella de {nodeId} confirmada (TOFU): {n.HuellaFijada[..16]}…");
        bus.Publicar("nodo", new { nodeId, confirmado = true });
        return n;
    }

    // ------------------------------------------------------------------ Anuncios UDP

    /// <summary>
    /// Procesa un anuncio ya validado. Un anuncio NO es confiable por sí mismo: si el nodo es
    /// nuevo, cambió de IP/puerto o de huella, se confirma por HTTP antes de guardarlo.
    /// </summary>
    public async Task ProcesarAnuncio(Anuncio a, CancellationToken ct = default)
    {
        var n = repo.ObtenerNodo(a.NodeId);
        if (a.Status == "offline")
        {
            if (n is not null) { n.Estado = "offline"; repo.GuardarNodo(n); bus.Publicar("nodo", new { nodeId = a.NodeId, estado = "offline" }); }
            return;
        }
        if (n is not null && n.Ip == a.Ip && n.HttpPort == a.HttpPort && n.HuellaPresentada == a.CertificateThumbprintSha256)
        {
            var volvio = n.Estado != "online";
            n.Estado = "online";
            n.VistoUtc = DateTime.UtcNow;
            n.Algoritmos = string.Join(',', a.Algorithms);
            repo.GuardarNodo(n);
            if (volvio) bus.Publicar("nodo", new { nodeId = a.NodeId, estado = "online" });
            return;
        }
        if (!_enCurso.TryAdd(a.NodeId, 0)) return;
        try
        {
            var r = await Verificar(a.Ip, a.HttpPort, "beacon", a.CertificateThumbprintSha256, ct);
            if (!r.Ok) log.LogInformation("Anuncio de {Nodo} descartado: {Motivo}", a.NodeId, r.Mensaje);
        }
        finally { _enCurso.TryRemove(a.NodeId, out _); }
    }

    /// <summary>Marca offline los nodos sin señal en 90 s (intenta antes un GET /api/status).</summary>
    public async Task RevisarOffline(CancellationToken ct = default)
    {
        foreach (var n in repo.ListarNodos().Where(n => n.Estado == "online" && n.VistoUtc < DateTime.UtcNow - LimiteOffline))
        {
            var e = await cliente.Estado(n.Direccion, TimeSpan.FromSeconds(2), ct);
            if (e is not null && e.NodeId == n.NodeId && e.CertificateThumbprintSha256 == n.HuellaPresentada)
            {
                n.VistoUtc = DateTime.UtcNow;
            }
            else
            {
                n.Estado = "offline";
                bus.Publicar("nodo", new { nodeId = n.NodeId, estado = "offline" });
            }
            repo.GuardarNodo(n);
        }
    }

    // ------------------------------------------------------------------ Escaneo HTTP (6.2)

    /// <summary>
    /// "Buscar nodos": recorre la subred /24 de cada interfaz en los puertos 5001–5020 con
    /// GET /api/status (500 ms por intento, máximo 64 conexiones a la vez).
    /// </summary>
    public async Task<int> Escanear(IEnumerable<IPAddress>? redes = null, CancellationToken ct = default, IEnumerable<int>? puertos = null)
    {
        if (!await _escaneo.WaitAsync(0, ct)) return -1; // ya hay un escaneo en curso
        try
        {
            var bases = (redes ?? DireccionPropia.Interfaces().Select(i => i.Ip))
                .Select(ip => ip.GetAddressBytes()).Select(b => $"{b[0]}.{b[1]}.{b[2]}.").Distinct().ToList();
            var objetivos = from b in bases from h in Enumerable.Range(1, 254) from p in (puertos ?? Enumerable.Range(5001, 20)) select (Ip: b + h, Puerto: p);
            var encontrados = 0;
            await Parallel.ForEachAsync(objetivos, new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct }, async (o, t) =>
            {
                if (o.Puerto == opciones.PuertoEfectivo && bases.Count > 0 && DireccionPropia.Interfaces().Any(i => i.Ip.ToString() == o.Ip)) return;
                var r = await Verificar(o.Ip, o.Puerto, "scan", null, t);
                if (r.Ok) Interlocked.Increment(ref encontrados);
            });
            repo.Registrar("directorio", $"Búsqueda de nodos terminada: {encontrados} encontrados en {string.Join(", ", bases.Select(b => b + "0/24"))}.");
            return encontrados;
        }
        finally { _escaneo.Release(); }
    }

    // ------------------------------------------------------------------ Uso

    /// <summary>
    /// Nodo que debe ejecutar un algoritmo (4.4): el dueño de la tabla 4.1 si está; para los
    /// reservados, el de número de equipo menor. Devuelve el nodo o el motivo de "no disponible".
    /// </summary>
    public (NodoConocido? Nodo, string Motivo) Proveedor(AlgoritmoOficial alg, string? nodoForzado = null)
    {
        var nodos = repo.ListarNodos();
        NodoConocido? n;
        if (nodoForzado is not null) n = nodos.FirstOrDefault(x => x.NodeId == nodoForzado);
        else if (alg.NodoDueno is { } dueno) n = nodos.FirstOrDefault(x => x.NodeId == dueno);
        else n = nodos.Where(x => x.ListaAlgoritmos.Contains(alg.Codigo)).OrderBy(x => x.Equipo).FirstOrDefault();

        var quien = nodoForzado ?? alg.NodoDueno ?? "ningún nodo";
        if (n is null) return (null, alg.NodoDueno is null && nodoForzado is null
            ? "Algoritmo reservado: ningún nodo del directorio lo anuncia."
            : $"{quien} no está en el directorio. Búscalo o dalo de alta manualmente.");
        if (n.Alerta) return (null, $"{n.NodeId} presenta una huella distinta a la confirmada. Revísala en Nodos.");
        if (n.HuellaFijada is null) return (null, $"Confirma la huella de {n.NodeId} en Nodos antes de usarlo.");
        if (n.Estado != "online") return (null, $"{n.NodeId} está fuera de línea (última vez: {n.VistoUtc:HH:mm:ss} UTC).");
        return (n, "");
    }

    /// <summary>
    /// Certificado de un nodo de confianza: se descarga y se exige que su huella sea la FIJADA.
    /// (Con él se cierran los sobres CC-ENV-1 dirigidos a ese nodo.)
    /// </summary>
    public async Task<X509Certificate2> CertificadoConfiable(NodoConocido n, CancellationToken ct = default)
    {
        var pem = await cliente.Certificado(n.Direccion, ct)
            ?? throw new ErrorProtocolo("E-TIMEOUT", $"{n.NodeId} no entregó su certificado.");
        var cert = IdentidadNodo.LeerPem(pem);
        if (Huellas.HuellaCertificado(cert) != n.HuellaFijada)
        {
            cert.Dispose();
            throw new ErrorProtocolo("E-CERT-UNTRUSTED", $"El certificado actual de {n.NodeId} no coincide con la huella fijada.");
        }
        return cert;
    }

    /// <summary>
    /// Confianza del remitente de un paquete (13.1): fijado y coincide → Firma OK;
    /// no fijado → Remitente no confirmado; fijado y distinto → E-CERT-UNTRUSTED.
    /// </summary>
    public string ConfianzaDe(string nodeId, string huella)
    {
        if (nodeId == opciones.NodoId)
            return Huellas.IgualesConstante(yo.Huella, huella) ? Verificaciones.FirmaOk
                : throw new ErrorProtocolo("E-CERT-UNTRUSTED", $"El paquete dice venir de {nodeId} (este nodo) pero con otro certificado.");
        var n = repo.ObtenerNodo(nodeId);
        if (n?.HuellaFijada is null) return Verificaciones.NoConfirmado;
        if (!Huellas.IgualesConstante(n.HuellaFijada, huella))
            throw new ErrorProtocolo("E-CERT-UNTRUSTED", $"{nodeId} está fijado con otra huella en el directorio de {opciones.NodoId}.");
        return Verificaciones.FirmaOk;
    }
}
