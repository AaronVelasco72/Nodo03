using System.Text.Json;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;

namespace Nodo03.Web.Servicios;

/// <summary>Valores que el usuario cambia desde la pantalla "Ajustes" (se guardan en la base).</summary>
public sealed record ValoresAjustes
{
    /// <summary>Si es false, /api/status anuncia acceptingPackages=false y la bandeja responde 503 E-BUSY.</summary>
    public bool AceptandoPaquetes { get; init; } = true;

    /// <summary>
    /// Ping-pong automático: al llegar una pelota RSA/ECC cuya llave (keyId) es de este nodo, se
    /// acepta, se descifra (inverse), se vuelve a cifrar (forward) y se regresa sola al remitente.
    /// </summary>
    public bool RebotarAutomatico { get; init; }

    /// <summary>Máximo de rebotes por rally, para que dos nodos automáticos no jueguen para siempre.</summary>
    public int MaxRebotes { get; init; } = 6;

    /// <summary>Pausa entre recibir y regresar la pelota (ms), para que la demo se pueda seguir con la vista.</summary>
    public int PausaRebotesMs { get; init; } = 800;

    /// <summary>Algoritmos propios que este nodo atiende como Proveedor ("RSA", "ECC").</summary>
    public string[] AlgoritmosHabilitados { get; init; } = [Diccionario.Rsa, Diccionario.Ecc];

    /// <summary>Permitir administrar el nodo desde otra máquina de la LAN (ej. celular).</summary>
    public bool AdminRemoto { get; init; }
}

/// <summary>
/// Lee y guarda los ajustes. Se cachean en memoria y se reemplazan de forma atómica
/// (registro inmutable + referencia volátil): ningún hilo ve un ajuste "a medias".
/// </summary>
public sealed class AjustesNodo
{
    private const string Clave = "ajustes";
    private readonly RepositorioNodo _repo;
    private volatile ValoresAjustes _actual;

    public AjustesNodo(RepositorioNodo repo, OpcionesNodo opciones)
    {
        _repo = repo;
        var json = repo.LeerAjuste(Clave);
        _actual = json is null
            ? new ValoresAjustes { AdminRemoto = opciones.AdminRemoto }
            : JsonSerializer.Deserialize<ValoresAjustes>(json) ?? new ValoresAjustes();
    }

    public ValoresAjustes Actual => _actual;

    public ValoresAjustes Guardar(ValoresAjustes nuevos)
    {
        // Saneamos límites para que nadie configure 0 rebotes o pausas absurdas.
        nuevos = nuevos with
        {
            MaxRebotes = Math.Clamp(nuevos.MaxRebotes, 1, 50),
            PausaRebotesMs = Math.Clamp(nuevos.PausaRebotesMs, 0, 10_000),
            AlgoritmosHabilitados = nuevos.AlgoritmosHabilitados
                .Where(Diccionario.Implementados.Contains).Distinct().ToArray(),
        };
        _repo.GuardarAjuste(Clave, JsonSerializer.Serialize(nuevos));
        _actual = nuevos;
        return nuevos;
    }

    /// <summary>¿El usuario tiene habilitado este algoritmo propio?</summary>
    public bool Habilitado(string codigo) => _actual.AlgoritmosHabilitados.Contains(codigo);
}
