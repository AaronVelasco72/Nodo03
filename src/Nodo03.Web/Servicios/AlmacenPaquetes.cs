namespace Nodo03.Web.Servicios;

/// <summary>
/// Guarda los .zip en disco. Estructura:
/// <code>
/// datos/paquetes/recibidos/  zips que pasaron la validación
/// datos/paquetes/invalidos/  zips que fallaron hash, firma, certificado o tiempo (evidencia)
/// datos/paquetes/generados/  zips producidos por forward (propios o delegados)
/// datos/paquetes/resultados/ zips result devueltos por un inverse
/// datos/paquetes/enviados/   copias reempaquetadas (9.6) que se mandaron a otras bandejas
/// </code>
/// El nombre en disco lleva un prefijo único (<c>id__nombre.zip</c>) porque dos nodos
/// distintos podrían mandar zips con el mismo nombre.
/// </summary>
public sealed class AlmacenPaquetes
{
    private readonly string _raiz;

    public AlmacenPaquetes(OpcionesNodo opciones)
    {
        _raiz = Path.Combine(opciones.RutaDatos, "paquetes");
        foreach (var c in new[] { "recibidos", "invalidos", "generados", "resultados", "enviados" })
            Directory.CreateDirectory(Path.Combine(_raiz, c));
    }

    /// <summary>Guarda y devuelve la ruta. <paramref name="carpeta"/> = recibidos | invalidos | generados | resultados | enviados.</summary>
    public string Guardar(string carpeta, string id, string nombreZip, byte[] bytes)
    {
        var ruta = Path.Combine(_raiz, carpeta, $"{id}__{NombreSeguro(nombreZip)}");
        File.WriteAllBytes(ruta, bytes);
        return ruta;
    }

    public byte[] Leer(string ruta) => File.ReadAllBytes(ruta);

    public void Borrar(string ruta)
    {
        try { File.Delete(ruta); } catch (IOException) { /* si no se puede borrar no pasa nada */ }
    }

    /// <summary>
    /// El nombre del zip lo manda OTRO equipo: lo limpiamos para que no pueda contener
    /// rutas ("../") ni caracteres inválidos en Windows.
    /// </summary>
    public static string NombreSeguro(string nombre)
    {
        // No usamos Path.GetFileName: en Windows trata "a:" como unidad de disco y se come
        // parte del nombre ("a:b.zip" -> "b.zip"). Cortamos a mano en '/' y '\'.
        var soloNombre = nombre.Split('/', '\\').Last();
        var invalidos = Path.GetInvalidFileNameChars().Concat(['/', '\\', ':', '*', '?', '"', '<', '>', '|']).ToHashSet();
        var limpio = new string(soloNombre.Select(c => invalidos.Contains(c) ? '_' : c).ToArray());
        if (string.IsNullOrWhiteSpace(limpio) || limpio is "." or "..") limpio = "paquete.zip";
        return limpio.Length > 120 ? limpio[^120..] : limpio;
    }
}
