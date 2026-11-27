// =====================================================================
//  Nodo EQ03 · Equipo 3 (RSA y ECC) · Virología y Criptografía (UPIICSA-IPN)
//  Estándar de Comunicación entre Nodos v2.0. Todo el armado está en NodoHost.Crear().
//
//  Ejecutar:            dotnet run --project src/Nodo03.Web            → http://localhost:5003
//  Segundo nodo local:  dotnet run --project src/Nodo03.Web -- --Nodo:Equipo=13 --Nodo:CarpetaDatos=datos-eq13
// =====================================================================
using Nodo03.Core.Protocolo;
using Nodo03.Web;
using Nodo03.Web.Servicios;

var app = NodoHost.Crear(args);

app.Lifetime.ApplicationStarted.Register(() =>
{
    var dir = app.Services.GetRequiredService<DireccionPropia>();
    var op = app.Services.GetRequiredService<OpcionesNodo>();
    var algoritmos = string.Join(", ", Diccionario.ProvistosPor(op.Equipo).Select(a => a.Codigo));
    Console.WriteLine();
    Console.WriteLine($"  ┌─ {op.NodoId} en línea · protocolo v{Identificadores.VersionProtocolo} ─────────────────");
    Console.WriteLine($"  │ Interfaz:   http://localhost:{dir.PuertoReal()}");
    Console.WriteLine($"  │ En la LAN:  http://{dir.Obtener()}");
    Console.WriteLine($"  │ Provee:     {(algoritmos.Length > 0 ? algoritmos : "ninguno (solo solicitante)")}");
    Console.WriteLine($"  │ Anuncio:    UDP {op.PuertoUdp} {(op.Descubrimiento ? "cada " + op.IntervaloAnuncioSegundos + " s" : "desactivado")}");
    Console.WriteLine($"  │ Datos:      {op.RutaDatos}");
    Console.WriteLine("  └──────────────────────────────────────────────────────────");
});

app.Run();

/// <summary>Clase parcial para que el proyecto de pruebas pueda referenciar el ensamblado.</summary>
public partial class Program;
