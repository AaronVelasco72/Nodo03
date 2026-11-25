// =====================================================================
//  Nodo 03 · Equipo 3 · Virología y Criptografía (UPIICSA-IPN)
//  Punto de entrada. Todo el armado está en NodoHost.Crear().
//
//  Ejecutar:            dotnet run --project src/Nodo03.Web
//  Segundo nodo local:  dotnet run --project src/Nodo03.Web -- --Nodo:Puerto=5001 --Nodo:NodoId=NODO-03B --Nodo:CarpetaDatos=datos-b
// =====================================================================
using Nodo03.Web;

var app = NodoHost.Crear(args);

app.Lifetime.ApplicationStarted.Register(() =>
{
    var dir = app.Services.GetRequiredService<DireccionPropia>();
    var op = app.Services.GetRequiredService<OpcionesNodo>();
    Console.WriteLine();
    Console.WriteLine($"  ┌─ {op.NodoId} en línea ─────────────────────────────");
    Console.WriteLine($"  │ Interfaz:  http://localhost:{dir.PuertoReal()}");
    Console.WriteLine($"  │ En la LAN: http://{dir.Obtener()}   (dale esta dirección a los demás equipos)");
    Console.WriteLine($"  │ Datos:     {op.RutaDatos}");
    Console.WriteLine("  └──────────────────────────────────────────────────");
});

app.Run();

/// <summary>Clase parcial para que el proyecto de pruebas pueda referenciar el ensamblado.</summary>
public partial class Program;
