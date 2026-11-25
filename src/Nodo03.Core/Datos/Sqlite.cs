using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Nodo03.Core.Datos;

/// <summary>
/// Puente mínimo a la librería nativa de SQLite mediante P/Invoke.
/// </summary>
/// <remarks>
/// <para><b>¿Por qué no Entity Framework ni Microsoft.Data.Sqlite?</b> Ambos son paquetes NuGet.
/// Con este puente el proyecto compila y corre SIN internet, usando el SQLite que ya trae
/// el sistema operativo:</para>
/// <list type="bullet">
///   <item>Windows 10/11: <c>winsqlite3.dll</c> (viene en System32).</item>
///   <item>Linux: <c>libsqlite3.so.0</c> (paquete libsqlite3-0, preinstalado en Ubuntu).</item>
///   <item>macOS: <c>libsqlite3.dylib</c> (viene con el sistema).</item>
/// </list>
/// <para>Si el equipo prefiere Microsoft.Data.Sqlite, solo hay que reescribir
/// <see cref="BaseDatos"/>; el resto del sistema usa <see cref="RepositorioNodo"/> y no se entera.</para>
/// <para><b>Hilos:</b> cada conexión se abre con <c>SQLITE_OPEN_FULLMUTEX</c> (modo serializado) y
/// la base usa journal WAL, que permite lectores concurrentes mientras alguien escribe.</para>
/// </remarks>
internal static unsafe class Sqlite
{
    private const string Lib = "sqlite3";

    public const int SQLITE_OK = 0, SQLITE_ROW = 100, SQLITE_DONE = 101;
    public const int SQLITE_INTEGER = 1, SQLITE_FLOAT = 2, SQLITE_TEXT = 3, SQLITE_BLOB = 4, SQLITE_NULL = 5;
    public const int OPEN_READWRITE = 0x2, OPEN_CREATE = 0x4, OPEN_FULLMUTEX = 0x10000;

    /// <summary>SQLITE_TRANSIENT (-1): le dice a SQLite que copie el texto porque nuestro buffer se libera.</summary>
    private static readonly IntPtr Transitorio = new(-1);

    static Sqlite()
    {
        // Resolvemos el nombre real de la librería según el sistema operativo.
        NativeLibrary.SetDllImportResolver(typeof(Sqlite).Assembly, Resolver);
    }

    private static IntPtr Resolver(string nombre, Assembly asm, DllImportSearchPath? ruta)
    {
        if (nombre != Lib) return IntPtr.Zero;
        string[] candidatos = OperatingSystem.IsWindows()
            ? ["winsqlite3", "e_sqlite3", "sqlite3"]
            : OperatingSystem.IsMacOS()
                ? ["libsqlite3.dylib", "/usr/lib/libsqlite3.dylib", "libe_sqlite3"]
                : ["libsqlite3.so.0", "libsqlite3.so", "libe_sqlite3"];
        foreach (var c in candidatos)
            if (NativeLibrary.TryLoad(c, asm, ruta, out var h)) return h;
        throw new DllNotFoundException(
            "No se encontró SQLite en el sistema. En Linux instala 'libsqlite3-0'; en Windows debe existir winsqlite3.dll.");
    }

    // ----- Funciones nativas usadas (API C de SQLite, https://sqlite.org/c3ref/funclist.html) -----
    [DllImport(Lib)] public static extern int sqlite3_open_v2(byte[] archivo, out IntPtr db, int flags, IntPtr vfs);
    [DllImport(Lib)] public static extern int sqlite3_close_v2(IntPtr db);
    [DllImport(Lib)] public static extern int sqlite3_busy_timeout(IntPtr db, int ms);
    [DllImport(Lib)] public static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int bytes, out IntPtr stmt, IntPtr resto);
    [DllImport(Lib)] public static extern int sqlite3_step(IntPtr stmt);
    [DllImport(Lib)] public static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport(Lib)] public static extern int sqlite3_changes(IntPtr db);
    [DllImport(Lib)] public static extern IntPtr sqlite3_errmsg(IntPtr db);
    [DllImport(Lib)] public static extern int sqlite3_bind_text(IntPtr stmt, int i, byte[] valor, int bytes, IntPtr destructor);
    [DllImport(Lib)] public static extern int sqlite3_bind_int64(IntPtr stmt, int i, long valor);
    [DllImport(Lib)] public static extern int sqlite3_bind_double(IntPtr stmt, int i, double valor);
    [DllImport(Lib)] public static extern int sqlite3_bind_null(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern int sqlite3_column_count(IntPtr stmt);
    [DllImport(Lib)] public static extern IntPtr sqlite3_column_name(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern int sqlite3_column_type(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern long sqlite3_column_int64(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern double sqlite3_column_double(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern IntPtr sqlite3_column_text(IntPtr stmt, int i);
    [DllImport(Lib)] public static extern int sqlite3_column_bytes(IntPtr stmt, int i);

    /// <summary>Texto UTF-8 terminado en cero, como lo espera la API de C.</summary>
    public static byte[] Utf8z(string s) => Encoding.UTF8.GetBytes(s + "\0");

    public static string Error(IntPtr db) => Marshal.PtrToStringUTF8(sqlite3_errmsg(db)) ?? "error desconocido";

    /// <summary>Enlaza un parámetro .NET al marcador ?N de la sentencia.</summary>
    public static int Enlazar(IntPtr stmt, int indice, object? valor) => valor switch
    {
        null => sqlite3_bind_null(stmt, indice),
        string s => sqlite3_bind_text(stmt, indice, Encoding.UTF8.GetBytes(s), Encoding.UTF8.GetByteCount(s), Transitorio),
        bool b => sqlite3_bind_int64(stmt, indice, b ? 1 : 0),
        int n => sqlite3_bind_int64(stmt, indice, n),
        long n => sqlite3_bind_int64(stmt, indice, n),
        double d => sqlite3_bind_double(stmt, indice, d),
        DateTime d => Enlazar(stmt, indice, d.ToUniversalTime().ToString("O")),
        _ => Enlazar(stmt, indice, valor.ToString()),
    };

    /// <summary>Lee la columna i de la fila actual como objeto .NET.</summary>
    public static object? LeerColumna(IntPtr stmt, int i) => sqlite3_column_type(stmt, i) switch
    {
        SQLITE_NULL => null,
        SQLITE_INTEGER => sqlite3_column_int64(stmt, i),
        SQLITE_FLOAT => sqlite3_column_double(stmt, i),
        _ => Marshal.PtrToStringUTF8(sqlite3_column_text(stmt, i), sqlite3_column_bytes(stmt, i)),
    };
}

/// <summary>Excepción de base de datos con el mensaje de SQLite.</summary>
public sealed class ErrorBaseDatosException(string mensaje, int codigo) : Exception(mensaje)
{
    /// <summary>Código de error de SQLite (19 = violación de restricción, ej. UNIQUE).</summary>
    public int Codigo { get; } = codigo;
}

/// <summary>
/// Acceso sencillo y seguro a una base SQLite: siempre con parámetros (?1, ?2...) para
/// evitar inyección SQL, y una conexión por operación (seguro entre hilos).
/// </summary>
public sealed class BaseDatos
{
    private readonly byte[] _ruta;

    /// <summary>
    /// Candado de ESCRITURA de proceso. SQLite solo admite un escritor a la vez; en lugar
    /// de reintentar al recibir SQLITE_BUSY, serializamos las escrituras aquí. Las lecturas
    /// no toman el candado (WAL permite leer mientras se escribe).
    /// </summary>
    private readonly object _escritura = new();

    public string Ruta { get; }

    public BaseDatos(string ruta)
    {
        Ruta = ruta;
        _ruta = Sqlite.Utf8z(ruta);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(ruta))!);
        // WAL: mejor concurrencia lectura/escritura. Es persistente en el archivo.
        Ejecutar("PRAGMA journal_mode=WAL;");
    }

    private IntPtr Abrir()
    {
        var rc = Sqlite.sqlite3_open_v2(_ruta, out var db,
            Sqlite.OPEN_READWRITE | Sqlite.OPEN_CREATE | Sqlite.OPEN_FULLMUTEX, IntPtr.Zero);
        if (rc != Sqlite.SQLITE_OK)
        {
            var msg = db != IntPtr.Zero ? Sqlite.Error(db) : $"código {rc}";
            Sqlite.sqlite3_close_v2(db);
            throw new ErrorBaseDatosException($"No se pudo abrir la base: {msg}", rc);
        }
        Sqlite.sqlite3_busy_timeout(db, 10_000); // espera hasta 10 s si otro proceso tiene el candado
        return db;
    }

    /// <summary>Ejecuta INSERT/UPDATE/DELETE/DDL. Devuelve filas afectadas.</summary>
    public int Ejecutar(string sql, params object?[] parametros)
    {
        lock (_escritura)
        {
            var db = Abrir();
            try
            {
                Recorrer(db, sql, parametros, _ => { });
                return Sqlite.sqlite3_changes(db);
            }
            finally { Sqlite.sqlite3_close_v2(db); }
        }
    }

    /// <summary>
    /// Ejecuta <paramref name="cuerpo"/> dentro de una transacción (todo o nada).
    /// El cuerpo recibe una función <c>ejecutar(sql, parámetros) -> filas afectadas</c>.
    /// Si el cuerpo lanza una excepción se hace ROLLBACK.
    /// </summary>
    /// <example>
    /// <code>
    /// bool ok = db.Transaccion(ejecutar =>
    /// {
    ///     if (ejecutar("UPDATE t SET estado='X' WHERE id=?1 AND estado='P'", [id]) == 0) return false;
    ///     ejecutar("INSERT INTO otra ...", [...]);
    ///     return true;
    /// });
    /// </code>
    /// </example>
    public T Transaccion<T>(Func<Func<string, object?[], int>, T> cuerpo)
    {
        lock (_escritura)
        {
            var db = Abrir();
            try
            {
                Recorrer(db, "BEGIN IMMEDIATE;", [], _ => { });
                try
                {
                    var resultado = cuerpo((sql, ps) =>
                    {
                        Recorrer(db, sql, ps, _ => { });
                        return Sqlite.sqlite3_changes(db);
                    });
                    Recorrer(db, "COMMIT;", [], _ => { });
                    return resultado;
                }
                catch
                {
                    Recorrer(db, "ROLLBACK;", [], _ => { });
                    throw;
                }
            }
            finally { Sqlite.sqlite3_close_v2(db); }
        }
    }

    /// <summary>Ejecuta un SELECT y devuelve las filas como diccionarios columna -> valor.</summary>
    public List<Dictionary<string, object?>> Consultar(string sql, params object?[] parametros)
    {
        var filas = new List<Dictionary<string, object?>>();
        var db = Abrir();
        try
        {
            Recorrer(db, sql, parametros, stmt =>
            {
                var n = Sqlite.sqlite3_column_count(stmt);
                var fila = new Dictionary<string, object?>(n, StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < n; i++)
                    fila[Marshal.PtrToStringUTF8(Sqlite.sqlite3_column_name(stmt, i))!] = Sqlite.LeerColumna(stmt, i);
                filas.Add(fila);
            });
        }
        finally { Sqlite.sqlite3_close_v2(db); }
        return filas;
    }

    /// <summary>Primer valor de la primera fila (ej. COUNT(*)).</summary>
    public object? Escalar(string sql, params object?[] parametros) =>
        Consultar(sql, parametros).FirstOrDefault()?.Values.FirstOrDefault();

    private static void Recorrer(IntPtr db, string sql, object?[] parametros, Action<IntPtr> porFila)
    {
        var rc = Sqlite.sqlite3_prepare_v2(db, Sqlite.Utf8z(sql), -1, out var stmt, IntPtr.Zero);
        if (rc != Sqlite.SQLITE_OK) throw new ErrorBaseDatosException($"SQL inválido: {Sqlite.Error(db)}", rc);
        try
        {
            for (var i = 0; i < parametros.Length; i++) Sqlite.Enlazar(stmt, i + 1, parametros[i]);
            while (true)
            {
                rc = Sqlite.sqlite3_step(stmt);
                if (rc == Sqlite.SQLITE_ROW) { porFila(stmt); continue; }
                if (rc == Sqlite.SQLITE_DONE) break;
                throw new ErrorBaseDatosException(Sqlite.Error(db), rc);
            }
        }
        finally { Sqlite.sqlite3_finalize(stmt); }
    }
}
