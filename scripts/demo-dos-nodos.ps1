# =====================================================================
#  Demo local en Windows: levanta DOS nodos en la misma computadora
#  (como si fueran dos células) para probar envío y ping-pong.
#    Nodo A -> http://localhost:5000   (NODO-03)
#    Nodo B -> http://localhost:5001   (NODO-03B)
#  Uso (desde la raíz del proyecto):  powershell -ExecutionPolicy Bypass -File scripts\demo-dos-nodos.ps1
# =====================================================================
$raiz = Split-Path -Parent $PSScriptRoot
dotnet build "$raiz\src\Nodo03.Web" -c Release | Out-Null

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$raiz'; dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Puerto=5000 --Nodo:NodoId=NODO-03 --Nodo:CarpetaDatos=datos-a"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$raiz'; dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Puerto=5001 --Nodo:NodoId=NODO-03B --Nodo:CarpetaDatos=datos-b"

Start-Sleep -Seconds 6
Start-Process "http://localhost:5000"
Start-Process "http://localhost:5001"
Write-Host "Listo. En el nodo A ve a Enviar y usa como destino 127.0.0.1:5001"
