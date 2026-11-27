# =====================================================================
#  Demo local en Windows: levanta DOS nodos en la misma computadora.
#    EQ03 -> http://localhost:5003   (proveedor de RSA y ECC)
#    EQ13 -> http://localhost:5013   (nodo de prueba: solo solicitante, delega RSA/ECC al EQ03)
#  Uso (desde la raíz del proyecto):  powershell -ExecutionPolicy Bypass -File scripts\demo-dos-nodos.ps1
#  Los dos se descubren solos por el anuncio UDP 5099 (si el firewall lo permite);
#  si no, en Nodos agrega 127.0.0.1:5003 / 127.0.0.1:5013 a mano y confirma las huellas.
# =====================================================================
$raiz = Split-Path -Parent $PSScriptRoot
dotnet build "$raiz\src\Nodo03.Web" -c Release | Out-Null

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$raiz'; dotnet run --no-build -c Release --project src/Nodo03.Web"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$raiz'; dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Equipo=13 --Nodo:CarpetaDatos=datos-eq13"

Start-Sleep -Seconds 6
Start-Process "http://localhost:5003"
Start-Process "http://localhost:5013"
Write-Host "Listo. En cada pestaña: Nodos > Confirmar huella. Luego en EQ13: Operar > RSA > mandar a la bandeja de EQ03."
