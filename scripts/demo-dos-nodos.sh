#!/usr/bin/env bash
# Demo local en Linux/macOS: EQ03 (5003, proveedor RSA/ECC) y EQ13 (5013, solo solicitante).
# Uso desde la raíz del proyecto:  bash scripts/demo-dos-nodos.sh   (Ctrl+C detiene ambos)
set -e
cd "$(dirname "$0")/.."
dotnet build src/Nodo03.Web -c Release >/dev/null
dotnet run --no-build -c Release --project src/Nodo03.Web &
A=$!
dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Equipo=13 --Nodo:CarpetaDatos=datos-eq13 &
B=$!
trap 'kill $A $B 2>/dev/null' INT TERM EXIT
echo "EQ03: http://localhost:5003   EQ13: http://localhost:5013"
wait
