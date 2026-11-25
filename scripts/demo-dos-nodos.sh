#!/usr/bin/env bash
# Demo local en Linux/macOS: dos nodos en la misma máquina (5000 y 5001).
# Uso desde la raíz del proyecto:  bash scripts/demo-dos-nodos.sh   (Ctrl+C detiene ambos)
set -e
cd "$(dirname "$0")/.."
dotnet build src/Nodo03.Web -c Release >/dev/null
dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Puerto=5000 --Nodo:NodoId=NODO-03  --Nodo:CarpetaDatos=datos-a &
A=$!
dotnet run --no-build -c Release --project src/Nodo03.Web -- --Nodo:Puerto=5001 --Nodo:NodoId=NODO-03B --Nodo:CarpetaDatos=datos-b &
B=$!
trap 'kill $A $B 2>/dev/null' INT TERM EXIT
echo "Nodo A: http://localhost:5000   Nodo B: http://localhost:5001"
wait
