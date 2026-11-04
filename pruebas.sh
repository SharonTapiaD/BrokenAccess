#!/bin/bash
# Uso: ./pruebas.sh            (contra http://127.0.0.1:5000)
URL=${1:-http://127.0.0.1:5000}
JAR=$(mktemp)

echo "== PRUEBA 1: Navegación forzada a /api/usuarios SIN login =="
curl -s -w "\n-> HTTP %{http_code}\n" "$URL/api/usuarios" | tail -n 5

echo
echo "== PRUEBA 2: Cookie manipulada (uid=2; role=admin) hacia /admin =="
curl -s -o /dev/null -w "-> HTTP %{http_code}\n" -H "Cookie: uid=2; role=admin" "$URL/admin"

echo
echo "== PRUEBA 3: IDOR - login como alice y pedir /perfil?id=1 (admin) =="
curl -s -c "$JAR" -o /dev/null -d "username=alice&password=alice123" "$URL/"
curl -s -b "$JAR" -w "\n-> HTTP %{http_code}\n" "$URL/perfil?id=1" | grep -E "Dato confidencial|HTTP"

echo
echo "Interpretación: HTTP 200 = VULNERABLE | HTTP 302/401/403 = PROTEGIDO"
rm -f "$JAR"
