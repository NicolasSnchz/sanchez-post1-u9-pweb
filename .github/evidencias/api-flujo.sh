#!/usr/bin/env bash
# Parte 2, Paso 7: login JWT, peticion aceptada y rechazada
B=http://localhost:8080
corto() { echo "${1:0:40}...${1: -12}"; }
echo '$ curl -X POST /api/auth/login -d {"email":"admin@universidad.edu","contrasenia":"admin123"}'
R=$(curl -s -X POST "$B/api/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"admin@universidad.edu","contrasenia":"admin123"}' -w '\nHTTP %{http_code}')
echo "$R"
TOKEN=$(echo "$R" | head -1 | jq -r .token)
echo
echo '$ curl /api/tareas -H "Authorization: Bearer <token del admin>"'
curl -s "$B/api/tareas" -H "Authorization: Bearer $TOKEN" -w '\nHTTP %{http_code}\n'
echo
echo '$ curl /api/tareas                                   # sin token'
curl -s "$B/api/tareas" -w '\nHTTP %{http_code}\n'
echo
i=$(( ${#TOKEN} - 10 ))
C=${TOKEN:$i:1}; [ "$C" = A ] && N=B || N=A
ALTERADO="${TOKEN:0:$i}$N${TOKEN:$((i+1))}"
echo "\$ curl /api/tareas -H \"Authorization: Bearer <token con un caracter de la firma cambiado>\""
curl -s "$B/api/tareas" -H "Authorization: Bearer $ALTERADO" -w '\nHTTP %{http_code}\n'
echo
echo '$ curl -X POST /api/auth/login -d {"email":"admin@universidad.edu","contrasenia":"incorrecta"}'
curl -s -X POST "$B/api/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"admin@universidad.edu","contrasenia":"incorrecta"}' -w '\nHTTP %{http_code}\n'
echo
TL=$(curl -s -X POST "$B/api/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"laura@universidad.edu","contrasenia":"clave-laura-1"}' | jq -r .token)
echo '$ curl /api/tareas -H "Authorization: Bearer <token de laura, ROLE_USER>"'
curl -s "$B/api/tareas" -H "Authorization: Bearer $TL" -w '\nHTTP %{http_code}\n'
echo
echo '$ curl /api/admin/usuarios -H "Authorization: Bearer <token de laura, ROLE_USER>"'
curl -s "$B/api/admin/usuarios" -H "Authorization: Bearer $TL" -w '\nHTTP %{http_code}\n'
echo
echo '$ curl /api/admin/usuarios -H "Authorization: Bearer <token del admin>"'
curl -s "$B/api/admin/usuarios" -H "Authorization: Bearer $TOKEN" -w '\nHTTP %{http_code}\n'
echo
echo '$ curl -i /api/tareas -H "Authorization: Bearer <token del admin>"   # cabeceras: sin Set-Cookie'
curl -s -i "$B/api/tareas" -H "Authorization: Bearer $TOKEN" | grep -iE '^HTTP|^Set-Cookie|^Content-Type' || true
