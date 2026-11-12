#!/usr/bin/env bash
# Checkpoint 3: POST a /logout sin token CSRF, con y sin sesion
B=http://localhost:8080
echo '$ curl -i -X POST http://localhost:8080/logout          # sin sesion y sin token CSRF'
curl -s -i -X POST "$B/logout" | head -12
echo
echo '# Ahora con una sesion valida de laura (cookie JSESSIONID), pero sin token CSRF:'
curl -s -c /tmp/cookies.txt "$B/login" > /tmp/login.html
TOKEN=$(grep -o 'name="_csrf" value="[^"]*"' /tmp/login.html | head -1 | sed 's/.*value="//;s/"$//')
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -X POST "$B/login" \
    --data-urlencode "username=laura@universidad.edu" --data-urlencode "password=clave-laura-1" --data-urlencode "_csrf=$TOKEN" -o /dev/null
echo '$ curl -i -X POST http://localhost:8080/logout -b "JSESSIONID=..."'
curl -s -i -b /tmp/cookies.txt -X POST "$B/logout" | head -12
echo
echo '$ curl -i http://localhost:8080/dashboard -b "JSESSIONID=..."   # la sesion sigue viva'
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -b /tmp/cookies.txt "$B/dashboard"
