#!/usr/bin/env bash
# Mide y captura la evidencia del laboratorio en GitHub Actions. Deja todo en $SALIDA.
set -u
REPO=$PWD
SALIDA=${SALIDA:-$PWD/evid}
H=$REPO/.github/evidencias
W=$REPO/seguridad-web
TRABAJO=$(mktemp -d)
mkdir -p "$SALIDA/logs" "$SALIDA/capturas" "$SALIDA/surefire"
J17=$JAVA_HOME_17_X64
J23=$JAVA_HOME_23_X64
export DB_URL="jdbc:mysql://127.0.0.1:3306/seguridad_db?serverTimezone=UTC&allowPublicKeyRetrieval=true&useSSL=false"
export DB_USERNAME=appuser
export DB_PASSWORD=appuser123

correr() {
    local nombre=$1 dir=$2 jdk=$3; shift 3
    echo "### $nombre: mvn $*"
    (cd "$dir" && JAVA_HOME=$jdk PATH="$jdk/bin:$PATH" mvn -B -ntp "$@") > "$SALIDA/logs/$nombre.log" 2>&1
    echo $? > "$SALIDA/logs/$nombre.exit"
    if [ -d "$dir/target/surefire-reports" ]; then
        mkdir -p "$SALIDA/surefire/$nombre" && cp "$dir"/target/surefire-reports/*.xml "$SALIDA/surefire/$nombre/" 2>/dev/null
    fi
}
esperar_arranque() {
    for i in $(seq 1 90); do grep -q "Started SeguridadApplication" "$1" && return 0; sleep 2; done; return 1
}

{ echo "commit: $(git rev-parse HEAD)"; JAVA_HOME=$J17 mvn -v; echo; "$J23/bin/java" -version 2>&1; mysql --version; } > "$SALIDA/entorno.txt" 2>&1
git log --format='%h %s' > "$SALIDA/historial.txt"

# 1. Cada commit compila por si solo
for c in $(git rev-list --reverse HEAD); do
    if git cat-file -e "$c:seguridad-web/pom.xml" 2>/dev/null; then
        git worktree add -q --detach "$TRABAJO/c-$c" "$c"
        correr "compila-${c:0:7}" "$TRABAJO/c-$c/seguridad-web" "$J17" -DskipTests package
        echo "${c:0:7} $(git log -1 --format=%s "$c") -> exit $(cat "$SALIDA/logs/compila-${c:0:7}.exit")" >> "$SALIDA/compilacion-por-commit.txt"
    fi
done

# 2. Suite completa con JDK 17 y con JDK 23 (H2, sin MySQL)
correr pruebas-jdk17 "$W" "$J17" clean verify
correr pruebas-jdk23 "$W" "$J23" clean verify

# 3. Hash del ADMIN con el mismo PasswordEncoder de la aplicacion (Paso 8)
correr generar-hash "$W" "$J17" test -Dtest=GenerarHash
HASH=$(grep -o 'HASH_ADMIN=\$2a\$12\$[./A-Za-z0-9]*' "$SALIDA/logs/generar-hash.log" | head -1 | cut -d= -f2)
echo "hash generado: $HASH" > "$SALIDA/logs/hash-admin.txt"

# 4. La aplicacion real contra MySQL
correr empaquetar "$W" "$J17" -DskipTests clean package
cp "$W"/target/seguridad-0.0.1-SNAPSHOT.jar "$TRABAJO/app.jar"
"$J17/bin/java" -jar "$TRABAJO/app.jar" > "$SALIDA/logs/app.log" 2>&1 &
echo $! > "$TRABAJO/app.pid"
esperar_arranque "$SALIDA/logs/app.log" || echo "la app no arranco" >> "$SALIDA/logs/errores.txt"

MYSQL="mysql -h127.0.0.1 -uappuser -pappuser123 seguridad_db"
$MYSQL -e "INSERT INTO usuarios (nombre, email, contrasenia, rol, activo) VALUES ('Administrador', 'admin@universidad.edu', '$HASH', 'ROLE_ADMIN', 1);" \
    > "$SALIDA/logs/insert-admin.log" 2>&1

# 5. Variante TEMPORAL con th:utext activo (solo para la demostracion de XSS; no se versiona)
cp -r "$W" "$TRABAJO/variante-utext"
python3 "$H/activar-utext.py" "$TRABAJO/variante-utext/src/main/resources/templates/dashboard.html" > "$SALIDA/logs/variante-utext.txt"
correr empaquetar-utext "$TRABAJO/variante-utext" "$J17" -DskipTests clean package
"$J17/bin/java" -jar "$TRABAJO/variante-utext/target/seguridad-0.0.1-SNAPSHOT.jar" --server.port=8081 > "$SALIDA/logs/app-utext.log" 2>&1 &
echo $! > "$TRABAJO/app-utext.pid"
esperar_arranque "$SALIDA/logs/app-utext.log" || echo "la variante no arranco" >> "$SALIDA/logs/errores.txt"

# 6. Navegador real (Chromium con ventana, sobre Xvfb): todo el recorrido de la Parte 1 y la convivencia
(cd "$RUNNER_TEMP" && NODE_PATH="$RUNNER_TEMP/node_modules" xvfb-run -a -s "-screen 0 1366x900x24" \
    node "$H/navegar.js" "$SALIDA/capturas" "$H/api-flujo.sh") > "$SALIDA/logs/navegador.log" 2>&1

# 7. Terminal: CSRF, API JWT y los hashes en MySQL
bash "$H/csrf.sh" > "$SALIDA/logs/csrf.txt" 2>&1
bash "$H/api-flujo.sh" > "$SALIDA/logs/api-flujo.txt" 2>&1
$MYSQL -t -e "SELECT id, nombre, email, LEFT(contrasenia, 29) AS contrasenia_inicio, LENGTH(contrasenia) AS largo, rol FROM usuarios;" \
    > "$SALIDA/logs/mysql-usuarios.txt" 2>&1
$MYSQL -t -e "SELECT t.id, t.titulo, u.email AS propietario FROM tareas t JOIN usuarios u ON u.id = t.usuario_id;" \
    > "$SALIDA/logs/mysql-tareas.txt" 2>&1

kill "$(cat "$TRABAJO/app.pid")" "$(cat "$TRABAJO/app-utext.pid")" 2>/dev/null
for f in "$SALIDA"/logs/*.exit; do echo "$(basename "$f" .exit) -> $(cat "$f")"; done > "$SALIDA/resumen.txt"
cat "$SALIDA/resumen.txt" "$SALIDA/compilacion-por-commit.txt"
