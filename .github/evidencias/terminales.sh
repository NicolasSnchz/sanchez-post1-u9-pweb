#!/usr/bin/env bash
# Abre una xterm real por cada archivo de terminal/*.txt, espera a que termine y captura solo esa ventana.
# Se ejecuta dentro de xvfb-run, desde la raiz del repositorio.
# uso: terminales.sh <carpeta-capturas> <carpeta-temporal>
salida=$1; tmp=$2
H=$(cd "$(dirname "$0")" && pwd)
export MYSQL_PWD=appuser123
for cmds in "$H"/terminal/*.txt; do
    nombre=$(basename "$cmds" .txt)
    rm -f "$tmp/listo-$nombre"
    xterm -geometry 160x46+0+0 -fa 'DejaVu Sans Mono' -fs 9 -bg '#0d1117' -fg '#c9d1d9' -T "$nombre" \
        -e bash "$H/mostrar.sh" "$cmds" "$tmp/listo-$nombre" &
    pid=$!
    for i in $(seq 1 400); do [ -f "$tmp/listo-$nombre" ] && break; sleep 1; done
    sleep 2
    ventana=$(xwininfo -name "$nombre" | awk '/Window id:/{print $4}')
    import -window "$ventana" "$salida/$nombre.png" && echo "captura $nombre.png"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
done
