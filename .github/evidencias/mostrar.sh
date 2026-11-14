#!/usr/bin/env bash
# Lee un archivo de comandos y, como en una terminal, muestra cada comando y su salida real.
# Las lineas "# ..." se muestran como comentario y no se ejecutan.
# uso: mostrar.sh <archivo-de-comandos> <archivo-listo>
cmds=$1; listo=$2
while IFS= read -r linea || [ -n "$linea" ]; do
    case "$linea" in
        '') echo ;;
        '#'*) printf '\033[38;5;245m%s\033[0m\n' "$linea" ;;
        *) printf '\033[1;32m$\033[0m %s\n' "$linea"; eval "$linea" < /dev/null ;;
    esac
done < "$cmds"
touch "$listo"
sleep 600
