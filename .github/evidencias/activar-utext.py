"""Saca la linea th:utext del comentario del dashboard (variante temporal para la prueba de XSS)."""
import sys
ruta = sys.argv[1]
html = open(ruta, encoding="utf-8").read()
linea = '<p th:utext="${usuario}"></p>'
inicio = html.index("<!-- INSEGURO")
html = html.replace("    " + linea + "\n", "", 1)
html = html[:inicio] + linea + "\n    " + html[inicio:]
open(ruta, "w", encoding="utf-8").write(html)
print("Linea activada en la variante temporal:", linea)
print(html[html.index("<h1>Dashboard</h1>"):html.index("<!-- INSEGURO")])
