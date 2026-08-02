"""Deja importar `kit.*` desde `tests/` sin instalar el paquete.

Cada modulo de `kit/` se usa suelto en produccion (se copia a otro repo), pero
para correr la suite ACA hace falta que la raiz del repo este en `sys.path`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
