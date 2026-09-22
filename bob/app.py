"""
Bob — Segunda instancia del canje de claves Diffie-Hellman (servicio interno).

Esta aplicación corre en su propio proceso/contenedor, sin memoria compartida
con Alice. Su único deber de red es:

  POST /canje  ← recibe {p, g, A}   (parámetros públicos + clave pública de Alice)
  POST /canje  → devuelve  {B}      (únicamente SU clave pública)

En privado (nunca sale de este proceso por el protocolo):
  1. Genera su clave privada b de forma autónoma.
  2. Calcula B = g^b mod p  (clave pública).
  3. Calcula el secreto compartido S = A^b mod p.
  4. Aplica hash SHA-256 a S para obtener la llave compartida K.
  5. Imprime TODO en su consola (stdout → docker logs dh-bob).

Endpoint GET /estado es SOLO introspección de demostración para que la
página web pueda pintar la consola de Bob y el check K_Alice == K_Bob.
NO forma parte del protocolo DH: en un sistema real jamás se expondría K.
"""

import hashlib
import secrets
import traceback
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

# Tamaño en bits del exponente privado. El RFC 3526 recomienda al menos
# el doble de la fortaleza del grupo (≈110-160 bits → 220-320 bits).
BITS_EXPONENTE = 256

# Último canje realizado por Bob (estado local de este proceso, no compartido).
_estado = {
    "lineas": [],
    "p": None,
    "g": None,
    "privada": None,
    "publica": None,
    "S": None,
    "K": None,
    "timestamp": None,
}


def _log(linea: str) -> None:
    """Imprime una línea en la consola de Bob y la guarda para /estado."""
    print(f"[BOB] {linea}", flush=True)
    _estado["lineas"].append(linea)


def _a_entero(valor, nombre: str) -> int:
    """
    Convierte un valor JSON a entero.

    Acepta int directo o cadena decimal (los enteros de 2048 bits se
    transmiten como string para no perder precisión en el JSON).
    """
    if isinstance(valor, bool):
        raise ValueError(f"{nombre} debe ser un entero, no un booleano")
    if isinstance(valor, int):
        return valor
    if isinstance(valor, str):
        try:
            return int(valor, 0)  # acepta decimal ("123") y hex ("0x...")
        except ValueError:
            raise ValueError(f"{nombre} no es una cadena numérica válida") from None
    raise ValueError(f"{nombre} debe ser un entero o cadena numérica")


def _validar_entrada(p, g, A):
    """Valida que los valores recibidos de Alice sean enteros y tengan sentido."""
    if p <= 2:
        raise ValueError("p debe ser un primo mayor que 2")
    if not (1 < g < p):
        raise ValueError("g debe cumplir 1 < g < p")
    if not (1 < A < p):
        raise ValueError("A debe cumplir 1 < A < p")


@app.route("/canje", methods=["POST"])
def canje():
    """
    Recibe {p, g, A} de Alice y responde únicamente {B}.

    Este es el ÚNICO mensaje del protocolo que Bob emite.
    """
    global _estado
    try:
        datos = request.get_json(silent=True)
        if not datos:
            return jsonify({"error": "Se esperaba un cuerpo JSON con p, g y A"}), 400

        # Estado nuevo para este canje (se limpia al inicio del request)
        _estado = {
            "lineas": [],
            "p": None,
            "g": None,
            "privada": None,
            "publica": None,
            "S": None,
            "K": None,
            "timestamp": None,
        }

        # --- Validación de parámetros entrantes (try-except explícito) ---
        try:
            p = _a_entero(datos.get("p"), "p")
            g = _a_entero(datos.get("g"), "g")
            A = _a_entero(datos.get("A"), "A")
            _validar_entrada(p, g, A)
        except (ValueError, TypeError) as e:
            _log(f"ERROR de validación: {e}")
            return jsonify({"error": str(e)}), 400

        _log("─" * 72)
        _log("INICIO DE CANJE DIFFIE-HELLMAN (lado Bob)")
        _log(f"[1] Parámetros públicos recibidos de Alice")
        _log(f"    p = 0x{p:x}  ({p.bit_length()} bits)")
        _log(f"    g = {g}")

        try:
            # --- 1) Clave privada local de Bob (nunca se transmite) ---
            b = secrets.randbits(BITS_EXPONENTE) + 1
            _log(f"[2] Clave privada b generada localmente (secreta):")
            _log(f"    b = 0x{b:x}  ({b.bit_length()} bits)")

            # --- 2) Clave pública de Bob: B = g^b mod p ---
            B = pow(g, b, p)
            _log(f"[3] Clave pública calculada: B = g^b mod p")
            _log(f"    B = 0x{B:x}")

            # --- 3) Secreto compartido local: S = A^b mod p ---
            S = pow(A, b, p)
            _log(f"[4] Secreto compartido calculado en LOCAL: S = A^b mod p")
            _log(f"    S = 0x{S:x}")

            # --- 4) Llave compartida K = SHA-256(S) en hexadecimal ---
            K = hashlib.sha256(str(S).encode("utf-8")).hexdigest()
            _log(f"[5] Llave compartida K = SHA-256(S):")
            _log(f"    K = {K}")

            _log("[6] VALIDACIÓN local: K de Bob calculada correctamente.")
            _log("    (La igualdad K_Alice == K_Bob se comprueba en la página web)")
            _log(f"FIN — {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
            _log("")

            # Guardar estado para la introspección de la UI (/estado)
            _estado.update(
                {
                    "p": hex(p),
                    "g": g,
                    "privada": hex(b),
                    "publica": hex(B),
                    "S": hex(S),
                    "K": K,
                    "timestamp": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                }
            )

            # ÚNICA RESPUESTA DEL PROTOCOLO: la clave pública B.
            return jsonify({"B": str(B)})

        except Exception as e:
            _log(f"ERROR durante el cálculo DH: {e}")
            traceback.print_exc()
            return jsonify({"error": f"Fallo en el cálculo DH: {e}"}), 500

    except Exception as e:
        _log(f"ERROR inesperado en /canje: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Error interno en Bob: {e}"}), 500


@app.route("/estado", methods=["GET"])
def estado():
    """
    INTROSPECCIÓN DE DEMO — no forma parte del protocolo Diffie-Hellman.

    Devuelve el estado local del último canje de Bob para que la página
    de Alice pueda mostrar la consola de Bob y comprobar K_Alice == K_Bob
    en la misma pantalla. En producción este endpoint no existiría.
    """
    try:
        return jsonify(_estado)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Healthcheck simple para Docker."""
    return jsonify({"ok": True, "servicio": "bob"}), 200


if __name__ == "__main__":
    print("[BOB] Servicio Diffie-Hellman iniciado en 0.0.0.0:5000", flush=True)
    # host 0.0.0.0 para ser alcanzable por Alice a través de la red Docker.
    app.run(host="0.0.0.0", port=5000)
