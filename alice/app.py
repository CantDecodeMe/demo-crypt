"""
Alice — Primera instancia del canje de claves Diffie-Hellman (servicio público).

Esta aplicación corre en su propio proceso/contenedor, sin memoria compartida
con Bob. Es el punto de entrada público (dh.maxthecoder.online) y:

  1. Genera su clave privada a de forma autónoma (nunca sale de este proceso).
  2. Calcula A = g^a mod p  (clave pública).
  3. Envía por HTTP a Bob ÚNICAMENTE {p, g, A}  (los parámetros públicos).
  4. Recibe de Bob únicamente {B}.
  5. Calcula localmente S = B^a mod p  y  K = SHA-256(S).
  6. Imprime TODO en su consola (stdout → docker logs dh-alice).
  7. Sirve la página web con las dos consolas y el check K_Alice == K_Bob.

Grupo real: RFC 3526, MODP de 2048 bits (grupo 14), generador g = 2.

El único tráfico del PROTOCOLO DH entre Alice y Bob es:
    Alice → Bob : {p, g, A}
    Bob   → Alice: {B}

GET /estado de Bob es introspección de demo (no del protocolo) usada solo
para pintar la consola de Bob en la misma página y mostrar el check de K.
"""

import hashlib
import os
import secrets
import traceback
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Parámetros públicos: grupo MODP de 2048 bits del RFC 3526 (grupo 14).
# p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 * pi] + 124476 }
# g = 2
# Estos valores SON públicos: viajan por la red hacia Bob.
# ─────────────────────────────────────────────────────────────────────────────
P_RFC3526_2048 = int(
    """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""),
    16,
)
G_GENERADOR = 2

# Tamaño en bits del exponente privado (misma consideración que Bob).
BITS_EXPONENTE = 256

# URL interna de Bob en la red Docker "services" (configurable por env).
BOB_URL = os.environ.get("BOB_URL", "http://dh-bob:5000")

# Último canje de Alice (estado local de este proceso, no compartido).
_estado = {
    "lineas": [],
    "p": None,
    "g": None,
    "privada": None,
    "publica": None,
    "publica_bob": None,
    "S": None,
    "K": None,
    "timestamp": None,
}


def _log(linea: str) -> None:
    """Imprime una línea en la consola de Alice y la guarda para la UI."""
    print(f"[ALICE] {linea}", flush=True)
    _estado["lineas"].append(linea)


@app.route("/", methods=["GET"])
def indice():
    """Página principal: dos consolas (Alice/Bob) + botón de intercambio."""
    return render_template("index.html")


@app.route("/intercambiar", methods=["POST"])
def intercambiar():
    """
    Ejecuta el canje completo Diffie-Hellman Alice ↔ Bob sobre HTTP.

    Flujo del protocolo (lo único que cruza la red entre ambos):
        Alice → Bob : {p, g, A}
        Bob   → Alice: {B}

    Local, sin salir del proceso: a, S, K de Alice (y b, S, K de Bob).
    """
    global _estado
    try:
        p = P_RFC3526_2048
        g = G_GENERADOR

        _estado = {
            "lineas": [],
            "p": None,
            "g": None,
            "privada": None,
            "publica": None,
            "publica_bob": None,
            "S": None,
            "K": None,
            "timestamp": None,
        }

        _log("═" * 72)
        _log("INICIO DE CANJE DIFFIE-HELLMAN (lado Alice)")
        _log("[1] Parámetros públicos del grupo RFC 3526 (MODP 2048 bits):")
        _log(f"    p = 0x{p:x}  ({p.bit_length()} bits)")
        _log(f"    g = {g}")

        # ── Cálculo local autónomo de Alice (try/except explícito) ──────────
        try:
            # Clave privada local de Alice — NUNCA se transmite por la red.
            a = secrets.randbits(BITS_EXPONENTE) + 1
            _log("[2] Clave privada a generada localmente (secreta):")
            _log(f"    a = 0x{a:x}  ({a.bit_length()} bits)")

            # Clave pública de Alice: A = g^a mod p
            A = pow(g, a, p)
            _log("[3] Clave pública calculada: A = g^a mod p")
            _log(f"    A = 0x{A:x}")
        except Exception as e:
            _log(f"ERROR al generar claves de Alice: {e}")
            traceback.print_exc()
            return jsonify({"ok": False, "error": f"Fallo generando claves: {e}"}), 500

        # ── Transmisión de {p, g, A} a Bob (try/except explícito) ────────────
        _log("[4] ENVIANDO por la red a Bob: únicamente {p, g, A}")
        try:
            resp = requests.post(
                f"{BOB_URL}/canje",
                # p y A viajan como string: enteros de 2048 bits seguros en JSON.
                json={"p": str(p), "g": g, "A": str(A)},
                timeout=15,
            )
            resp.raise_for_status()
            datos = resp.json()
        except requests.exceptions.ConnectTimeout:
            _log("ERROR: Bob no responde (timeout de conexión).")
            return jsonify({"ok": False, "error": "Timeout conectando a Bob"}), 502
        except requests.exceptions.ConnectionError as e:
            _log(f"ERROR: no se pudo conectar a Bob en {BOB_URL}: {e}")
            return jsonify({"ok": False, "error": f"Sin conexión a Bob: {e}"}), 502
        except requests.exceptions.HTTPError as e:
            _log(f"ERROR: Bob devolvió HTTP error: {e}")
            return jsonify({"ok": False, "error": f"HTTP error de Bob: {e}"}), 502
        except Exception as e:
            _log(f"ERROR inesperado hablando con Bob: {e}")
            traceback.print_exc()
            return jsonify({"ok": False, "error": f"Error con Bob: {e}"}), 502

        if "B" not in datos:
            _log(f"ERROR: respuesta de Bob sin clave pública B: {datos}")
            return jsonify({"ok": False, "error": "Bob no devolvió B"}), 502

        try:
            B = int(datos["B"])
        except (TypeError, ValueError) as e:
            _log(f"ERROR: B recibida no es un entero válido: {e}")
            return jsonify({"ok": False, "error": f"B inválida: {e}"}), 502

        _log("[5] RECIBIDO de Bob por la red: únicamente {B}")
        _log(f"    B = 0x{B:x}")

        # ── Cálculo local del secreto y la llave (try/except explícito) ─────
        try:
            if not (1 < B < p):
                raise ValueError("B recibida fuera de rango (1 < B < p)")

            # Secreto compartido local de Alice: S = B^a mod p
            S = pow(B, a, p)
            _log("[6] Secreto compartido calculado en LOCAL: S = B^a mod p")
            _log(f"    S = 0x{S:x}")

            # Llave compartida: K = SHA-256(S) en hexadecimal
            K = hashlib.sha256(str(S).encode("utf-8")).hexdigest()
            _log("[7] Llave compartida K = SHA-256(S):")
            _log(f"    K = {K}")
        except Exception as e:
            _log(f"ERROR al calcular S/K: {e}")
            traceback.print_exc()
            return jsonify({"ok": False, "error": f"Fallo calculando S/K: {e}"}), 500

        # ── Introspección de DEMO: consola de Bob para pintar la UI ─────────
        # (NO es parte del protocolo DH; solo para mostrar K_Bob en pantalla.)
        bob_estado = None
        try:
            resp_estado = requests.get(f"{BOB_URL}/estado", timeout=5)
            resp_estado.raise_for_status()
            bob_estado = resp_estado.json()
        except Exception as e:
            _log(f"AVISO: no se pudo leer /estado de Bob ({e}).")
            _log("       La UI mostrará solo la consola de Alice.")

        # ── Validación K_Alice == K_Bob ─────────────────────────────────────
        K_bob = (bob_estado or {}).get("K")
        if K_bob is None:
            match = None  # no se pudo comparar
            _log("[8] VALIDACIÓN: K_Bob no disponible (solo consola local).")
        elif K_bob == K:
            match = True
            _log("[8] VALIDACIÓN: ✓ K_Alice == K_Bob  ¡CANJE EXITOSO!")
        else:
            match = False
            _log("[8] VALIDACIÓN: ✗ K_Alice != K_Bob  ¡FALLO EN EL CANJE!")

        _log(f"FIN — {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
        _log("")

        _estado.update(
            {
                "p": hex(p),
                "g": g,
                "privada": hex(a),
                "publica": hex(A),
                "publica_bob": hex(B),
                "S": hex(S),
                "K": K,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )

        return jsonify(
            {
                "ok": True,
                "match": match,
                "alice": _estado,
                "bob": bob_estado,
            }
        )

    except Exception as e:
        _log(f"ERROR inesperado en /intercambiar: {e}")
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"Error interno en Alice: {e}"}), 500


@app.route("/estado", methods=["GET"])
def estado():
    """Estado local del último canje de Alice (para la UI / depuración)."""
    try:
        return jsonify(_estado)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Healthcheck simple para Docker."""
    return jsonify({"ok": True, "servicio": "alice"}), 200


if __name__ == "__main__":
    print(
        f"[ALICE] Servicio Diffie-Hellman iniciado en 0.0.0.0:5000 → Bob en {BOB_URL}",
        flush=True,
    )
    # host 0.0.0.0 para ser alcanzable desde el túnel de Cloudflare.
    app.run(host="0.0.0.0", port=5000)
