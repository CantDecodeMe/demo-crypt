#!/usr/bin/env bash
# Agrega la ruta pública dh.maxthecoder.online al túnel de Cloudflare
# existente de la Pi (gestionado por token, sin tocar las reglas de los
# demás servicios que comparten el mismo túnel) y crea/actualiza el
# registro DNS CNAME correspondiente.
#
# Uso:  bash setup_cloudflare.sh
#
# Lee el token desde ~/.config/cloudflared/api.env. Nunca imprime el valor
# del token (ni con set -x, ni con curl -v).
set -euo pipefail

API_ENV_FILE="$HOME/.config/cloudflared/api.env"
ACCOUNT_ID="794115a35d2de0c9da2359c657139948"
TUNNEL_ID="77a689b7-3206-49d1-aaf4-b80086a3cacf"
DOMINIO_RAIZ="maxthecoder.online"
HOSTNAME_DH="dh.maxthecoder.online"
SERVICIO="http://dh-alice:5000"   # nombre del contenedor en la red Docker "services"

if [ ! -f "$API_ENV_FILE" ]; then
  echo "No se encontro $API_ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$API_ENV_FILE"
set +a

TOKEN="${CLOUDFLARE_API_TOKEN:-${CF_API_TOKEN:-${API_TOKEN:-}}}"
if [ -z "$TOKEN" ]; then
  echo "No encontre CLOUDFLARE_API_TOKEN / CF_API_TOKEN / API_TOKEN en $API_ENV_FILE." >&2
  exit 1
fi

AUTH_HEADER="Authorization: Bearer ${TOKEN}"
API="https://api.cloudflare.com/client/v4"

api_get()  { curl -sS -H "$AUTH_HEADER" "$@"; }
api_put()  { curl -sS -X PUT  -H "$AUTH_HEADER" -H "Content-Type: application/json" "$@"; }
api_post() { curl -sS -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" "$@"; }
api_patch(){ curl -sS -X PATCH -H "$AUTH_HEADER" -H "Content-Type: application/json" "$@"; }

echo "== 1) Leyendo configuracion actual del tunel =="
CURRENT=$(api_get "${API}/accounts/${ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations")
OK=$(echo "$CURRENT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('success'))")
if [ "$OK" != "True" ]; then
  echo "No se pudo leer la configuracion del tunel:" >&2
  echo "$CURRENT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('errors', d), indent=2))" >&2
  exit 1
fi

echo "Reglas actuales:"
echo "$CURRENT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['result']['config'].get('ingress', []) or []:
    print(' -', r.get('hostname', '(catch-all)'), r.get('path',''), '->', r.get('service'))
"

# Reconstruye el ingress: elimina reglas previas de este hostname y agrega
# la nueva ANTES del catch-all (siempre debe ir al final).
NEW_CONFIG=$(HOSTNAME="$HOSTNAME_DH" SERVICIO="$SERVICIO" echo "$CURRENT" | HOSTNAME="$HOSTNAME_DH" SERVICIO="$SERVICIO" python3 -c "
import json, sys, os
hostname = os.environ['HOSTNAME']
servicio = os.environ['SERVICIO']
data = json.load(sys.stdin)
ingress = data['result']['config'].get('ingress', []) or []

ingress = [r for r in ingress if r.get('hostname') != hostname]
catch_all = None
if ingress and 'hostname' not in ingress[-1]:
    catch_all = ingress.pop()

nueva = {'hostname': hostname, 'service': servicio, 'originRequest': {}}
ingress = ingress + [nueva] + ([catch_all] if catch_all else [{'service': 'http_status:404'}])

config = data['result']['config']
config['ingress'] = ingress
print(json.dumps({'config': config}))
")

echo ""
echo "== 2) Nueva configuracion propuesta =="
echo "$NEW_CONFIG" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['config'].get('ingress', []) or []:
    print(' -', r.get('hostname', '(catch-all)'), r.get('path',''), '->', r.get('service'))
"

read -r -p $'\n¿Aplicar esta configuracion al tunel? [s/N] ' CONFIRMA
if [ "$CONFIRMA" != "s" ] && [ "$CONFIRMA" != "S" ]; then
  echo "Cancelado, no se hizo ningun cambio."
  exit 0
fi

echo "== 3) Aplicando nueva configuracion del tunel =="
RESULT=$(api_put "${API}/accounts/${ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations" --data "$NEW_CONFIG")
echo "$RESULT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('success:', d.get('success'))
if not d.get('success'):
    print(json.dumps(d.get('errors', d), indent=2))
"

echo ""
echo "== 4) Buscando zona DNS de ${DOMINIO_RAIZ} =="
ZONE=$(api_get "${API}/zones?name=${DOMINIO_RAIZ}")
ZONE_ID=$(echo "$ZONE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
res = d.get('result') or []
print(res[0]['id'] if res else '')
")
if [ -z "$ZONE_ID" ]; then
  echo "No pude encontrar la zona ${DOMINIO_RAIZ} con este token." >&2
  echo "Falta crear manualmente el CNAME: ${HOSTNAME_DH} -> ${TUNNEL_ID}.cfargotunnel.com (proxied)." >&2
  exit 1
fi
echo "zone_id: $ZONE_ID"

echo ""
echo "== 5) Creando/actualizando el CNAME de ${HOSTNAME_DH} =="
EXISTING=$(api_get "${API}/zones/${ZONE_ID}/dns_records?name=${HOSTNAME_DH}&type=CNAME")
RECORD_ID=$(echo "$EXISTING" | python3 -c "
import json, sys
d = json.load(sys.stdin)
res = d.get('result') or []
print(res[0]['id'] if res else '')
")

DNS_BODY=$(HOSTNAME="$HOSTNAME_DH" TUNNEL_ID="$TUNNEL_ID" python3 -c "
import json, os
print(json.dumps({
    'type': 'CNAME',
    'name': os.environ['HOSTNAME'],
    'content': os.environ['TUNNEL_ID'] + '.cfargotunnel.com',
    'proxied': True,
    'ttl': 1,
}))
")

if [ -n "$RECORD_ID" ]; then
  echo "Ya existe un registro, actualizando..."
  DNS_RESULT=$(api_patch "${API}/zones/${ZONE_ID}/dns_records/${RECORD_ID}" --data "$DNS_BODY")
else
  echo "No existia, creando..."
  DNS_RESULT=$(api_post "${API}/zones/${ZONE_ID}/dns_records" --data "$DNS_BODY")
fi

echo "$DNS_RESULT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('success:', d.get('success'))
if not d.get('success'):
    print(json.dumps(d.get('errors', d), indent=2))
else:
    r = d['result']
    print('CNAME', r['name'], '->', r['content'], '(proxied)' if r.get('proxied') else '(DNS only)')
"

echo ""
echo "Listo. Prueba con: curl -sI https://${HOSTNAME_DH}/"
