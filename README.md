
# HackTheBox Write-ups

> Documentación técnica de máquinas resueltas en HackTheBox.  
> Cada write-up incluye reconocimiento, análisis de vulnerabilidades, explotación y escalada de privilegios.

**Autor:** Andres  
**Perfil HTB:** [yisus666
#CR] 


---


## Metodología General

```
Reconocimiento → Enumeración → Análisis → Explotación → PrivEsc → Post-Explotación
```

### Herramientas que uso regularmente

| Categoría | Herramientas |
|---|---|
| Reconocimiento | `nmap`, `masscan`, `rustscan` |
| Web | `gobuster`, `ffuf`, `nikto`, `burpsuite` |
| Explotación | `metasploit`, `searchsploit`, scripts custom |
| Post-Explotación | `linpeas`, `winpeas`, `bloodhound` |
| Scripting | `bash`, `python` |

---

## Estructura de Repositorio

```
htb-writeups/
├── README.md               ← Este archivo (índice general)
├── TEMPLATE.md             ← Plantilla para nuevos write-ups
├── WRITEUP-Abducted.md
├── WRITEUP-Cap.md
├── WRITEUP-FireFlow.md
```

---

## ⚠️ Disclaimer

> Todos los ataques documentados aquí fueron realizados en entornos **controlados y legales** de HackTheBox, exclusivamente con fines educativos. No apliques estas técnicas en sistemas sin autorización explícita.

---

*Última actualización: Junio 2026*
