# sqli-hunter

**Leichtgewichtiger SQL-Injection-Scanner für autorisierte Penetrationstests**

Autor: [G4MEOVER18](https://github.com/G4MEOVER18) · Lizenz: MIT · Version: 1.0.0

---

> **Inspiriert von [sqlmap](https://github.com/sqlmapproject/sqlmap)**
> sqlmap ist das Goldstandard-Werkzeug für SQL-Injection-Automatisierung.
> sqli-hunter ist eine eigenständige, auf stdlib-Python basierende
> Neuimplementierung für Lernzwecke und leichtgewichtige Einsätze.
> Volle Anerkennung gilt dem sqlmapproject-Team und allen Mitwirkenden.

---

## Erkennungsmethoden

| Methode | Beschreibung | Risk-Level |
|---------|-------------|-----------|
| **Error-based** | Analysiert DBMS-Fehlermeldungen im Response-Body | 1 (immer) |
| **Boolean-blind** | Vergleicht Response-Länge bei TRUE- vs. FALSE-Payload | 1+ |
| **Time-based blind** | Misst Antwortzeit nach SLEEP/WAITFOR/pg_sleep-Injektion | 2–3 |
| **UNION-based (Dump)** | Extrahiert Datenbanknamen via UNION SELECT nach bestätigter Injektion | --dump |

## Unterstützte DBMS

| Datenbanksystem | Error-Erkennung | Time-based | DB-Enumeration |
|-----------------|-----------------|-----------|----------------|
| MySQL           | ✓ (12 Muster)   | ✓ SLEEP() | ✓ information_schema |
| MariaDB         | ✓ (9 Muster)    | ✓ SLEEP() | ✓ information_schema |
| MSSQL           | ✓ (13 Muster)   | ✓ WAITFOR DELAY | ✓ sysdatabases |
| PostgreSQL      | ✓ (12 Muster)   | ✓ pg_sleep() | ✓ pg_database |
| Oracle          | ✓ (12 Muster)   | ✓ DBMS_PIPE | ✓ all_tables |
| SQLite          | ✓ (12 Muster)   | ✓ randomblob | ✓ sqlite_master |
| DB2             | ✓ (9 Muster)    | —          | — |
| Sybase          | ✓ (9 Muster)    | —          | — |

## Voraussetzungen

- Python 3.8+ (keine externen Abhängigkeiten — nur stdlib)

## Installation

```bash
git clone https://github.com/G4MEOVER18/sqli-hunter.git
cd sqli-hunter
python sqli_hunter.py --help
```

## Verwendung

### Grundlegende GET-Parameter-Prüfung

```bash
python sqli_hunter.py -u "http://ziel.local/seite.php?id=1"
```

### POST-Formular testen

```bash
python sqli_hunter.py -u "http://ziel.local/login" \
    --data "username=admin&password=test" \
    --risk 2
```

### Mit Cookie-Injection und Dump

```bash
python sqli_hunter.py -u "http://ziel.local/profil.php?uid=5" \
    --cookies "session=abc123; role=user" \
    --risk 3 \
    --dump
```

### Header-Injection (User-Agent, Referer, X-Forwarded-For)

```bash
python sqli_hunter.py -u "http://ziel.local/" \
    --inject-headers \
    --risk 2
```

### Mit Tamper-Skripten (WAF-Bypass)

```bash
python sqli_hunter.py -u "http://ziel.local/page.php?id=1" \
    --tamper space2comment,randomcase
```

### Über Proxy (z. B. Burp Suite)

```bash
python sqli_hunter.py -u "http://ziel.local/page.php?id=1" \
    --proxy http://127.0.0.1:8080
```

### JSON-Export

```bash
python sqli_hunter.py -u "http://ziel.local/page.php?id=1" \
    --output ergebnisse.json
```

## Parameter-Referenz

| Parameter | Beschreibung | Standard |
|-----------|-------------|---------|
| `-u`, `--url` | Ziel-URL (erforderlich) | — |
| `-d`, `--data` | POST-Body (`key=val&key2=val2`) | — |
| `--cookies` | Cookie-Header-String | — |
| `--inject-headers` | Auch User-Agent/Referer/X-Forwarded-For testen | aus |
| `--risk` | 1=sicher, 2=medium (time-based), 3=schwer | 1 |
| `--dump` | Datenbankennamen extrahieren (nach bestätigter Injektion) | aus |
| `--tamper` | Kommagetrennte Tamper-Skripte | — |
| `--timeout` | HTTP-Timeout in Sekunden | 10 |
| `--proxy` | HTTP-Proxy (`http://host:port`) | — |
| `--user-agent` | Eigener User-Agent-Header | sqli-hunter/1.0.0 |
| `--output` | JSON-Ergebnisdatei | — |

## Verfügbare Tamper-Skripte

| Name | Beschreibung | Beispiel |
|------|-------------|---------|
| `space2comment` | Leerzeichen → `/**/` | `AND 1=1` → `AND/**/1=1` |
| `charencode` | Vollständige URL-Kodierung | `' OR 1` → `%27%20%4f%52%20%31` |
| `randomcase` | Zufällige Groß-/Kleinschreibung | `UNION` → `uNiOn` |
| `between` | `>` / `<` → `BETWEEN` | `>5` → `NOT BETWEEN 0 AND 5` |

## Exit-Codes

| Code | Bedeutung |
|------|-----------|
| `0` | Keine Injektion gefunden |
| `1` | Mindestens eine bestätigte Injektion |

## Payload-Wordlist

`wordlists/sqli_payloads.txt` enthält 50+ kategorisierte Payloads:
- Klassische Quote-Probes
- Error-based
- Boolean-blind
- UNION-based
- Time-based (MySQL, MSSQL, PostgreSQL, SQLite, Oracle)
- Stacked Queries
- WAF-Bypass-Varianten

## Projektstruktur

```
sqli-hunter/
├── sqli_hunter.py              # Hauptwerkzeug (~420 Zeilen, nur stdlib)
├── wordlists/
│   └── sqli_payloads.txt       # 50+ Payloads
├── README.md
├── LICENSE
└── .gitignore
```

---

## Credits

Dieses Projekt wurde stark von **[sqlmap](https://github.com/sqlmapproject/sqlmap)**
inspiriert — dem umfassendsten Open-Source-SQL-Injection-Tool.
Volle Anerkennung gilt Miroslav Stampar, Bernardo Damele A. G. und allen
Mitwirkenden des sqlmapproject.

---

## Rechtlicher Hinweis / Legal Notice

**ACHTUNG:** Dieses Werkzeug darf ausschließlich auf Systemen verwendet
werden, für die eine ausdrückliche schriftliche Genehmigung vorliegt.
Unautorisiertes Testen fremder Systeme ist in den meisten Ländern strafbar
(§ 202a StGB in Deutschland, CFAA in den USA).

Der Autor übernimmt keinerlei Haftung für Schäden, die durch den Missbrauch
dieses Werkzeugs entstehen.

**This tool must only be used against systems you own or have explicit written
authorization to test. Unauthorized use is illegal.**

---

## Spende / Donation

Falls dieses Projekt nützlich war — Bitcoin-Spenden sind willkommen:

**BTC:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
