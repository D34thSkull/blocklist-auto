"""Funções partilhadas entre o gerador da lista (generate_combined_list.py)
e a interface web (app.py), para que ambos interpretem as regras da mesma forma."""
import re
import time
from urllib.parse import urlparse

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
LOCAL_HOSTS = {"localhost.localdomain", "broadcasthost"}
SRC_RE = re.compile(r"^(#\s*)?(https?://\S+)\s*(?:#\s*(.*))?$")


def valid_domain(d):
    return (bool(d) and len(d) <= 253 and bool(DOMAIN_RE.match(d))
            and not IPV4_RE.match(d) and not d.rsplit(".", 1)[1].isdigit())


def suffixes(d):
    """'a.b.example.com' -> a.b.example.com, b.example.com, example.com"""
    p = d.split(".")
    for i in range(len(p) - 1):
        yield ".".join(p[i:])


def parse_rule(line):
    """Lê uma linha de uma blocklist e devolve [(dominio, 'block'|'allow'), ...].
    Suporta: ||dominio^, @@||dominio^, formato hosts (vários nomes por linha)
    e domínios simples. Regras com modificadores ($third-party, etc.) são ignoradas."""
    s = line.strip().lower()
    if not s or s[0] in "#![":
        return []
    s = re.split(r"\s+#", s, maxsplit=1)[0].strip()
    allow = s.startswith("@@")
    if allow:
        s = s[2:]
    if s.startswith("||"):
        body, _, mods = s[2:].partition("$")
        if (mods and mods != "important") or not body.endswith("^"):
            return []
        d = body[:-1]
        return [(d, "allow" if allow else "block")] if valid_domain(d) else []
    if allow:
        return []
    parts = s.split()
    if len(parts) >= 2 and parts[0] in HOSTS_IPS:
        return [(h, "block") for h in parts[1:]
                if valid_domain(h) and h not in LOCAL_HOSTS]
    if len(parts) == 1 and valid_domain(parts[0]):
        return [(parts[0], "block")]
    return []


def normalize_domain(raw):
    """Normaliza o que o utilizador escreve (URL, ||x^, hosts, x.com/path) para 'x.com'."""
    s = (raw or "").strip().lower()
    if not s:
        return None
    if "://" in s:
        s = urlparse(s).hostname or ""
    else:
        rules = parse_rule(s)
        if rules:
            s = rules[0][0]
        else:
            s = s.split("/")[0].split("?")[0]
            if s.count(":") == 1:
                s = s.split(":")[0]
    s = s.lstrip("*.").rstrip(".")
    if s.startswith("www."):
        s = s[4:]
    return s if valid_domain(s) else None


# ---------- whitelist ----------
def parse_whitelist(text):
    return {d for d in map(normalize_domain, text.splitlines()) if d}


def format_whitelist(domains):
    head = ["! Personal Whitelist (Cleaned, Homogenized, and Sorted)",
            f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S GMT', time.gmtime())}",
            ""]
    return "\n".join(head + sorted(domains)) + "\n"


# ---------- sources.txt ----------
def parse_sources(text):
    """[{'url', 'enabled', 'note'}]. Linhas '#https://...' contam como listas desativadas."""
    items = []
    for line in text.splitlines():
        m = SRC_RE.match(line.strip())
        if m:
            items.append({"url": m.group(2), "enabled": not m.group(1),
                          "note": (m.group(3) or "").strip()})
    return items


def _fmt_source(url, enabled, note):
    return f"{'' if enabled else '#'}{url}" + (f"  # {note}" if note else "")


def edit_sources(text, op, url, note="", enabled=True):
    """op: 'add' (adiciona ou reativa), 'remove', 'set' (ativa/desativa).
    Preserva todos os outros comentários do ficheiro."""
    out, found = [], False
    for line in text.splitlines():
        m = SRC_RE.match(line.strip())
        if m and m.group(2) == url:
            found = True
            if op == "remove":
                continue
            keep_note = note or (m.group(3) or "").strip()
            line = _fmt_source(url, True if op == "add" else enabled, keep_note)
        out.append(line)
    if not found and op == "add":
        out.append(_fmt_source(url, True, note))
    return "\n".join(out) + "\n"
