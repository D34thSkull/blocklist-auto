"""Interface web para gerir sources.txt e a whitelist pessoal.
Variáveis de ambiente: GITHUB_TOKEN, ADMIN_PASSWORD (obrigatórias),
ADMIN_USER, REPO_OWNER, REPO_NAME, BRANCH, WORKFLOW_FILE (opcionais)."""
import base64
import hmac
import os
import re
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

from blocklib import (edit_sources, format_whitelist, normalize_domain,
                      parse_sources, parse_whitelist)

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
REPO_OWNER = os.getenv("REPO_OWNER", "D34thSkull")
REPO_NAME = os.getenv("REPO_NAME", "blocklist-auto")
BRANCH = os.getenv("BRANCH", "main")
WORKFLOW_FILE = os.getenv("WORKFLOW_FILE")  # ex: "update.yml" (opcional)
SOURCES_PATH = "sources.txt"
WHITELIST_PATH = "whitelists/personal-whitelist.txt"

API = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}",
           "Accept": "application/vnd.github+json"}


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify(ok=False, message=str(e)), e.status


@app.errorhandler(requests.HTTPError)
def _gh_error(e):
    code = e.response.status_code
    return jsonify(ok=False, message=f"Erro da API do GitHub ({code})."), 502


def require_auth(f):
    """Autenticação HTTP Basic. Sem isto qualquer pessoa podia mexer nas listas."""
    @wraps(f)
    def wrapper(*a, **kw):
        if not ADMIN_PASSWORD or not GITHUB_TOKEN:
            return jsonify(ok=False, message="Servidor sem ADMIN_PASSWORD/GITHUB_TOKEN."), 503
        auth = request.authorization
        ok = (auth and auth.username is not None and auth.password is not None
              and hmac.compare_digest(auth.username, ADMIN_USER)
              and hmac.compare_digest(auth.password, ADMIN_PASSWORD))
        if not ok:
            return ("Autenticação necessária", 401,
                    {"WWW-Authenticate": 'Basic realm="Blocklist"'})
        return f(*a, **kw)
    return wrapper


# ---------- GitHub ----------
def gh_read(path):
    r = requests.get(f"{API}/contents/{path}", headers=HEADERS,
                     params={"ref": BRANCH}, timeout=15)
    if r.status_code == 404:
        return "", None
    r.raise_for_status()
    j = r.json()
    return base64.b64decode(j["content"]).decode("utf-8"), j["sha"]


def gh_modify(path, transform, message):
    """Lê, aplica transform(texto) e grava. Repete se houver conflito de versão."""
    for _ in range(3):
        text, sha = gh_read(path)
        new = transform(text)
        if new == text:
            return False
        payload = {"message": message, "branch": BRANCH,
                   "content": base64.b64encode(new.encode()).decode()}
        if sha:
            payload["sha"] = sha
        r = requests.put(f"{API}/contents/{path}", headers=HEADERS, json=payload, timeout=15)
        if r.status_code in (409, 422):
            continue
        r.raise_for_status()
        return True
    raise ApiError("Conflito ao gravar no GitHub, tenta outra vez.", 409)


def valid_source_url(raw):
    u = (raw or "").strip()
    p = urlparse(u)
    if len(u) > 500 or re.search(r"\s", u) or p.scheme != "https" or not p.hostname:
        raise ApiError("O URL tem de ser https:// e não pode ter espaços.")
    return u


# ---------- rotas ----------
@app.route("/")
@require_auth
def index():
    return render_template("index.html")


@app.get("/api/state")
@require_auth
def state():
    sources = parse_sources(gh_read(SOURCES_PATH)[0])
    whitelist = sorted(parse_whitelist(gh_read(WHITELIST_PATH)[0]))
    return jsonify(ok=True, sources=sources, whitelist=whitelist,
                   can_rebuild=bool(WORKFLOW_FILE))


@app.post("/api/sources")
@require_auth
def add_source():
    d = request.get_json(silent=True) or {}
    url, note = valid_source_url(d.get("url")), (d.get("note") or "").strip()[:100]
    changed = gh_modify(SOURCES_PATH, lambda t: edit_sources(t, "add", url, note=note),
                        f"Add source {urlparse(url).path.rsplit('/', 1)[-1]} via web UI")
    return jsonify(ok=True, message="Lista adicionada." if changed else "A lista já estava ativa.")


@app.patch("/api/sources")
@require_auth
def toggle_source():
    d = request.get_json(silent=True) or {}
    url, enabled = valid_source_url(d.get("url")), bool(d.get("enabled"))
    gh_modify(SOURCES_PATH, lambda t: edit_sources(t, "set", url, enabled=enabled),
              f"{'Enable' if enabled else 'Disable'} source via web UI")
    return jsonify(ok=True, message="Lista ativada." if enabled else "Lista desativada.")


@app.delete("/api/sources")
@require_auth
def remove_source():
    url = valid_source_url((request.get_json(silent=True) or {}).get("url"))
    gh_modify(SOURCES_PATH, lambda t: edit_sources(t, "remove", url),
              "Remove source via web UI")
    return jsonify(ok=True, message="Lista removida.")


@app.post("/api/whitelist")
@require_auth
def add_whitelist():
    raw = (request.get_json(silent=True) or {}).get("domain") or ""
    items = [x for x in re.split(r"[\s,;]+", raw) if x]
    good = {d for d in map(normalize_domain, items) if d}
    bad = [x for x in items if not normalize_domain(x)]
    if not good:
        raise ApiError("Nenhum domínio válido encontrado.")
    gh_modify(WHITELIST_PATH, lambda t: format_whitelist(parse_whitelist(t) | good),
              f"Add {len(good)} domain(s) to whitelist via web UI")
    msg = f"{len(good)} domínio(s) na whitelist."
    if bad:
        msg += f" Ignorados: {', '.join(bad[:5])}"
    return jsonify(ok=True, message=msg)


@app.delete("/api/whitelist")
@require_auth
def remove_whitelist():
    domain = normalize_domain((request.get_json(silent=True) or {}).get("domain"))
    if not domain:
        raise ApiError("Domínio inválido.")
    gh_modify(WHITELIST_PATH, lambda t: format_whitelist(parse_whitelist(t) - {domain}),
              f"Remove {domain} from whitelist via web UI")
    return jsonify(ok=True, message=f"{domain} removido da whitelist.")


@app.post("/api/rebuild")
@require_auth
def rebuild():
    if not WORKFLOW_FILE:
        raise ApiError("WORKFLOW_FILE não está configurado.", 400)
    r = requests.post(f"{API}/actions/workflows/{WORKFLOW_FILE}/dispatches",
                      headers=HEADERS, json={"ref": BRANCH}, timeout=15)
    r.raise_for_status()
    return jsonify(ok=True, message="Atualização iniciada. Demora cerca de um minuto.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
