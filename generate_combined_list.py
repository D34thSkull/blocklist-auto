#!/usr/bin/env python3
"""Consolida várias blocklists numa só lista para o AdGuard Home."""
import glob
import hashlib
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import islice

import requests

from blocklib import normalize_domain, parse_rule, parse_sources, suffixes

SOURCES_FILE = "sources.txt"
DOWNLOAD_DIR = "blocklists/downloaded"
CUSTOM_DIR = "blocklists/custom"
WHITELIST_DIR = "whitelists"
OUTPUT_FILE = "combined-blocklist.txt"
HOMEPAGE = "https://github.com/D34thSkull/blocklist-auto"


def cache_path(url):
    name = os.path.basename(url.split("?")[0]) or "list"
    return os.path.join(DOWNLOAD_DIR, f"{hashlib.sha1(url.encode()).hexdigest()[:8]}-{name}")


def download(url):
    """Devolve (url, caminho, estado) com estado 'ok', 'cache' (usou cópia antiga) ou 'falhou'."""
    dest = cache_path(url)
    for attempt in range(1, 4):
        try:
            r = requests.get(url, timeout=30, headers={"User-Agent": "blocklist-auto/2.0"})
            r.raise_for_status()
            with open(dest + ".tmp", "wb") as f:
                f.write(r.content)
            os.replace(dest + ".tmp", dest)  # escrita atómica: nunca deixa ficheiros a meio
            return url, dest, "ok"
        except requests.RequestException as e:
            print(f"  tentativa {attempt}/3 falhou ({url}): {e}")
            time.sleep(2 * attempt)
    return url, dest, "cache" if os.path.exists(dest) else "falhou"


def read_rules(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield from parse_rule(line)


def load_user_whitelist():
    domains = set()
    for path in glob.glob(os.path.join(WHITELIST_DIR, "*.txt")):
        with open(path, encoding="utf-8", errors="ignore") as f:
            domains |= {d for d in map(normalize_domain, f) if d}
    return domains


def covered_by(domain, pool):
    """True se o domínio ou qualquer domínio-pai estiver em 'pool'."""
    return any(s in pool for s in suffixes(domain))


def generate():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    # 1. Fontes ativas (as desativadas/removidas deixam de contar, mesmo que haja cache antiga)
    urls = []
    if os.path.exists(SOURCES_FILE):
        with open(SOURCES_FILE, encoding="utf-8") as f:
            urls = [s["url"] for s in parse_sources(f.read()) if s["enabled"]]
    urls = list(dict.fromkeys(urls))

    print(f"A descarregar {len(urls)} listas em paralelo...")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(download, urls))

    keep = {path for _, path, status in results if status != "falhou"}
    for old in glob.glob(os.path.join(DOWNLOAD_DIR, "*")):
        if old not in keep:
            os.remove(old)

    # 2. Ler regras
    blocked, upstream_allow = set(), set()
    files = [(u, p, s) for u, p, s in results if s != "falhou"]
    files += [(p, p, "custom") for p in glob.glob(os.path.join(CUSTOM_DIR, "*.txt"))]
    for url, path, status in files:
        n = 0
        for domain, kind in read_rules(path):
            if kind == "block":
                blocked.add(domain)
                n += 1
            else:
                upstream_allow.add(domain)
        note = " (cache antiga)" if status == "cache" else ""
        print(f"  {n:>8} regras  {url}{note}")
    for url, _, status in results:
        if status == "falhou":
            print(f"  AVISO: {url} falhou e não há cache, foi ignorada")

    if not blocked:
        print("Erro: nenhum domínio lido. A lista anterior foi mantida.")
        return 1

    # 3. Whitelist: remove o domínio e os seus subdomínios (igual ao @@||dominio^ do AdGuard)
    user_allow = load_user_whitelist()
    allow_all = user_allow | upstream_allow
    kept = {d for d in blocked if not covered_by(d, allow_all)}

    # 4. Remove subdomínios redundantes (ads.exemplo.com já é coberto por exemplo.com)
    final = {d for d in kept if not any(p in kept for p in islice(suffixes(d), 1, None))}

    # 5. Se o utilizador faz whitelist de um subdomínio cujo pai está bloqueado,
    #    emite uma exceção explícita para o AdGuard
    exceptions = sorted(w for w in user_allow
                        if any(p in final for p in islice(suffixes(w), 1, None)))

    # 6. Escrever (ficheiro temporário + replace)
    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("! Title: Combined AdGuard Home Blocklist\n")
        f.write(f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S GMT', time.gmtime())}\n")
        f.write("! Expires: 1 day\n")
        f.write(f"! Homepage: {HOMEPAGE}\n")
        f.write(f"! Domains: {len(final)}\n!\n")
        f.writelines(f"||{d}^\n" for d in sorted(final))
        f.writelines(f"@@||{d}^\n" for d in exceptions)
    os.replace(tmp, OUTPUT_FILE)

    print(f"\nBruto: {len(blocked)} | após whitelist: {len(kept)} | "
          f"após remover redundantes: {len(final)} | exceções: {len(exceptions)}")
    print(f"Gerado '{OUTPUT_FILE}'.")
    return 0


if __name__ == "__main__":
    sys.exit(generate())
