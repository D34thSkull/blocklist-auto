import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import glob
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Sessão HTTP partilhada com retries automáticos (backoff exponencial)
# ---------------------------------------------------------------------------
def build_session():
    session = requests.Session()
    retries = Retry(
        total=3,                      # até 3 tentativas extra por fonte
        backoff_factor=1,             # 1s, 2s, 4s...
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retries, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = build_session()
MAX_CONTENT_BYTES = 50 * 1024 * 1024  # 50MB - limite de segurança por ficheiro


def download_file(url, destination_path):
    """Descarrega um ficheiro de uma URL para um caminho de destino.

    Inclui retries automáticos (via SESSION), verificação básica de
    Content-Type e limite de tamanho para evitar ficheiros maliciosos
    ou respostas de erro disfarçadas de sucesso (ex: páginas HTML 404).
    """
    try:
        print(f"A descarregar: {url} para {destination_path}")
        response = SESSION.get(url, stream=True, timeout=15)
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            print(f"Aviso: {url} devolveu Content-Type HTML — a ignorar (provável página de erro).")
            return False

        total = 0
        with open(destination_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > MAX_CONTENT_BYTES:
                    print(f"Erro: {url} excedeu o limite de tamanho ({MAX_CONTENT_BYTES} bytes) — a abortar.")
                    f.close()
                    os.remove(destination_path)
                    return False
                f.write(chunk)

        if total == 0:
            print(f"Aviso: {url} devolveu ficheiro vazio.")
            os.remove(destination_path)
            return False

        print(f"Descarregado com sucesso: {url} ({total} bytes)")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Erro ao descarregar {url}: {e}")
        return False


def download_all(urls, destination_dir, max_workers=8):
    """Descarrega várias URLs em paralelo e devolve estatísticas."""
    results = {}

    def _task(url):
        filename = os.path.basename(url.split("?")[0])
        if not filename.endswith(".txt"):
            filename += ".txt"
        destination_path = os.path.join(destination_dir, filename)
        ok = download_file(url, destination_path)
        return url, ok

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_task, url): url for url in urls}
        for future in as_completed(futures):
            url, ok = future.result()
            results[url] = ok

    return results


# ---------------------------------------------------------------------------
# Parsing / normalização de domínios (sem alterações funcionais)
# ---------------------------------------------------------------------------
DOMAIN_REGEX = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
)


def clean_and_normalize_domain(domain_line):
    """Limpa e classifica uma linha de uma blocklist.

    Devolve (domínio_ou_None, tipo) onde tipo é 'block', 'whitelist' ou 'invalid'.
    """
    domain = domain_line.strip().lower()

    if domain.startswith("@@||") and domain.endswith("^"):
        return domain[4:-1], "whitelist"

    elif domain.startswith("||") and domain.endswith("^"):
        return domain[2:-1], "block"

    elif domain.startswith(("0.0.0.0 ", "127.0.0.1 ")):
        parts = domain.split(" ", 1)
        if len(parts) > 1:
            domain_part = parts[1].strip()
            if DOMAIN_REGEX.match(domain_part):
                return domain_part, "block"
            else:
                return None, "invalid"
        return None, "invalid"

    elif DOMAIN_REGEX.match(domain):
        return domain, "block"

    if not domain or domain.startswith(("#", "!")) or domain.startswith("/") or "." not in domain or " " in domain:
        return None, "invalid"

    return None, "invalid"


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------
def remove_redundant_subdomains(domains):
    """Remove subdomínios cujo domínio "pai" já está na lista.

    Se 'tracker.com' está na lista, bloqueá-lo já bloqueia
    'ads.tracker.com', 'x.ads.tracker.com', etc. — por isso esses
    subdomínios são redundantes e podem ser removidos para reduzir
    o tamanho final da lista sem perder cobertura.

    Limitação conhecida: não usa uma "public suffix list", por isso
    mantém sempre pelo menos 2 labels (ex: nunca reduz a apenas "com").
    Domínios com TLDs compostos (ex: "co.uk", "com.br") podem, em casos
    raros, ser tratados como "pai" de algo que na prática é um domínio
    independente (ex: "example.co.uk" não deveria ser considerado pai
    de "other.co.uk"). Para a esmagadora maioria dos casos isto não é
    um problema, mas fica documentado.
    """
    domains_set = set(domains)
    result = set()
    removed_count = 0

    for domain in domains_set:
        labels = domain.split(".")
        is_redundant = False

        # Gera candidatos a "pai": vai removendo o label mais à esquerda,
        # mas nunca reduz a menos de 2 labels (evita tratar TLDs como pai).
        for i in range(1, len(labels) - 1):
            parent_candidate = ".".join(labels[i:])
            if parent_candidate in domains_set:
                is_redundant = True
                break

        if is_redundant:
            removed_count += 1
        else:
            result.add(domain)

    if removed_count:
        print(f"Subdomínios redundantes removidos: {removed_count}")

    return result


def generate_combined_list():
    sources_file = "sources.txt"
    downloaded_blocklists_dir = "blocklists/downloaded"
    custom_blocklists_dir = "blocklists/custom"
    whitelists_dir = "whitelists"
    output_file = "combined-blocklist.txt"

    # 1. Descarregar listas de bloqueio externas (em paralelo, com retries)
    os.makedirs(downloaded_blocklists_dir, exist_ok=True)
    if os.path.exists(sources_file):
        with open(sources_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        results = download_all(urls, downloaded_blocklists_dir)
        ok_count = sum(1 for v in results.values() if v)
        fail_count = len(results) - ok_count
        print(f"Downloads: {ok_count} com sucesso, {fail_count} falharam (de {len(results)} fontes).")
        if fail_count:
            failed_urls = [u for u, ok in results.items() if not ok]
            print("Fontes que falharam: " + ", ".join(failed_urls))

    # 2. Carregar domínios da whitelist
    whitelist_domains = set()
    for filepath in glob.glob(os.path.join(whitelists_dir, "*.txt")):
        print(f"A carregar whitelist de: {filepath}")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain, domain_type = clean_and_normalize_domain(line)
                if domain and domain_type in ("block", "whitelist"):
                    whitelist_domains.add(domain)

    # 3. Carregar e filtrar domínios das blocklists (descarregadas e personalizadas)
    combined_domains_raw = set()
    source_stats = {}

    for filepath in glob.glob(os.path.join(downloaded_blocklists_dir, "*.txt")):
        print(f"A processar blocklist descarregada: {filepath}")
        added = 0
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain, domain_type = clean_and_normalize_domain(line)
                if domain_type == "block" and domain not in whitelist_domains:
                    combined_domains_raw.add(domain)
                    added += 1
                elif domain_type == "whitelist":
                    whitelist_domains.add(domain)
        source_stats[filepath] = added

    for filepath in glob.glob(os.path.join(custom_blocklists_dir, "*.txt")):
        print(f"A processar blocklist personalizada: {filepath}")
        added = 0
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain, domain_type = clean_and_normalize_domain(line)
                if domain_type == "block" and domain not in whitelist_domains:
                    combined_domains_raw.add(domain)
                    added += 1
        source_stats[filepath] = added

    print("Domínios adicionados por fonte:")
    for filepath, count in sorted(source_stats.items(), key=lambda x: -x[1]):
        print(f"  {filepath}: {count}")

    # 3.5 Remover subdomínios redundantes (ex: descartar "ads.tracker.com"
    #     se "tracker.com" já está na lista)
    before_count = len(combined_domains_raw)
    combined_domains_raw = remove_redundant_subdomains(combined_domains_raw)
    after_count = len(combined_domains_raw)
    print(f"Total antes da remoção de subdomínios redundantes: {before_count}")
    print(f"Total depois da remoção de subdomínios redundantes: {after_count}")

    # 4. Escrever para o ficheiro de saída no formato ||domínio^
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("! Title: Combined AdGuard Home Blocklist\n")
        f.write(f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S GMT', time.gmtime())}\n")
        f.write("! Expires: 1 day\n")
        f.write("! Homepage: https://github.com/D34thSkull/blocklist-auto\n")
        f.write("! Version: 1.0\n")
        f.write("!\n")

        count = 0
        for domain in sorted(combined_domains_raw):
            f.write(f"||{domain}^\n")
            count += 1

        print(f"Lista consolidada gerada em '{output_file}' com {count} domínios no formato AdGuard/Adblock Plus.")


if __name__ == "__main__":
    try:
        import requests  # noqa: F401
    except ImportError:
        print("A biblioteca 'requests' não está instalada. Por favor, instala-a com: pip install requests")
        exit(1)

    generate_combined_list()
