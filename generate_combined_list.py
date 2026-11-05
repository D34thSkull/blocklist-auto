import hashlib
import ipaddress
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = BASE_DIR / "sources.txt"
WHITELISTS_DIR = BASE_DIR / "whitelists"
CUSTOM_BLOCKLISTS_DIR = BASE_DIR / "blocklists" / "custom"
OUTPUT_FILE = BASE_DIR / "combined-blocklist.txt"

MAX_RESPONSE_BYTES = 50 * 1024 * 1024
MAX_WORKERS = 8
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def load_entries(filepath):
    """Read non-empty, non-comment lines from a file."""
    try:
        with open(filepath, encoding="utf-8") as file:
            return [
                line.strip()
                for line in file
                if line.strip() and not line.lstrip().startswith(("#", "!"))
            ]
    except FileNotFoundError:
        return []


def normalize_domain(value):
    """Return a normalized domain or None if invalid."""
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "/" in value or " " in value:
        return None

    if value.startswith("||"):
        value = value[2:]
    value = value.lstrip("*.").rstrip("^")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    labels = value.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        return None

    return value


def parse_rule(raw_line):
    """Extract (domain, type) from a common blocklist rule."""
    line = raw_line.strip()
    if not line or line.startswith(("#", "!", "/", "[")):
        return []

    if line.startswith("@@||"):
        candidate = line[4:].split("^", 1)[0].split("$", 1)[0]
        domain = normalize_domain(candidate)
        return [(domain, "whitelist")] if domain else []

    if line.startswith("||"):
        candidate = line[2:].split("^", 1)[0].split("$", 1)[0]
        if "/" in candidate:
            return []
        domain = normalize_domain(candidate)
        return [(domain, "block")] if domain else []

    fields = line.split()
    try:
        ipaddress.ip_address(fields[0])
        candidates = fields[1:]
    except (ValueError, IndexError):
        candidates = [line] if len(fields) == 1 else []

    entries = []
    for candidate in candidates:
        domain = normalize_domain(candidate)
        if domain:
            entries.append((domain, "block"))
    return entries


def download_file(url, destination):
    """Download a source to disk with a size cap."""
    try:
        with requests.get(
            url,
            headers={"User-Agent": "BlocklistAuto/1.0"},
            stream=True,
            timeout=(5, 20),
        ) as response:
            response.raise_for_status()
            total_bytes = 0
            with open(destination, "wb") as output:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_RESPONSE_BYTES:
                        raise ValueError(
                            f"response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
                        )
                    output.write(chunk)
        return True
    except (requests.RequestException, OSError, ValueError) as error:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        print(f"[AVISO] Erro ao descarregar {url}: {error}")
        return False


def read_blocklist_file(filepath):
    blocked = set()
    exceptions = set()

    with open(filepath, encoding="utf-8", errors="replace") as file:
        for line in file:
            for domain, rule_type in parse_rule(line):
                if rule_type == "whitelist":
                    exceptions.add(domain)
                else:
                    blocked.add(domain)

    return blocked, exceptions


def is_whitelisted(domain, whitelist):
    """Whitelist a domain and each of its subdomains."""
    return any(
        domain == allowed or domain.endswith("." + allowed)
        for allowed in whitelist
    )


def write_output(blocked_domains, whitelist_domains):
    """Create the output list atomically."""
    fd, temporary_path = tempfile.mkstemp(
        prefix=".combined-blocklist-",
        dir=BASE_DIR,
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write("! Title: Combined AdGuard Home Blocklist\n")
            output.write("! Expires: 1 day\n")
            output.write("! Homepage: https://github.com/D34thSkull/blocklist-auto\n")
            output.write("! Version: 1.0\n!\n")

            for domain in sorted(whitelist_domains):
                output.write(f"@@||{domain}^\n")

            for domain in sorted(blocked_domains):
                if not is_whitelisted(domain, whitelist_domains):
                    output.write(f"||{domain}^\n")

        os.replace(temporary_path, OUTPUT_FILE)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def main():
    print("[INFO] A iniciar a atualização das blocklists...")

    sources = list(dict.fromkeys(load_entries(SOURCES_FILE)))
    if not sources:
        raise SystemExit("[ERRO] Nenhuma fonte encontrada em sources.txt")

    whitelist_domains = set()
    if WHITELISTS_DIR.is_dir():
        for filepath in sorted(WHITELISTS_DIR.glob("*.txt")):
            for line in load_entries(filepath):
                for domain, rule_type in parse_rule(line):
                    if rule_type == "whitelist":
                        whitelist_domains.add(domain)
                    else:
                        whitelist_domains.add(domain)

    all_blocked = set()
    downloaded_files = []

    with tempfile.TemporaryDirectory(prefix=".blocklists-", dir=BASE_DIR) as temp_dir:
        temp_dir = Path(temp_dir)
        futures = []

        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(sources))) as executor:
            for url in sources:
                digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
                destination = temp_dir / f"{digest}.txt"
                futures.append(executor.submit(download_file, url, destination))

            for future in as_completed(futures):
                result = future.result()
                # No result; download already logged failure.
                if result is False:
                    continue

        for url in sources:
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
            destination = temp_dir / f"{digest}.txt"
            if not destination.exists():
                print(f"[AVISO] Falha ao descarregar: {url}")
                continue
            downloaded_files.append(destination)

        if not downloaded_files:
            raise SystemExit(
                "[ERRO] Nenhuma fonte foi descarregada; "
                "o ficheiro existente foi preservado."
            )

        for filepath in downloaded_files:
            blocked, exceptions = read_blocklist_file(filepath)
            all_blocked.update(blocked)
            whitelist_domains.update(exceptions)

    if CUSTOM_BLOCKLISTS_DIR.is_dir():
        for filepath in sorted(CUSTOM_BLOCKLISTS_DIR.glob("*.txt")):
            blocked, exceptions = read_blocklist_file(filepath)
            all_blocked.update(blocked)
            whitelist_domains.update(exceptions)

    final_blocked = {
        domain for domain in all_blocked
        if not is_whitelisted(domain, whitelist_domains)
    }

    write_output(final_blocked, whitelist_domains)

    print(f"[INFO] Fontes descarregadas: {len(downloaded_files)}/{len(sources)}")
    print(f"[INFO] Domínios recolhidos: {len(all_blocked)}")
    print(f"[INFO] Domínios na whitelist: {len(whitelist_domains)}")
    print(f"[SUCESSO] Domínios finais: {len(final_blocked)}")
    print(f"[SUCESSO] Ficheiro gerado: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
