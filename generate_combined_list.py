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
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def load_entries(filepath):
    """Read non-empty, non-comment lines from a text file."""
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
    """Return a normalized domain, or None if the value is invalid."""
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "/" in value or " " in value:
        return None

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


def parse_line(raw_line):
    """Extract (domain, rule_type) entries from common blocklist formats."""
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
        candidates = fields[1:]  # Hosts-file format.
    except (ValueError, IndexError):
        candidates = [line] if len(fields) == 1 else []

    entries = []
    for candidate in candidates:
        domain = normalize_domain(candidate)
        if domain:
            entries.append((domain, "block"))
    return entries


def fetch_to_file(url, destination):
    """Download a source to a temporary file with a size limit."""
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

        return url, destination
    except (requests.RequestException, OSError, ValueError) as error:
        Path(destination).unlink(missing_ok=True)
        print(f"[AVISO] Erro ao descarregar {url}: {error}")
        return url, None


def read_blocklist_file(filepath):
    blocked_domains = set()
    whitelist_domains = set()

    with open(filepath, encoding="utf-8", errors="replace") as file:
        for line in file:
            for domain, rule_type in parse_line(line):
                if rule_type == "whitelist":
                    whitelist_domains.add(domain)
                else:
                    blocked_domains.add(domain)

    return blocked_domains, whitelist_domains


def is_whitelisted(domain, whitelist):
    """Whitelist a domain and all its subdomains."""
    labels = domain.split(".")
    return any(
        ".".join(labels[index:]) in whitelist
        for index in range(len(labels) - 1)
    )


def optimize_domains(domains, whitelist):
    """Apply the whitelist and remove subdomains covered by parent rules."""
    filtered = {
        domain for domain in domains
        if not is_whitelisted(domain, whitelist)
    }
    optimized = set()

    for domain in sorted(filtered, key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        has_blocked_parent = any(
            ".".join(labels[index:]) in optimized
            for index in range(1, len(labels))
        )
        if not has_blocked_parent:
            optimized.add(domain)

    return sorted(optimized)


def write_output(domains):
    """Atomically replace the output file."""
    fd, temporary_path = tempfile.mkstemp(
        prefix=".combined-blocklist-",
        dir=BASE_DIR,
        text=True,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            # Keep the header stable so an unchanged list does not create a
            # new commit every day just because its timestamp changed.
            output.write("! Title: Combined AdGuard Home Blocklist\n")
            output.write("! Expires: 1 day\n")
            output.write(
                "! Homepage: https://github.com/D34thSkull/blocklist-auto\n"
            )
            output.write("! Version: 1.0\n!\n")

            for domain in domains:
                output.write(f"||{domain}^\n")

        os.replace(temporary_path, OUTPUT_FILE)
    except Exception:
        Path(temporary_path).unlink(missing_ok=True)
        raise


def main():
    print("[INFO] A iniciar a atualização das blocklists...")
    sources = list(dict.fromkeys(load_entries(SOURCES_FILE)))
    if not sources:
        raise SystemExit("[ERRO] Nenhuma fonte encontrada em sources.txt")

    whitelist = set()
    if WHITELISTS_DIR.is_dir():
        for filepath in sorted(WHITELISTS_DIR.glob("*.txt")):
            for line in load_entries(filepath):
                for domain, _ in parse_line(line):
                    whitelist.add(domain)

    all_domains = set()
    downloaded_count = 0

    # Store downloads in a temporary directory to avoid stale files and
    # collisions when different URLs have the same filename.
    with tempfile.TemporaryDirectory(prefix=".blocklists-", dir=BASE_DIR) as temp_dir:
        temp_dir = Path(temp_dir)
        futures = []

        with ThreadPoolExecutor(
            max_workers=min(MAX_WORKERS, len(sources))
        ) as executor:
            for url in sources:
                filename = hashlib.sha256(url.encode("utf-8")).hexdigest() + ".txt"
                destination = temp_dir / filename
                futures.append(
                    executor.submit(fetch_to_file, url, destination)
                )

            downloaded_files = []
            for future in as_completed(futures):
                url, filepath = future.result()
                if filepath is not None:
                    downloaded_count += 1
                    downloaded_files.append((url, filepath))

        if not downloaded_files:
            raise SystemExit(
                "[ERRO] Nenhuma fonte foi descarregada; "
                "o ficheiro existente foi preservado."
            )

        # Collect all source exceptions before filtering, so download order
        # cannot affect whitelist behavior.
        for _, filepath in downloaded_files:
            blocked, exceptions = read_blocklist_file(filepath)
            all_domains.update(blocked)
            whitelist.update(exceptions)

    if CUSTOM_BLOCKLISTS_DIR.is_dir():
        for filepath in sorted(CUSTOM_BLOCKLISTS_DIR.glob("*.txt")):
            print(f"[INFO] A processar lista personalizada: {filepath}")
            blocked, exceptions = read_blocklist_file(filepath)
            all_domains.update(blocked)
            whitelist.update(exceptions)

    final_domains = optimize_domains(all_domains, whitelist)
    write_output(final_domains)

    print(f"[INFO] Fontes descarregadas: {downloaded_count}/{len(sources)}")
    print(f"[INFO] Domínios recolhidos: {len(all_domains)}")
    print(f"[INFO] Domínios na whitelist: {len(whitelist)}")
    print(f"[SUCESSO] Domínios finais: {len(final_domains)}")
    print(f"[SUCESSO] Ficheiro gerado: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
