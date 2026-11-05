import hashlib
import ipaddress
import os
import re
import tempfile
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
USER_AGENT = "BlocklistAuto/1.0"


def load_entries(filepath):
    """Return non-empty, non-comment lines from a text file."""
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
    if not value or len(value) > 253 or "/" in value or any(char.isspace() for char in value):
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
    """Extract (domain, rule type) entries from common blocklist formats."""
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
    """Download a source to a temporary file with a decompressed size cap."""
    try:
        with requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
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
    """Parse a blocklist file into blocked and exception domain sets."""
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


def load_whitelist():
    """Load whitelist entries; every valid domain entry is an allow rule."""
    whitelist = set()
    if not WHITELISTS_DIR.is_dir():
        return whitelist

    for filepath in sorted(WHITELISTS_DIR.glob("*.txt")):
        with open(filepath, encoding="utf-8", errors="replace") as file:
            for line in file:
                for domain, _ in parse_rule(line):
                    whitelist.add(domain)
    return whitelist


def is_whitelisted(domain, whitelist):
    """Check the domain and its parent domains in O(number of labels)."""
    labels = domain.split(".")
    return any(
        ".".join(labels[index:]) in whitelist
        for index in range(len(labels) - 1)
    )


def remove_redundant_subdomains(domains):
    """Drop blocked subdomains already covered by a blocked parent domain."""
    optimized = set()
    for domain in sorted(domains, key=lambda value: (value.count("."), value)):
        labels = domain.split(".")
        has_blocked_parent = any(
            ".".join(labels[index:]) in optimized
            for index in range(1, len(labels))
        )
        if not has_blocked_parent:
            optimized.add(domain)
    return optimized


def required_exceptions(blocked_domains, whitelist_domains):
    """Return only whitelist rules needed to override an active parent block."""
    required = set()

    for allowed_domain in whitelist_domains:
        labels = allowed_domain.split(".")
        # A whitelist entry needs an AdGuard exception only if a block rule
        # matches one of its parent domains. The domain itself and its
        # descendants are already excluded during block filtering.
        for index in range(1, len(labels)):
            parent_domain = ".".join(labels[index:])
            if parent_domain in blocked_domains:
                required.add(allowed_domain)
                break

    # An exception for a parent also protects its subdomains, so omit
    # redundant, more specific exception rules.
    compact = set()
    for domain in sorted(required, key=lambda value: (value.count("."), value)):
        labels = domain.split(".")
        has_exception_parent = any(
            ".".join(labels[index:]) in compact
            for index in range(1, len(labels))
        )
        if not has_exception_parent:
            compact.add(domain)

    return compact


def write_output(blocked_domains, exceptions):
    """Atomically replace the generated list, preserving required exceptions."""
    fd, temporary_path = tempfile.mkstemp(
        prefix=".combined-blocklist-",
        dir=BASE_DIR,
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            # Keep headers deterministic so unchanged content does not cause
            # a new generated commit solely because the date changed.
            output.write("! Title: Combined AdGuard Home Blocklist\n")
            output.write("! Expires: 1 day\n")
            output.write("! Homepage: https://github.com/D34thSkull/blocklist-auto\n")
            output.write("! Version: 1.0\n!\n")

            for domain in sorted(exceptions):
                output.write(f"@@||{domain}^\n")
            for domain in sorted(blocked_domains):
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

    whitelist_domains = load_whitelist()
    source_results = []

    # Downloads are isolated in a temporary directory, so stale files can
    # never silently be included in the output.
    with tempfile.TemporaryDirectory(prefix=".blocklists-", dir=BASE_DIR) as temp_dir:
        temp_dir = Path(temp_dir)
        future_to_source = {}

        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(sources))) as executor:
            for index, url in enumerate(sources):
                destination = temp_dir / f"source-{index}.txt"
                future = executor.submit(download_file, url, destination)
                future_to_source[future] = (url, destination)

            failed_sources = []
            for future in as_completed(future_to_source):
                url, destination = future_to_source[future]
                if future.result():
                    source_results.append((url, destination))
                else:
                    failed_sources.append(url)

        if failed_sources:
            details = "\n".join(f"  - {url}" for url in failed_sources)
            raise SystemExit(
                "[ERRO] Um ou mais downloads falharam; a lista existente foi "
                f"preservada. Fontes com erro:\n{details}"
            )

        all_blocked = set()
        for _, filepath in sorted(source_results):
            blocked, exceptions = read_blocklist_file(filepath)
            all_blocked.update(blocked)
            whitelist_domains.update(exceptions)

    if CUSTOM_BLOCKLISTS_DIR.is_dir():
        for filepath in sorted(CUSTOM_BLOCKLISTS_DIR.glob("*.txt")):
            blocked, exceptions = read_blocklist_file(filepath)
            all_blocked.update(blocked)
            whitelist_domains.update(exceptions)

    filtered_domains = {
        domain
        for domain in all_blocked
        if not is_whitelisted(domain, whitelist_domains)
    }
    final_domains = remove_redundant_subdomains(filtered_domains)
    exceptions = required_exceptions(final_domains, whitelist_domains)

    write_output(final_domains, exceptions)

    print(f"[INFO] Fontes descarregadas: {len(source_results)}/{len(sources)}")
    print(f"[INFO] Domínios recolhidos: {len(all_blocked)}")
    print(f"[INFO] Domínios na whitelist: {len(whitelist_domains)}")
    print(f"[INFO] Exceções de whitelist necessárias: {len(exceptions)}")
    print(f"[SUCESSO] Domínios finais: {len(final_domains)}")
    print(f"[SUCESSO] Ficheiro gerado: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
