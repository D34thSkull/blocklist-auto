import pytest
from generate_combined_list import clean_and_normalize_domain, remove_redundant_subdomains


# --- Formato AdGuard / Adblock Plus -----------------------------------------

def test_adguard_block_rule():
    assert clean_and_normalize_domain("||ads.example.com^") == ("ads.example.com", "block")


def test_adguard_whitelist_rule():
    assert clean_and_normalize_domain("@@||trusted.example.com^") == ("trusted.example.com", "whitelist")


def test_adguard_block_rule_with_whitespace():
    assert clean_and_normalize_domain("   ||ads.example.com^   \n") == ("ads.example.com", "block")


# --- Formato hosts (0.0.0.0 / 127.0.0.1) ------------------------------------

def test_hosts_format_0000():
    assert clean_and_normalize_domain("0.0.0.0 tracker.example.com") == ("tracker.example.com", "block")


def test_hosts_format_127():
    assert clean_and_normalize_domain("127.0.0.1 tracker.example.com") == ("tracker.example.com", "block")


def test_hosts_format_invalid_target():
    # depois do IP não vem um domínio válido
    assert clean_and_normalize_domain("0.0.0.0 not_a_domain") == (None, "invalid")


def test_hosts_format_missing_target():
    assert clean_and_normalize_domain("0.0.0.0") == (None, "invalid")


# --- Domínio puro ------------------------------------------------------------

def test_plain_domain():
    assert clean_and_normalize_domain("ads.example.com") == ("ads.example.com", "block")


def test_plain_domain_uppercase_is_lowercased():
    assert clean_and_normalize_domain("ADS.EXAMPLE.COM") == ("ads.example.com", "block")


def test_plain_domain_with_subdomain():
    assert clean_and_normalize_domain("a.b.c.ads.example.com") == ("a.b.c.ads.example.com", "block")


# --- Linhas inválidas / a ignorar -------------------------------------------

def test_comment_hash():
    assert clean_and_normalize_domain("# isto é um comentário") == (None, "invalid")


def test_comment_bang():
    assert clean_and_normalize_domain("! isto é um comentário AdGuard") == (None, "invalid")


def test_empty_line():
    assert clean_and_normalize_domain("") == (None, "invalid")


def test_whitespace_only_line():
    assert clean_and_normalize_domain("   \n") == (None, "invalid")


def test_pure_ip_address():
    # Um IP sozinho não é um domínio válido para os nossos critérios
    assert clean_and_normalize_domain("192.168.1.1") == (None, "invalid")


def test_regex_rule_is_invalid():
    # Regras regex tipo /padrao/ não são suportadas — devem ser ignoradas, não crashar
    assert clean_and_normalize_domain("/some-regex-pattern/") == (None, "invalid")


def test_line_with_path_is_invalid():
    assert clean_and_normalize_domain("example.com/path/to/thing") == (None, "invalid")


def test_no_dot_is_invalid():
    assert clean_and_normalize_domain("localhost") == (None, "invalid")


# --- Casos limite -------------------------------------------------------------

def test_adguard_rule_without_closing_caret_falls_through():
    # "||ads.example.com" sem "^" não corresponde à regra AdGuard,
    # mas pode ainda corresponder ao regex de domínio puro (com "||" como prefixo inválido)
    domain, domain_type = clean_and_normalize_domain("||ads.example.com")
    assert domain_type == "invalid"


def test_single_label_tld_like_string():
    # "test.x" tem TLD de 1 caractere -> não deve ser aceite (regex exige 2+)
    assert clean_and_normalize_domain("test.x") == (None, "invalid")


@pytest.mark.parametrize(
    "line,expected",
    [
        ("doubleclick.net", ("doubleclick.net", "block")),
        ("||doubleclick.net^", ("doubleclick.net", "block")),
        ("@@||doubleclick.net^", ("doubleclick.net", "whitelist")),
        ("0.0.0.0 doubleclick.net", ("doubleclick.net", "block")),
        ("127.0.0.1 doubleclick.net", ("doubleclick.net", "block")),
    ],
)
def test_same_domain_across_formats(line, expected):
    assert clean_and_normalize_domain(line) == expected


# --- remove_redundant_subdomains --------------------------------------------

def test_removes_direct_subdomain_when_parent_present():
    result = remove_redundant_subdomains({"tracker.com", "ads.tracker.com"})
    assert result == {"tracker.com"}


def test_removes_multi_level_subdomain_when_parent_present():
    result = remove_redundant_subdomains(
        {"tracker.com", "ads.tracker.com", "x.ads.tracker.com"}
    )
    assert result == {"tracker.com"}


def test_keeps_unrelated_domains():
    result = remove_redundant_subdomains({"a.com", "b.com"})
    assert result == {"a.com", "b.com"}


def test_keeps_subdomain_when_parent_not_present():
    result = remove_redundant_subdomains({"ads.tracker.com"})
    assert result == {"ads.tracker.com"}


def test_never_reduces_below_two_labels():
    # "tracker.com" não deve ser tratado como tendo "com" como pai
    result = remove_redundant_subdomains({"tracker.com"})
    assert result == {"tracker.com"}


def test_empty_set():
    assert remove_redundant_subdomains(set()) == set()


def test_does_not_remove_siblings_with_same_parent_label():
    # "shop.example.com" e "blog.example.com" não são pai/filho um do outro
    result = remove_redundant_subdomains({"shop.example.com", "blog.example.com"})
    assert result == {"shop.example.com", "blog.example.com"}
