# Simple Blocklist

Este repositório gera automaticamente uma blocklist consolidada a partir de várias fontes públicas, aplica regras de whitelist e elimina domínios redundantes para reduzir o tamanho final da lista.

## Objetivo

O projeto reúne listas de bloqueio de anúncios, rastreadores e malware e produz um único ficheiro compatível com AdGuard/Adblock Plus no formato:

```text
||example.com^
@@||allowed.example.com^
```

## Estrutura do repositório

- `sources.txt` - URLs das listas de origem, uma por linha.
- `whitelists/` - URLs de exceção, para não serem bloqueados.
- `generate_combined_list.py` - script principal que descarrega, processa e escreve a lista final.
- `combined-blocklist.txt` - output gerado pela execução do script.
- `.github/workflows/generate_list.yml` — workflow do GitHub Actions para gerar a lista automaticamente.

## Como funciona

1. Lê `sources.txt` e descarrega todas as listas configuradas em paralelo.
2. Normaliza cada linha para extrair domínios válidos.
3. Aplica whitelist e elimina exceções de subdomínios que não devem ser bloqueados.
4. Remove regras redundantes, como subdomínios cobertos por um domínio pai.
5. Escreve a lista final em `combined-blocklist.txt` com formato AdGuard.

## Regras de whitelist

Os ficheiros dentro de `whitelists/` podem conter:

- domínios simples, por exemplo `google.com`
- entradas do tipo `@@||example.com^`
- regras de hosts (por exemplo `0.0.0.0 example.com`)

O script trata essas entradas como exceções e mantém o domínio protegido, bem como os seus subdomínios.

## Execução local

Requer Python 3.10+ e a biblioteca `requests`.

```bash
python -m pip install requests
python generate_combined_list.py
```

## GitHub Actions

O workflow executa o script diariamente e também pode ser acionado manualmente.

- dispara em `schedule` diário
- aceita `workflow_dispatch`
- grava a lista gerada no repositório apenas quando houve alterações

## Importante

Se algum download falhar, o script aborta e preserva a versão anterior da lista. Isto evita publicar uma lista incompleta ou corrompida.

## Dicas

- Mantém `sources.txt` atualizado para controlar o perfil da blocklist.
- Usa a whitelist para permitir domínios que não devem ser bloqueados.
- Se o tamanho da lista crescer demasiado, revisa quais fontes são realmente necessárias.

## Licença

Sem licença definida neste repositório por enquanto.
