# Documento de Mudança — FerroGate v0.30.29

> Atende: NRM §5.3.1 (Mudanças). Deve ser aprovado antes de colocar a versão em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação | Proposta: nível 4, sujeita à validação do ESI |
| Versão | 0.30.29 |
| Tag no controle de versão | `v0.30.29` |
| Data prevista de publicação | 2026-11-13 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Alteração e motivo |
|---|---|
| `crates/mia-tray/dist/icons/ferrogate-mia.svg` | Mover o comentário para dentro da raiz SVG para que o GdkPixbuf reconheça o ícone no lançador GTK. A arte permanece igual. |
| `scripts/check-deb-package.sh` | Verificar que a raiz SVG aparece no prefixo usado na identificação do formato. |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` | Atualizar a versão e documentar a correção. |

## Verificações

| Verificação | Resultado |
|---|---|
| Teste regressivo do pacote | Falhou com o pacote anterior e passou com o pacote corrigido. |
| SVG extraído do pacote | Decodificado pelo GdkPixbuf, 1024 × 1024, com transparência. |
| `make fmt`, `make lint` | Aprovados. |
| `make test` | Falha não relacionada em `cmis/tests/app_admin.rs`: esperado `lineage_frozen`, recebido `no_auto_parent`. |
| Verificação de segurança do ESI antes da produção | Pendente. |
