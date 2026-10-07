# Documento de Mudança — FerroGate v0.28.0

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
> Deve ser produzido antes de colocar em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação (1–4) | Pendente de confirmação pelo ESI |
| Versão | 0.28.0 |
| Tag no controle de versão | `releases/v0.28.0` (prevista) |
| Data prevista de publicação | 2026-10-07 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia-tray/src/actions.rs`, `crates/mia-tray/src/gui/setup_view.rs`, `crates/mia-tray/src/i18n.rs`, `crates/mia-tray/src/wizard.rs` | Campo opcional de fingerprint SHA-384, validação e passagem de `--expect-fingerprint` pela ação elevada | Permitir no tray a mesma confirmação textual da chave de registro disponível no console |
| `crates/mia/src/setup.rs`, `crates/mia/src/setup_apply.rs` | Aceitar e validar `--expect-fingerprint` durante `mia setup --fetch-enrollment-key`; recusar escrita quando a chave recebida divergir | Preservar a integridade da chave pública de registro obtida do CMIS |
| `crates/mia-tray/src/gui/setup_view.rs`, `crates/mia-tray/src/wizard.rs`, `crates/mia/src/setup_apply.rs`, `crates/ferrogate-cli/src/main.rs` | Campo para colar a chave pública de registro no setup gráfico; `ferrogate enrollment-key --format public-key`; validação e instalação atômica e auditada | Facilitar o provisionamento manual sem mover a chave de confiança para a configuração TOML |
| `docs/features/F18-mia-tray.md`, `docs/mia-tray.md`, `docs/mia.md` | Atualização de comportamento e argumentos documentados | Documentar o fluxo gráfico e o comportamento de falha segura |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `docs/change-v0.28.0.md` | Bump e registro da versão | Identificar e registrar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim |
| Quais | Provisionamento e validação da chave pública de registro do CMIS |
| O que foi alterado | O tray aceita fingerprint opcional para busca ou colagem; MIA valida e instala a chave pública colada através do gravador atômico e auditado |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | Chave inválida ou fingerprint divergente não é instalada; substituição de uma chave diferente continua exigindo o fluxo explícito de rotação |
| Responsável oficial pelo versionamento do componente | Não informado |
| **Verificação/homologação do ESI** | Pendente |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum |
| Há componente descontinuado ou sem suporte? | Sim — `cargo audit` reportou `paste`, `proc-macro-error` e `ttf-parser` como não mantidos; este release não os atualiza |
| Há vulnerabilidade crítica conhecida pendente? | Não identificada por `cargo audit` nesta execução; o relatório também registrou o aviso de correção de segurança `RUSTSEC-2024-0429` em `glib` |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Análise de qualidade de código-fonte (SAST) | Não executada nesta mudança | — |
| Lint automatizado (`make lint`) | Falhou por quatro avisos Clippy já presentes no HEAD anterior: `logview.rs` (`must_use_candidate`), `credstore.rs` (2 × `similar_names`) e `setup_apply.rs` (`too_many_lines`) | 2026-10-07 |
| Testes automatizados (`make test`) | Falhou somente no encerramento intermitente de `short_chaos_run_keeps_serving_while_quorum_holds`; a repetição isolada passou | 2026-10-07 |
| Testes focados | `cargo test -p mia-tray --lib` (82), `cargo test -p mia setup_apply --lib` (17) e `cargo test -p ferrogate-cli enrollment_key` (2) passaram; `cargo check -p mia-tray --features gui` passou | 2026-10-07 |
| Falhas em relatórios automatizados de segurança | Não avaliadas nesta mudança | — |
| Verificação de segurança do ESI (obrigatória antes da produção) | Pendente | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — componente de segurança | ESI | — | Pendente |
| Infraestrutura — se houver alteração em servidores | Não aplicável | — | — |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `releases/v0.27.1` |
| Procedimento | Reinstalar os artefatos da versão 0.27.1 e manter a chave de registro já instalada; esta mudança não executa migration nem altera a configuração persistida sem ação explícita do operador. |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
