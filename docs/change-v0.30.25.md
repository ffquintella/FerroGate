# Documento de Mudança — FerroGate v0.30.25

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
> Deve ser produzido antes de colocar em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação (1–4) | Proposta: nível 4, sujeita à validação do ESI |
| Versão | 0.30.25 |
| Tag no controle de versão | `v0.30.25` — pendente |
| Data prevista de publicação | 2026-11-13 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia/src/hardening.rs`, `crates/mia/src/main.rs` | Tornar a exigência de IMA appraisal opt-in com `FERROGATE_REQUIRE_IMA=1` | Permitir que o agente inicie em kernels Linux de estação de trabalho sem appraisal ativo |
| `crates/mia/src/helper/auth.rs`, `crates/mia/src/registration/identify.rs` | Documentar e sinalizar a autenticação de chamadores sem o cross-check do log IMA | Manter explícita a redução de garantia quando IMA não é exigido |
| `crates/mia/src/status_cli.rs` | Fazer o estado `ima_disabled` aparecer somente quando o processo ou o ambiente do serviço exige IMA | Evitar diagnóstico incorreto em instalações com a nova política padrão |
| `crates/mia/dist/mia.env`, `docs/mia.md`, `docs/features/F08-helper-api.md`, `docs/features/F12-mia-hardening.md`, `docs/roadmap.md`, `CHANGELOG.md` | Documentar o novo padrão, o opt-in e o risco residual | Dar visibilidade operacional à mudança de premissa de segurança |
| `Cargo.toml`, `Cargo.lock`, `docs/change-v0.30.25.md` | Atualizar a versão do workspace e registrar esta mudança | Identificar e documentar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim |
| Quais | Hardening de processo Linux e autenticação local de chamadores do helper |
| O que foi alterado | IMA appraisal deixa de ser obrigatório por padrão; `FERROGATE_REQUIRE_IMA=1` restaura a exigência fail-closed e o cross-check do log de medições |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | Sem IMA, a identidade local se apoia no SHA-384 da imagem carregada por `/proc/<pid>/exe` e na allowlist assinada; seccomp, queda de privilégios, `mlock`, `no_new_privs` e `dumpable=off` permanecem ativos |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | Pendente antes da produção |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum |
| Há componente descontinuado ou sem suporte? | Pendente de verificação SCA |
| Há vulnerabilidade crítica conhecida pendente? | Pendente de verificação SCA |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Formatação (`make fmt`) | Aprovada | 2026-11-13 |
| Build (`cargo build -p mia`) | Aprovado | 2026-11-13 |
| Testes de hardening e autenticação (`cargo test -p mia --lib hardening::tests`; `cargo test -p mia --lib helper::auth::`) | Aprovados — 5 + 14 passaram | 2026-11-13 |
| Testes de status (`cargo test -p mia --lib status_cli::tests`; `cargo test -p mia --test agent_states`) | Aprovados — 8 + 1 passaram | 2026-11-13 |
| Análise de qualidade de código-fonte (`make lint`) | Aprovada | 2026-11-13 |
| Suíte completa (`make test`) | Reprovada — `cmis/tests/app_admin.rs`: `revoke_update_and_freeze_are_audited_and_change_the_served_allowlist` esperava `lineage_frozen` e recebeu `no_auto_parent`; fora dos módulos alterados | 2026-11-13 |
| Build e inspeção do pacote (`make pkg-deb`; `scripts/check-deb-package.sh`) | Aprovados — `ferrogate-mia_0.30.25-1_amd64.deb` | 2026-11-13 |
| Falhas em relatórios automatizados de segurança | Pendente | — |
| Verificação de segurança do ESI (obrigatória antes da produção) | Pendente | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — alteração de componente básico de segurança | ESI | — | Pendente |
| Infraestrutura — se houver alteração em servidores | Não aplicável | — | — |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `v0.30.24` |
| Procedimento | Reinstalar os artefatos da versão 0.30.24; para manter a versão 0.30.25 com a política anterior, definir `FERROGATE_REQUIRE_IMA=1` e reiniciar o serviço |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
