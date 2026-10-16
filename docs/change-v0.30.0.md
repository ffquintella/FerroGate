# Documento de Mudança — FerroGate v0.30.0

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
>
> **Situação: rascunho, versão ainda não publicada.** O conteúdo está em
> `[Unreleased]` no `CHANGELOG.md`. A versão do workspace passou a 0.30.0 com
> o T293 (mudança de comportamento de segurança em `Rotate`, como a 0.29.0 fez
> com a F20 Fase 0); a tag sai no commit de release.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / CMIS, MIA, CLI `ferrogate`, TUI `ferrogate-tui` (novo binário) e SDK |
| Nível de classificação (1–4) | Proposta: 4 para a superfície administrativa e o ledger de aprovações (contém nomes de usuário, SIDs e caminhos — dado pessoal, F19 §10) — pendente de confirmação pelo ESI |
| Versão | 0.30.0 — funcionalidade nova; **sem quebra** enquanto o modo permanecer `legacy`, exceto `Rotate`, que passa a exigir prova de host (T293; nenhum MIA publicado chama `Rotate`) |
| Tag no controle de versão | `releases/v0.30.0` (a criar no release) |
| Data prevista de publicação | A definir |
| Requisição de mudança (nº) | Não informada |
| Especificação | F19 (`docs/features/F19-app-registration-approval.md`, §2–§11), ADR-0004, F20 §7 (tabela de permissões); marcos M37 (T263–T271), M38 (T272–T274) e M39 (T275–T279; F21, `docs/features/F21-admin-tui.md`) do `ROADMAP.md`; T293 (M33; F04, `docs/protocol.md` §"Renewal vs re-attestation") |

O ROADMAP previa F19 na 0.29; a 0.29.0 foi publicada só com a Fase 0 da F20
(autenticação administrativa), por isso F19 sai na 0.30.0.

## Motivação

Substituir as allowlists de chamadores mantidas à mão por um ciclo de vida de
aprovação por aplicação: o host pede a aprovação de um binário, um aprovador
decide, toda decisão é auditada e as aprovações nunca são substituídas por
pedidos (ADR-0004). O M38 conclui a migração: importa as allowlists legadas
como aprovações, troca o modo do cluster de forma auditada e reversível e
mantém os agentes antigos funcionando com um corpo v1 que só contém o que eles
conseguem aplicar.

## O que foi alterado e onde

### M37 — ledger de aprovações (T263–T271)

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/ferro-raft/src/apps/`, `migrations.rs` | Tabelas replicadas do ledger (linhagens, binários, pedidos, aprovações, revisões, estado da allowlist por host) com migrações ordenadas 1 e 2 e triggers SQLite (INV-1 a INV-3) | Não substituição de aprovações garantida também no banco |
| `crates/ferro-appid/` (novo) | Identificação de binários ELF/PE/Mach-O sem executá-los | Hash e metadados confiáveis |
| `crates/ferro-svid/src/{allowlist_v2,app_docs}.rs` | Allowlist v2 vinculada ao host, com geração; documentos assinados dos hosts | Proteção contra rollback e troca de host |
| `crates/cmis/src/apps/`, `admin/apps.rs`, `host_auth.rs`, `service.rs` | RPCs de host (`SubmitAppRequest`, `GetAppRequestStatus`, `SyncAllowlist`), decisões administrativas, auto-atualização, compilação v2, varredores | Fluxo de pedido e aprovação |
| `crates/mia/src/{allowlist_sync,registration}/`, `crates/mia-helper-proto/` | Sincronização a cada 5 min, protocolo helper v2, `mia app` | Agente atualizado |
| `crates/ferrogate-cli/src/apps.rs` | `ferrogate admin apps …` | Operação pelos aprovadores |

### M38 — migração para aprovações (T272–T274)

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/ferro-raft/src/apps/legacy.rs` (novo), `schema.rs` (`LEGACY_IMPORT_GUARDS`), `migrations.rs` (migração 3), `cluster.rs` | Importação idempotente das entradas legadas como aprovações `legacy_import` (id derivado da entrada; uma importação revogada nunca é recriada); trigger que recusa `legacy_import` com outros termos; contagens do rollback; leitura consistente de `host_allowlists` | T272; F19 §11 passo 4 |
| `crates/cmis/src/apps/migration.rs` (novo) | Plano (dry run) e importação em lotes; revogação (código 1000) das importações cuja entrada saiu do corpo legado; corpos legados ilegíveis ou sob chave que não é UUID são relatados e não importados | Falha segura; um binário removido em modo `legacy` não volta em `approvals` |
| `crates/cmis/src/admin/migration.rs` (novo), `admin/authz.rs`, `admin/service.rs` | RPCs `GetAllowlistMode` (qualquer sessão), `SetAllowlistMode` (`settings.allowlist_mode`, step-up) e `ImportLegacyAllowlists` (`allowlist.import`, step-up), classificadas em `METHOD_ACCESS` | T272, T273; F20 §7 |
| `crates/cmis/src/apps/v1.rs` (novo), `state.rs`, `service.rs` (`GetAllowlist`) | Corpo v1 "lossy-safe" em modo `approvals`, com cache por nó; `CMIS_LEGACY_GETALLOWLIST` | T273; F19 §6.4 |
| `crates/cmis/src/service.rs` (`SetAllowlist`, `DeleteAllowlist`, `ProposeAllowlist`), `apps/proposals.rs` (novo), `apps/mode.rs`, `apps/config.rs`, `state.rs` | Gravações legadas recusadas em modo `approvals` (`mode_approvals`), com o modo verificado na mesma transação da gravação; propostas de agentes antigos viram pedidos `observed`, sem adoção TOFU, com leituras agrupadas e no máximo 4096 entradas | T273; F19 §11 passo 5 |
| `crates/cmis/src/admin/apps.rs` | Escopo de caminho exato recusado para binário de caminho desconhecido (`path_unknown`) | Evitar aprovação que nunca casaria |
| `crates/ferro-audit/src/event.rs`, `crates/cmis/src/apps/events.rs` | Eventos `AllowlistImported` e `AllowlistModeChanged`, sem dados pessoais | Trilha de auditoria (NRM §5.3.1) |
| `crates/ferro-proto/proto/admin.proto`, `machine_identity.proto` | Mensagens das três RPCs; documentação do comportamento em modo `approvals` | Contrato de rede |
| `crates/ferrogate-cli/src/migration.rs` (novo), `admin.rs`, `allowlist.rs`, `main.rs` | `ferrogate admin migrate-allowlists [--dry-run]`, `ferrogate admin set-allowlist-mode legacy\|approvals [--yes] [--allow-unimported]`; `allowlist add\|remove` mapeados para registro direto e revogação em modo `approvals` | Operação da migração |
| `docs/operations.md` (runbook), `docs/cmis.md`, `docs/allowlist-provisioning.md`, `docs/audit.md`, `docs/mia.md`, F19/F20, `CHANGELOG.md`, `ROADMAP.md`, este documento | Runbook de migração e rollback, códigos de erro, variável `CMIS_LEGACY_GETALLOWLIST`, anúncio de descontinuação | T274 |

### M39 — TUI de administração do servidor (T275–T279)

Novo binário **`ferrogate-tui`** (F21): interface de terminal em tela cheia
para visualizadores e aprovadores. Não acessa o banco: toda ação é uma RPC do
serviço `Admin` autorizada pela CMIS (`AdminAuthz`), como na CLI. Nenhuma RPC
nova e nenhuma alteração de autorização no servidor.

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/ferrogate-tui/` (novo; `Cargo.toml` do workspace) | Binário `ferrogate-tui` e biblioteca sem terminal: `config` (arquivo `admin.toml` sem segredos, `FERROGATE_ADMIN_ENDPOINT`/`FERROGATE_ADMIN_SPKI_PIN`, recusa sem pin e sem porta explícita, leitura sem seguir symlink), `client` (tarefa tokio dona do canal fixado por SPKI em TLS híbrido PQC e do token de sessão), `app` (máquina de estados, filtros, diálogos, bloqueio por inatividade, nova tentativa única após step-up), `screens` (telas), `sanitize`, `secret` | T275–T278; F21 §1–§6, §8 |
| `crates/ferrogate-tui/src/sanitize.rs` | Neutralização de controles C0/C1, sequências ESC (OSC 52, OSC 8, CSI, DCS), bidi e largura zero em todo texto vindo do servidor | T279; F21 §7 (injeção de escape de terminal) |
| `crates/ferrogate-tui/tests/admin_tui.rs` | Teste de ponta a ponta contra a CMIS em processo (harness de `crates/cmis/tests/support`) atrás de um listener TLS real | Login → lista → aprovação com step-up; negação, edição com conflito (`ABORTED`), revogação e congelamento auditados; inclusão direta com TOTP novo; pin errado; visualizador recusado pelo servidor |
| `docs/operations.md` ("Administering approvals with `ferrogate-tui`"), `CHANGELOG.md`, `ROADMAP.md`, este documento | Guia de operação e registro da mudança | NRM §5.3.1 |

### T293 — prova de host em `Rotate` (M33)

Correção de segurança: `Rotate` era pública e não verificava assinatura,
validade nem revogação da SVID apresentada (oráculo de emissão).

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/ferro-svid/src/host_call.rs`, `lib.rs` | `RotateDoc`, `encode_rotate`/`decode_rotate` (CBOR canônico, chaves desconhecidas recusadas), contexto `ferrogate-rotate-v1` | Documento assinado pelo host |
| `crates/ferro-proto/proto/machine_identity.proto` | `RotateRequest` ganha `auth` (4) e `doc` (5); `pcr_values`/`known_epoch` ignorados | Contrato de rede |
| `crates/cmis/src/service.rs` (`rotate_with_host_proof`) | Autenticação pelo verificador único de host; recusa do nível TPM, de SVID superada e de deriva/época/janela; auditoria de emissão e recusas | Falha segura (NRM §5.3.5) e trilha (§5.3.1) |
| `crates/cmis/src/host_auth.rs`, `main.rs` | Limitador `rotate` e `CMIS_ROTATE_MAX_PER_HOUR` (padrão 6) | Limite por host |
| `crates/cmis/src/state.rs`, `crates/ferro-raft/src/cluster.rs` | `replace_bundle_if_current` / `replace_svid_if_unchanged` (comparar-e-trocar); `update_bundle` descontinuado | Duas renovações concorrentes não gravam ambas |
| `crates/cmis/src/admin/authz.rs` | `Rotate` passa a `Access::Host` | Ponto único de autorização |
| `crates/ferro-attest/src/rim.rs`, `crates/cmis/src/rim_watcher.rs`, `host_auth.rs` | `host-key` reservado no RIM (`HOST_KEY_POLICY_ID`, definição única; `apply`/`approve` recusam; log `rim.reserved_policy_id`); `RimStore::approve` passa a retornar `Result` | Um TPM não pode cair no nível host-key (revisão de segurança) |
| `crates/cmis/src/state.rs` (`lookup_checked`) | Falha de leitura do armazenamento em `Rotate` vira `UNAVAILABLE` auditado, não `NOT_FOUND` | Erro tratado e registrado (NRM §5.3.5) |
| `crates/mia/src/client.rs` | `rotate` / `rotate_request` | Cliente da prova (reuso na Parte 2) |
| `crates/cmis/tests/rotate_host_auth.rs` (novo), `crates/mia/tests/e2e_attest.rs` | 24 testes de integração; e2e migrado para o nível host-key | NRM §5.3.7 |
| `docs/protocol.md`, `cmis.md`, `operations.md`, `networking.md`, F04, F20, `CHANGELOG.md`, `ROADMAP.md`, este documento | Documentação | NRM §5.3.1 |

## Impacto e compatibilidade

- **`Rotate` (T293):** um cliente que chame `Rotate` sem a prova recebe
  `UNAUTHENTICATED host_auth_failed`; o nível TPM sempre recebe
  `FAILED_PRECONDITION` e refaz o `Attest`. Nenhum MIA publicado chama
  `Rotate` (a renovação em segundo plano no daemon é a Parte 2).

- **Nada muda até a troca de modo.** O cluster continua em `legacy`
  (`cmis_settings.allowlist_mode`); `SetAllowlist`, `GetAllowlist` e as
  propostas funcionam como na 0.29.0.
- **Pré-requisito da troca:** todos os nós da CMIS na 0.30.0 e a importação
  completa e atualizada (a CMIS recusa `approvals` com `import_stale` enquanto
  houver importação aberta cuja entrada saiu do corpo legado, sem exceção, e
  com `import_incomplete`, salvo `--allow-unimported`).
- **Em modo `approvals`:** `SetAllowlist`/`DeleteAllowlist` respondem
  `FAILED_PRECONDITION mode_approvals`; automações que gravavam allowlists
  devem passar a `ferrogate admin apps register` / `revoke` (aprovadores).
  Agentes MIA anteriores à F19 recebem só as aprovações que conseguem
  aplicar (qualquer caminho; uid Unix, qualquer usuário ou importação
  legada; válidas até o `not_after` do documento); os demais aplicativos são
  negados nesses agentes até a atualização (falha segura).
- **Rollback de modo** (`set-allowlist-mode legacy`): volta a servir os corpos
  legados preservados. As aprovações vivas que não são importações legadas
  deixam de valer e as importações legadas revogadas voltam a ser admitidas;
  a CLI mostra as duas contagens e exige confirmação.
- **Descontinuação anunciada:** a RPC v1 `GetAllowlist`, sem autenticação, está
  descontinuada. `CMIS_LEGACY_GETALLOWLIST=off` (padrão `on`) a desliga
  (`FAILED_PRECONDITION legacy_getallowlist_disabled`) quando não restar agente
  antigo; ela será removida em versão futura. `allowlist.propose` no MIA está
  descontinuado em modo `approvals`.

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim — autorização (novas permissões em uso: `settings.allowlist_mode`, `allowlist.import`), allowlists de chamadores (origem da autorização dos aplicativos), auditoria; emissão de SVID por `Rotate` (T293: autenticação de host, revogação, auditoria) |
| O que foi alterado | Ver tabelas acima. Negação por padrão: as três RPCs novas estão na tabela única `METHOD_ACCESS`; troca de modo e importação exigem operador de plataforma e step-up; falhas do armazenamento respondem `UNAVAILABLE` sem registrar evento |
| Desvio registrado | Risco aceito D4 (registro direto em um passo pelo mesmo aprovador, F19 §8), já registrado no M37 — a confirmar com o ESI |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | **Pendente** (NRM §5.3.1: obrigatória antes da produção) |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas adicionados nesta versão | `plist` 1.10.1 (M37, `ferro-appid`); nenhum no M38; no M39, `ratatui` 0.30 (MIT, sem features padrão, backend crossterm 0.29 já presente via `inquire`), `unicode-width` 0.2, `unicode-segmentation` 1.12, `static_assertions` 1.1 e `rustix` 1.1 (MIT/Apache-2.0; `unicode-*` e `rustix` já estavam na árvore) — `cargo deny check licenses bans sources` aprovado |
| Há componente descontinuado ou sem suporte? | Não avaliado nesta mudança (`make deny` / `make audit` no pipeline de release) |
| Há vulnerabilidade crítica conhecida pendente? | Não avaliada nesta mudança |

## Dados pessoais (LGPD)

O M38 não cria coluna nova de dado pessoal. As importações legadas guardam
apenas uid (ou RID) e hash, como os corpos legados. Os eventos de auditoria
novos levam somente ids de host e de administrador e contagens. A retenção e a
pseudonimização do ledger seguem pendentes de definição pelo DPO (T289).

## Limitações conhecidas

- O corpo v1 é "com perdas": aprovações com caminho exato, SID do Windows ou
  validade menor que a do documento não chegam aos agentes antigos.
- Pedidos vindos de `ProposeAllowlist` de agentes antigos não têm caminho nem
  metadados; ficam numa linhagem "caminho desconhecido" e só podem ser
  aprovados com escopo de qualquer caminho.
- O cache do corpo v1 é por nó. Uma entrada removida do corpo legado e depois
  incluída de novo continua revogada (registrar com `ferrogate admin apps
  register`).
- A troca para `approvals` só é gravada se nenhuma allowlist legada mudou
  desde a verificação (contagem e maior `updated_at` de `host_allowlists`, na
  mesma transação); duas gravações no mesmo segundo que preservem a contagem
  escapariam a essa impressão digital — risco residual muito baixo, com as
  gravações legadas já recusadas na própria transação após a troca.
- A troca de modo não confere a versão dos outros nós da CMIS: o operador deve
  garantir que todos estão na 0.30.0 antes de trocar.
- `ferrogate-tui` (M39) autentica apenas com senha + TOTP (AAL2, risco F21
  "TOTP only in the TUI", OQ1 a validar com o ESI). A tela Hosts não está
  disponível (a CMIS ainda não tem a RPC `ListHosts`); contas e sessões são
  somente leitura na TUI (administração pela CLI); revogação em lote, gerador
  de senha, textos em português, `--log-file` e o certificado de cliente do
  listener administrativo (mTLS opcional, `CMIS_ADMIN_CLIENT_CA`; disponível
  na CLI) ficam para depois. Os códigos
  de motivo de negação (1–6) e de revogação (1–5) são definidos pela TUI e
  documentados em `docs/operations.md`.
- `Rotate` (T293): o cache de nonces, o limitador e o conjunto de revogação
  são por nó, como nos demais métodos de host. Com o piso de 96 h da SVID e a
  janela de 24 h, a renovação agendada é normalmente um `Attest` completo. A
  SVID substituída continua válida até expirar (só não renova mais).

## Verificações

| Verificação | Resultado | Data |
|---|---|---|
| `make fmt` | Executado; divergência de formatação preexistente (rustfmt 1.10) em arquivos não alterados revertida | 2026-10-15 |
| `make lint` | Aprovada | 2026-10-15 |
| `make test` | Aprovada — 1325 testes, 0 falhas, 1 ignorado (82 suítes) | 2026-10-15 |
| Migração (`cargo test -p cmis --test allowlist_migration`) | Aprovada — dry run sem escrita; importação idempotente; linhas legadas intactas; importações obsoletas revogadas e troca recusada (`import_stale`); recusa sem permissão e sem step-up; troca e rollback; v1 lossy-safe e desligado; falha de armazenamento sem auditoria; propostas como pedidos `observed` e limite de entradas | 2026-10-15 |
| Revisão de segurança do diff (agente revisor) | 1 achado alto (importação obsoleta reativada na troca), 2 médios e 4 baixos — todos corrigidos e cobertos por testes | 2026-10-15 |
| Ledger (`cargo test -p ferro-raft --test app_ledger legacy`) | Aprovada — termos da importação, idempotência, validação, trigger da migração 3 | 2026-10-15 |
| CLI (`cargo test -p ferrogate-cli --test admin_cli migrate`) | Aprovada | 2026-10-15 |
| T293 (`cargo test -p cmis rotate`, `-p ferro-svid host_call`, `-p mia --test e2e_attest`, `make lint`) | Aprovada (ver relatório do T293) | 2026-10-16 |
| Verificação de segurança do ESI antes da produção | Pendente | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — componente de segurança | ESI | — | Pendente |

## Plano de rollback

| Campo | Valor |
|---|---|
| Rollback funcional (sem reinstalar) | `ferrogate admin set-allowlist-mode legacy` — volta a servir as allowlists legadas preservadas (runbook em `docs/operations.md`) |
| Tag de retorno | `releases/v0.29.0` |
| Procedimento | Voltar ao modo `legacy` **antes** de reinstalar os artefatos 0.29.0. A 0.29.0 não tem o modo nem `SyncAllowlist`: serve só os corpos legados por `GetAllowlist`; um MIA 0.30 que já guarda um corpo v2 o mantém até o `not_after` desse corpo (não aceita um v1 que reduziria a geração) e depois falha fechado. As tabelas do ledger e a migração 3 são ignoradas pela 0.29.0 |
| Migrations reversíveis? | Aditivas (tabelas, índices, triggers); a 0.29.0 não as lê. Eventos de auditoria novos permanecem no log WORM |
