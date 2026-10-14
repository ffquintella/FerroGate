# Documento de Mudança — FerroGate v0.29.0

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / CMIS, MIA e CLI `ferrogate` |
| Nível de classificação (1–4) | Proposta: 4 para a superfície administrativa (VPN, colaborador, NDA) — pendente de confirmação pelo ESI |
| Versão | 0.29.0 — **mudança incompatível (breaking) de segurança** |
| Tag no controle de versão | `releases/v0.29.0` |
| Data prevista de publicação | 2026-10-14 |
| Requisição de mudança (nº) | Não informada |
| Especificação | F20 Fase 0 (`docs/features/F20-admin-authentication.md` §1), F19 §7.1 (`HostCallAuth`), ADR-0005 |

## Motivação

Corrige a falha crítica registrada na visão geral (`docs/app-approval-and-admin.md`,
"Findings" 1–4): as RPCs administrativas da CMIS (`SetAllowlist`, `DeleteAllowlist`,
`ListAllowlists`, `ListProposals`, `DeleteProposal`, `RevokeSvid`, `RevokeHost`,
`BumpEpoch`, `ListSvids`) não verificavam o chamador, e o listener TLS não pede
certificado de cliente — qualquer host com acesso a `:8443` podia alterar allowlists,
revogar hosts ou forçar reatestação da frota. `AppendAuditEvent` aceitava eventos de
qualquer origem. Pela NRM §5.3.7, a falha crítica aberta bloqueava novas
funcionalidades (F19, F21, F22).

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/cmis/src/admin/` (`authz`, `layer`, `session`, `password`, `totp`, `throttle`, `bootstrap`, `keys`, `factors`, `webauthn`, `service`, `state`, `config`) | Contas administrativas locais, sessões, segundo fator TOTP e FIDO2, throttling NRM §5.3.5, tabela única método → permissão aplicada por camada tower em todos os listeners | Ponto único de autenticação e autorização (NRM §5.3.1) |
| `crates/cmis/src/server.rs`, `crates/cmis/src/transport.rs`, `crates/cmis/src/main.rs` | Listener administrativo `CMIS_ADMIN_LISTEN` (TLS híbrido PQC, mTLS opcional); métodos administrativos recusados sem TLS | Superfície administrativa separada e cifrada |
| `crates/cmis/src/host_auth.rs` (novo), `crates/cmis/src/service.rs`, `crates/cmis/src/state.rs` | Prova de host (`HostCallAuth`) em `AppendAuditEvent`: SVID, chave de máquina, assinatura sobre `ferrogate-audit-forward-v1 ‖ doc`, janela de 300 s, cache de nonces de 600 s, limite por host; apenas eventos originados em host; verificação de revogação também em `ProposeAllowlist` | Impedir injeção de eventos forjados e saturação do armazenamento WORM |
| `crates/cmis/src/state.rs`, `crates/cmis/src/service.rs` | Falhas de escrita no armazenamento replicado retornadas como `UNAVAILABLE (store_unavailable)` em vez de sucesso | "Perda silenciosa não" (G-002); auditoria não registra mudança que não ocorreu |
| `crates/ferro-proto/proto/admin.proto` (novo), `machine_identity.proto` | Serviço `ferrogate.admin.v1.Admin`; `HostCallAuth` e `AppendAuditRequest.auth`/`doc` | Contrato de rede da Fase 0 |
| `crates/ferro-svid/src/host_call.rs` (novo) | Documento assinado `AuditForwardDoc` e contexto de assinatura compartilhados por MIA e CMIS | Separação de domínio das assinaturas |
| `crates/ferro-raft/src/admin.rs` (novo), `cluster.rs` | Tabelas administrativas replicadas | Persistência de contas, sessões e fatores |
| `crates/ferro-audit/src/event.rs` | Novos eventos administrativos sem dados pessoais; `by_admin_id` pseudônimo nos eventos administrativos existentes | Trilha de auditoria (NRM §5.3.1) |
| `crates/ferro-crypto/src/transport.rs`, `crates/ferro-transport/src/lib.rs` | Configuração de servidor com mTLS e identidade de cliente | mTLS opcional no listener administrativo |
| `crates/ferrogate-cli/src/admin.rs` (novo), `main.rs`, `allowlist.rs` | `ferrogate admin login/logout/bootstrap/…`; comandos legados enviam a sessão | Operadores autenticados individualmente |
| `crates/mia/src/audit_client.rs` | O encaminhador de auditoria assina a prova de host | Compatível com a nova exigência |
| `docs/networking.md`, `docs/operations.md`, `docs/cmis.md`, `docs/audit.md`, `docs/allowlist-provisioning.md` | Corrige a alegação falsa de "credenciais TLS de operador"; documenta variáveis, bootstrap, login, atualização e limitações | Documentação operacional |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `ROADMAP.md`, `docs/change-v0.29.0.md` | Versão 0.29.0 e registro da mudança | Identificar e documentar o release |

## Impacto e compatibilidade

- **CLIs `ferrogate` anteriores a 0.29.0 deixam de funcionar** para comandos
  administrativos (`UNAUTHENTICATED`). Não há chave de compatibilidade sem
  autenticação.
- `CMIS_LEGACY_ADMIN_ON_MAIN=true` (padrão) mantém as RPCs legadas também em
  `:8443`, sempre autenticadas; deve passar a `false` após a migração dos operadores.
- Remetentes de `AppendAuditEvent` anteriores a 0.29.0 são recusados; o daemon MIA
  distribuído ainda não encaminha eventos pela rede.
- Operadores devem revisar o log de auditoria em busca de eventos `AllowlistSet`,
  `AllowlistDeleted`, `HostRevoked` e `PolicyEpochBumped` sem explicação (possível
  exploração anterior da falha). Se houver indício de uso indevido, tratar como
  incidente (NRM §5.4.4) e acionar o ESI.

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim — autenticação e autorização administrativa, segundo fator, sessões, throttling, prova de host, auditoria |
| O que foi alterado | Ver tabela acima |
| Desvio registrado | Contas locais em vez de integração com o AD corporativo (NRM §5.3.4) — decisão do product owner (D2), a registrar com o ESI |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | **Pendente antes da instalação em produção** (ROADMAP T262) |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas adicionados nesta versão | `argon2` 0.6, `hmac` 0.13, `sha1` 0.11 (somente HMAC-SHA-1 do TOTP, RFC 6238), `unicode-normalization` 0.1, `prost-types` 0.14 |
| Há componente descontinuado ou sem suporte? | Não avaliado nesta mudança (`make deny` / `make audit` a executar no pipeline de release) |
| Há vulnerabilidade crítica conhecida pendente? | Não avaliada nesta mudança |

## Limitações conhecidas

- O tipo de cliente (TUI, bandeja, CLI) é autodeclarado; a política
  `CMIS_ADMIN_TRAY_FIDO2_GROUPS` pode ser contornada declarando CLI/TUI e usando TOTP.
- Nonces de login e step-up são de uso único apenas por nó.
- Chaves de idempotência são aceitas, mas não aplicadas.
- Não há recuperação break-glass.
- O cache de nonces e o limite de `AppendAuditEvent`, assim como o conjunto de
  revogações, são por nó (não replicados).

## Verificações

| Verificação | Resultado | Data |
|---|---|---|
| `make fmt` | Executado; divergência de formatação preexistente em arquivos não alterados revertida | 2026-10-14 |
| `make lint` | Aprovada | 2026-10-14 |
| `make test` | Ver relatório da entrega | 2026-10-14 |
| Testes de prova de host (`cargo test -p cmis --test audit_forward`) | Aprovados — sem assinatura, host errado, `issued_at` antigo/futuro, nonce repetido, evento adulterado, host e SVID revogados, limite excedido, contexto errado, tipo de evento da CMIS | 2026-10-14 |
| Testes de falha de armazenamento (`cargo test -p cmis --test store_failures`) | Aprovados | 2026-10-14 |
| Encaminhamento MIA → CMIS ponta a ponta (`cargo test -p mia --test e2e_attest`) | Aprovado | 2026-10-14 |
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
| Tag de retorno | `releases/v0.28.2` |
| Procedimento | Reinstalar os artefatos 0.28.2. **Atenção:** o rollback reabre a falha crítica (RPCs administrativas sem autenticação); só com autorização do ESI. As tabelas administrativas criadas pela 0.29.0 são ignoradas pela 0.28.2 |
| Migrations reversíveis? | Aditivas (`CREATE TABLE IF NOT EXISTS`); a 0.28.2 não as lê. Eventos de auditoria novos permanecem no log WORM |
