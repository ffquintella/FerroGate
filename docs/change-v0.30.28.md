# Documento de Mudança — FerroGate v0.30.28

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Deve ser aprovado antes de colocar a versão em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação | Proposta: nível 4, sujeita à validação do ESI |
| Versão | 0.30.28 |
| Tag no controle de versão | `v0.30.28` |
| Data prevista de publicação | 2026-11-13 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia/dist/debian/postinst`, `crates/mia/dist/rpm/postinstall` | Conceder ACL de leitura somente a `_ferrogate` nos TOMLs de sistema | O daemon limpa grupos suplementares ao cair privilégios; associação ao grupo `ferrogate-status` não permitia reler `mia.toml` no SIGHUP |
| `crates/mia/src/setup_apply.rs` | Preservar `system.posix_acl_access` na substituição atômica de configuração no Linux | O provisionamento de `allowlist.key` troca o inode do TOML e removia a ACL aplicada pelo instalador |
| `crates/mia/src/resync.rs` | Exigir a chave de verificação antes do sync, aguardar um novo resultado do status e só confirmar sucesso com allowlist verificada carregada | Impedir que a interface mostre a ação como concluída apenas porque o SIGHUP foi entregue |
| `crates/mia/tests/package_state.rs`, scripts de inspeção de pacote | Cobrir ACL do instalador, sua presença nos pacotes e a preservação durante escrita atômica | Evitar regressão nas duas fronteiras que controlam a leitura pós-queda de privilégios |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` | Atualizar a versão e documentar a correção | Identificar o release |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim |
| Quais | Autorização local de leitura da configuração e verificação da allowlist assinada |
| O que foi alterado | `_ferrogate` recebe somente leitura dos TOMLs; nenhuma escrita, grupo suplementar ou chave é exposta. A ausência ou falha de verificação continua deny-all |
| Verificação/homologação do ESI | Pendente antes da produção |

## Verificações

| Verificação | Resultado | Data |
|---|---|---|
| Testes regressivos TDD (ACL do pacote, preservação atômica e resultado do resync) | Aprovados após reproduzirem os defeitos | 2026-11-13 |
| Formatação (`make fmt`) | Aprovada | 2026-11-13 |
| Análise estática (`make lint`) | Aprovada | 2026-11-13 |
| Testes do MIA (`cargo test -p mia --lib`; `cargo test -p mia --test package_state`) | Aprovados — 492 + 7 testes | 2026-11-13 |
| Suíte completa (`make test`) | Bloqueada por falha reproduzível e não relacionada em `cmis/tests/app_admin.rs`: esperava `lineage_frozen`, recebeu `no_auto_parent` | 2026-11-13 |
| Verificação de segurança do ESI | Pendente antes da produção | — |

## Autorizações

| Autorização | Responsável | Situação |
|---|---|---|
| Homologador de sistemas (TIC) | Não informado | Pendente |
| Homologador do usuário | Não informado | Pendente |
| Segurança — alteração de componente básico | ESI | Pendente |
| Infraestrutura — publicação do pacote | Infraestrutura | Pendente |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `v0.30.27` |
| Procedimento | Reinstalar 0.30.27 e reiniciar o MIA. A remoção opcional da entrada de ACL de `_ferrogate` nos TOMLs restaura exatamente a política anterior, mas também restaura a falha de reload |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
