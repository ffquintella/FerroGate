# Documento de Mudança — FerroGate v0.28.2

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação (1–4) | Pendente de confirmação pelo ESI |
| Versão | 0.28.2 |
| Tag no controle de versão | `releases/v0.28.2` |
| Data prevista de publicação | 2026-10-07 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia/dist/50-ferrogate-operators.rules` | Restringe controle Polkit a start, stop e restart de `mia.service` para o grupo `ferrogate-operators` | Delegar controle operacional sem conceder controle geral de unidades systemd |
| `crates/mia/dist/debian/postinst`, `Makefile`, `scripts/ferrogate-group.sh` | Criam o grupo e incluem a conta instaladora quando conhecida | Tornar a permissão disponível nos instaladores Linux |
| `crates/mia/Cargo.toml`, `scripts/check-deb-package.sh` | Empacotam e verificam a regra e o grupo | Garantir que o instalador Debian entregue a política esperada |
| `crates/mia/src/credstore.rs`, `crates/mia/src/setup_apply.rs`, `crates/mia/tests/swtpm_seal.rs` | Corrigem avisos Clippy e separam a apresentação do resultado do fluxo de aplicação | Manter lint sem avisos sem alterar a gravação de configuração ou auditoria |
| `docs/mia.md` | Documenta o escopo e os limites do grupo | Orientar operadores Linux |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `docs/change-v0.28.2.md` | Bump para 0.28.2 e registro da versão | Identificar e documentar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim — autorização local via Polkit para controle do serviço MIA |
| O que foi alterado | Grupo dedicado com permissão para start, stop e restart apenas de `mia.service`; ações de configuração continuam exigindo a autorização administrativa existente |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | Pendente antes da instalação em produção |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum |
| Há componente descontinuado ou sem suporte? | Não avaliado nesta mudança |
| Há vulnerabilidade crítica conhecida pendente? | Não avaliada nesta mudança |

## Verificações

| Verificação | Resultado | Data |
|---|---|---|
| Sintaxe dos scripts de instalação e verificação (`sh -n`) | Aprovada | 2026-10-07 |
| Sintaxe da regra Polkit (`node --check`) | Aprovada | 2026-10-07 |
| `make -n mia-install` | Aprovada | 2026-10-07 |
| `make test` | Aprovada — workspace; 1 teste ignorado por exigir 10 minutos | 2026-10-07 |
| Testes focados (`cargo test -p mia --lib setup_apply::tests`) | 17 passaram | 2026-10-07 |
| `make lint` | Aprovada | 2026-10-07 |
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
| Tag de retorno | `releases/v0.28.1` |
| Procedimento | Reinstalar os artefatos da versão 0.28.1 e remover a regra Polkit `50-ferrogate-operators.rules`; a mudança não migra dados persistidos |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
