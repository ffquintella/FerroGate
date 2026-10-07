# Documento de Mudança — FerroGate v0.28.1

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
> Deve ser produzido antes de colocar em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação (1–4) | Pendente de confirmação pelo ESI |
| Versão | 0.28.1 |
| Tag no controle de versão | `releases/v0.28.1` (prevista) |
| Data prevista de publicação | 2026-10-07 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia-tray/src/gui/setup_view.rs` | Após Apply bem-sucedido, manter os valores validados no formulário em vez de iniciar automaticamente outra leitura privilegiada | Evitar que uma segunda autorização polkit cancelada masque uma gravação concluída |
| `docs/mia-tray.md`, `CHANGELOG.md` | Documentar o fluxo de autorização e o comportamento corrigido | Orientar operadores após a aplicação |
| `crates/mia-tray/src/logview.rs` | Marcar como `must_use` o iterador público para satisfazer Clippy | Manter o lint do tray sem avisos |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `docs/change-v0.28.1.md` | Bump para 0.28.1 e registro da versão | Identificar e registrar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim — fluxo de autorização administrativa |
| Quais | Aplicação de configurações pelo MIA tray com `pkexec` no Linux |
| O que foi alterado | Removeu-se a segunda leitura privilegiada automática após Apply; cada leitura protegida explícita continua exigindo consentimento do sistema |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | O sucesso de `mia setup --apply` permanece visível mesmo se o operador precisar escolher **Load** para reler o arquivo posteriormente |
| Responsável oficial pelo versionamento do componente | Não informado |
| **Verificação/homologação do ESI** | Pendente |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum |
| Há componente descontinuado ou sem suporte? | Não avaliado nesta mudança |
| Há vulnerabilidade crítica conhecida pendente? | Não avaliada nesta mudança |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Análise de qualidade de código-fonte (SAST) | Não executada nesta mudança | — |
| Lint (`make lint-tray`) | Aprovado | 2026-10-07 |
| Testes focados (`cargo test -p mia-tray --features gui`) | 84 passaram | 2026-10-07 |
| Verificação de build (`cargo check -p mia-tray --features gui`) | Aprovada | 2026-10-07 |
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
| Tag de retorno | `releases/v0.28.0` |
| Procedimento | Reinstalar os artefatos da versão 0.28.0; a mudança não migra nem reescreve a configuração persistida |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
