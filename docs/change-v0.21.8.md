# Documento de Mudança — FerroGate v0.21.8

> Registro da alteração do instalador Debian para incluir a configuração dos grupos de acesso ao MIA e a instalação/inicialização do system tray.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação (1–4) | Pendente de confirmação pelo ESI |
| Versão | 0.21.8 |
| Tag no controle de versão | `releases/v0.21.8` |
| Data prevista de publicação | 2026-10-05 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `Cargo.toml`, `Cargo.lock` | Bump da versão do workspace | Identificar o release |
| `Makefile`, `crates/mia/Cargo.toml`, `crates/mia/dist/debian/` | Pacote Debian combinado para MIA + tray, criação idempotente de usuário/grupos e hooks de ciclo de vida | Corrigir a instalação Debian que não preparava acesso ao MIA nem instalava/iniciava o tray |
| `crates/mia-tray/dist/`, `scripts/check-deb-package.sh`, `.github/workflows/release.yml` | Unidade/autostart do tray e validação do pacote | Iniciar o tray na sessão disponível e verificar os componentes distribuídos |
| `CHANGELOG.md`, `docs/` | Registro e atualização de documentação | Documentar o conteúdo do release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim |
| Quais | Grupos de acesso ao socket local do MIA e configuração do usuário de serviço |
| O que foi alterado | O instalador cria `ferrogate-clients` e `ferrogate-status`, configura o GID do socket e inclui usuários locais pertinentes nos grupos |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | O acesso de grupo passa a valer após novo login; a política existente de autorização do MIA continua em vigor |
| Responsável oficial pelo versionamento do componente | Não informado |
| **Verificação/homologação do ESI** | Pendente |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum informado |
| Há componente descontinuado ou sem suporte? | Não identificado nesta mudança |
| Há vulnerabilidade crítica conhecida pendente? | Não avaliado nesta mudança |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Análise de qualidade de código-fonte (SAST) | Não executada nesta tarefa | — |
| Falhas em relatórios automatizados de segurança | Não avaliadas nesta tarefa | — |
| Verificação de segurança do ESI (obrigatória antes da produção) | Pendente | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — se componente crítico | ESI | — | Pendente |
| Infraestrutura — se houver alteração em servidores | Não aplicável ao empacotamento | — | — |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `releases/v0.21.7` |
| Procedimento | Reinstalar os pacotes da versão anterior. A remoção do novo pacote limpa o drop-in criado pelo pacote; as contas e grupos permanecem para preservar ownership numérico de arquivos existentes. |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
