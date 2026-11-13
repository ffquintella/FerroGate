# Documento de Mudança — FerroGate v0.30.24

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
> Deve ser produzido antes de colocar em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA e MIA Tray |
| Nível de classificação (1–4) | Proposta: nível 4, sujeita à validação do ESI |
| Versão | 0.30.24 |
| Tag no controle de versão | `v0.30.24` |
| Data prevista de publicação | 2026-11-13 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia-tray/dist/ferrogate-mia.desktop`, `crates/mia/Cargo.toml`, `crates/mia-tray/Cargo.toml` | Instalar uma entrada visível **FerroGate MIA** nos pacotes Debian e RPM, abrindo a janela de status do processo existente | Fazer o aplicativo aparecer no menu sem iniciar uma segunda bandeja |
| `crates/mia-tray/Cargo.toml`, `Cargo.lock` | Usar o backend KSNI do `tray-icon` e remover o backend libappindicator e suas dependências | Publicar o disco de estado como `IconPixmap`, renderizado pelo Pantheon Wingpanel |
| `Makefile`, `.github/workflows/mia-tray.yml` | Ajustar dependências Linux e verificar que o build usa KSNI em vez de libappindicator | Manter os builds reproduzíveis e impedir a regressão do backend invisível |
| `scripts/check-deb-package.sh` | Verificar a entrada de aplicações, seu comando e sua visibilidade no pacote Debian | Impedir que o pacote volte a omitir ou esconder o lançador |
| `crates/mia-tray/src/gui/admin/mod.rs`, `crates/mia-tray/src/gui/mod.rs`, `crates/mia-tray/src/logview.rs`, `crates/mia/src/selftest.rs`, `crates/mia/tests/swtpm_attest.rs` | Corrigir anotações `must_use`, configuração condicional e asserções de teste rejeitadas pelo Clippy atual | Satisfazer o Clippy em todos os alvos sem alterar o comportamento |
| `docs/mia-tray.md`, `CHANGELOG.md` | Documentar instalação, entrada de aplicações e backend de bandeja no Linux | Orientar usuários e operadores |
| `Cargo.toml`, `Cargo.lock`, `docs/change-v0.30.24.md` | Atualizar a versão do workspace e registrar esta mudança | Identificar e documentar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Não |
| Quais | Nenhum; autenticação, autorização, segredos, criptografia, atestação e armazenamento não foram alterados |
| O que foi alterado | Integração visual e empacotamento do cliente Linux |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | A janela de status passa a ser acessível pelo menu de aplicações e o ícone de estado passa a ser publicado via KSNI |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | Pendente antes da produção |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | O recurso Linux de `tray-icon` passa de `libappindicator` para `ksni` 0.3.7; `tray-icon` permanece em 0.26 |
| Há componente descontinuado ou sem suporte? | Pendente de verificação SCA |
| Há vulnerabilidade crítica conhecida pendente? | Pendente de verificação SCA |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Formatação (`make fmt`) | Aprovada | 2026-11-13 |
| Análise de qualidade de código-fonte (`make lint`) | Aprovada | 2026-11-13 |
| Testes de diagnóstico e assinatura (`cargo test -p mia selftest::tests::`) | Aprovados — 27 passaram | 2026-11-13 |
| Isolamento de dependências do tray (`make check-tray-isolation`) | Aprovado | 2026-11-13 |
| Build e inspeção do pacote (`make pkg-deb`) | Aprovados — `ferrogate-mia_0.30.24-1_amd64.deb` | 2026-11-13 |
| Falhas em relatórios automatizados de segurança | Pendente | — |
| Verificação de segurança do ESI (obrigatória antes da produção) | Pendente | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — antes da produção | ESI | — | Pendente |
| Infraestrutura — se houver alteração em servidores | Não aplicável | — | — |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `v0.30.23` |
| Procedimento | Reinstalar os artefatos da versão 0.30.23; a mudança não migra nem reescreve configuração persistida |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
