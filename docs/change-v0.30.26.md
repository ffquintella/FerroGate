# Documento de Mudança — FerroGate v0.30.26

> Atende: NRM §5.3.1 (Mudanças), §5.2 (Mudanças — aquisição), §5.4.2 (regras de manutenção).
> Obrigatório em toda mudança de versão, especificando o que foi alterado e onde.
> Deve ser produzido antes de colocar em produção.

## Identificação

| Campo | Valor |
|---|---|
| Sistema | FerroGate / MIA |
| Nível de classificação | Proposta: nível 4, sujeita à validação do ESI |
| Versão | 0.30.26 |
| Tag no controle de versão | `v0.30.26` — pendente |
| Data prevista de publicação | 2026-11-13 |
| Requisição de mudança (nº) | Não informada |

## O que foi alterado e onde

| Arquivo / módulo | Natureza da alteração | Motivo |
|---|---|---|
| `crates/mia/dist/70-ferrogate-mia-tpm.rules` | Conceder ACL `rw` somente a `_ferrogate` nos dispositivos `/dev/tpmrm[0-9]*`, preservando owner, grupo e modo definidos pela distribuição | Permitir atestação TPM após a queda de privilégios sem ampliar o acesso a outros usuários nem ao TPM bruto |
| `crates/mia/dist/debian/*`, `crates/mia/dist/rpm/*`, `crates/mia/Cargo.toml` | Aplicar a ACL na instalação/atualização, reaplicá-la pela regra udev quando o nó for recriado e removê-la na desinstalação final; declarar dependências de ACL/udev | Tornar o ajuste permanente e idempotente durante todo o ciclo do pacote |
| `scripts/check-deb-package.sh`, `scripts/check-rpm-package.sh`, `Makefile`, `scripts/build-rpm-amd64.sh` | Verificar a regra, dependências e scripts de lifecycle dentro dos pacotes gerados | Impedir regressão do acesso ao TPM e validar sem instalar o pacote no host de build |
| `docs/mia.md`, `CHANGELOG.md` | Documentar o acesso restrito ao resource manager e sua remoção | Dar visibilidade operacional e de segurança |
| `Cargo.toml`, `Cargo.lock`, `docs/change-v0.30.26.md` | Atualizar a versão do workspace e registrar a mudança | Identificar e documentar o release |

## Requisitante

| Campo | Valor |
|---|---|
| Requisitante da alteração | Usuário deste chat |
| Área demandante | Não informada |

## Componentes básicos de segurança

| Campo | Valor |
|---|---|
| Algum componente de segurança foi alterado? | Sim |
| Quais | Autorização local do dispositivo TPM usado pela atestação |
| O que foi alterado | A conta de serviço recebe acesso `rw` somente ao resource manager; o TPM bruto, o grupo e o modo da distribuição permanecem inalterados |
| Quem solicitou | Usuário deste chat |
| Mudanças decorrentes da alteração | MIA pode usar o TPM depois de remover grupos suplementares; a ACL é vinculada à conta `_ferrogate` e ao dispositivo `tpmrm` |
| Responsável oficial pelo versionamento do componente | Não informado |
| Verificação/homologação do ESI | Pendente antes da produção |

## Componentes de terceiros

| Campo | Valor |
|---|---|
| Frameworks/bibliotecas atualizados nesta versão | Nenhum; os pacotes passam a declarar `acl` e udev como dependências operacionais |
| Há componente descontinuado ou sem suporte? | Pendente de verificação SCA |
| Há vulnerabilidade crítica conhecida pendente? | Pendente de verificação SCA |

## Verificações de segurança

| Verificação | Resultado | Data |
|---|---|---|
| Sintaxe da regra (`udevadm verify`) | Aprovada | 2026-11-13 |
| Teste de regressão do pacote Debian | Aprovado após falhar contra 0.30.25 pela ausência da regra | 2026-11-13 |
| Build e inspeção do pacote Debian (`make pkg-deb`) | Aprovados — `ferrogate-mia_0.30.26-1_amd64.deb` | 2026-11-13 |
| Build e inspeção do pacote RPM (`make pkg-rpm`) | Aprovados — `ferrogate-mia-0.30.26-1.x86_64.rpm` | 2026-11-13 |
| Formatação (`make fmt`) | Aprovada | 2026-11-13 |
| Análise de qualidade (`make lint`) | Aprovada | 2026-11-13 |
| Teste de lifecycle de pacote (`cargo test -p mia --test package_state`) | Aprovado — 6 testes | 2026-11-13 |
| Suíte completa (`make test`) | Interrompida por solicitação do coordenador durante a compilação; nenhum teste chegou a executar nesta tentativa | 2026-11-13 |
| Verificação de segurança do ESI | Pendente antes da produção | — |

## Autorizações

| Autorização | Responsável | Data | Situação |
|---|---|---|---|
| Homologador de sistemas (TIC) | Não informado | — | Pendente |
| Homologador do usuário | Não informado | — | Pendente |
| Coordenador — autorização para produção | Não informado | — | Pendente |
| Segurança (ESI) — alteração de componente básico de segurança | ESI | — | Pendente |
| Infraestrutura — se houver alteração em servidores | Infraestrutura | — | Pendente |

## Plano de rollback

| Campo | Valor |
|---|---|
| Tag de retorno | `v0.30.25` |
| Procedimento | Reinstalar 0.30.25; remover `/usr/lib/udev/rules.d/70-ferrogate-mia-tpm.rules`, recarregar udev e retirar a entrada `_ferrogate` da ACL dos dispositivos `/dev/tpmrm[0-9]*` |
| Migrations reversíveis? | Não há migrations de banco nesta mudança |
