//! English / Portuguese strings — a compile-time table.
//!
//! Every user-facing string the tray itself produces is a [`Msg`]; the table
//! holds both languages side by side so a missing translation is a compile
//! error, not a runtime fallback. Placeholders are `{name}` and are filled with
//! [`fill`]. Text that comes from the daemon or from `mia` output is *not*
//! translated (it is shown escaped, see [`crate::text`]).

/// A UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (the default).
    #[default]
    En,
    /// Portuguese (Brazil).
    Pt,
}

impl Lang {
    /// Map a locale tag (`pt_BR.UTF-8`, `pt-BR`, `en_US`, `C`) to a language;
    /// `None` when the tag names neither.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        let lower = tag.trim().to_ascii_lowercase();
        let primary = lower
            .split(['_', '-', '.', '@', ':'])
            .next()
            .unwrap_or_default();
        match primary {
            "pt" => Some(Self::Pt),
            "en" | "c" | "posix" => Some(Self::En),
            _ => None,
        }
    }

    /// Pick the language from the environment (`LC_ALL`, `LC_MESSAGES`,
    /// `LANG`, `LANGUAGE` in that order) and then the OS locale; English when
    /// nothing matches.
    #[must_use]
    pub fn detect() -> Self {
        Self::detect_from(|k| std::env::var(k).ok(), sys_locale::get_locale())
    }

    /// [`Lang::detect`] over an injected environment and OS locale.
    #[must_use]
    pub fn detect_from(env: impl Fn(&str) -> Option<String>, os_locale: Option<String>) -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            if let Some(v) = env(var).filter(|v| !v.trim().is_empty()) {
                // LANGUAGE is a colon-separated preference list.
                if let Some(lang) = v.split(':').find_map(Self::from_tag) {
                    return lang;
                }
            }
        }
        os_locale
            .as_deref()
            .and_then(Self::from_tag)
            .unwrap_or_default()
    }
}

/// Replace each `{key}` in `template` with its value.
#[must_use]
pub fn fill(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in args {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

macro_rules! messages {
    ($( $id:ident => $en:literal, $pt:literal; )*) => {
        /// A user-facing string; the doc line of each variant is its English
        /// text.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Msg {
            $( #[doc = $en] $id, )*
        }

        impl Msg {
            /// Every message (for exhaustive tests).
            pub const ALL: &'static [Msg] = &[$(Msg::$id),*];

            /// The text in `lang`.
            #[must_use]
            pub fn text(self, lang: Lang) -> &'static str {
                match (self, lang) {
                    $( (Msg::$id, Lang::En) => $en, (Msg::$id, Lang::Pt) => $pt, )*
                }
            }
        }
    };
}

messages! {
    AppName => "FerroGate MIA", "FerroGate MIA";
    MenuOpenStatus => "Open status", "Abrir status";
    MenuSetup => "Setup…", "Configuração…";
    MenuLogs => "Logs…", "Logs…";
    MenuRunSelfTest => "Run self-test", "Executar autoteste";
    MenuQuit => "Quit", "Sair";
    MenuLastAction => "Last action: {action} — {outcome}", "Última ação: {action} — {outcome}";
    MenuReadDoc => "Read: {doc}", "Ler: {doc}";
    MenuForEnv => "{action} ({env})", "{action} ({env})";

    StateNotInstalled => "MIA is not installed", "O MIA não está instalado";
    StateNotRunning => "The agent is not running", "O agente não está em execução";
    StateNotConfigured => "The agent is not configured", "O agente não está configurado";
    StateAttesting => "Attesting…", "Atestando…";
    StateCmisUnreachable => "CMIS unreachable — retrying", "CMIS inacessível — tentando novamente";
    StateNotEnrolled => "This machine is not enrolled", "Esta máquina não está registrada";
    StatePinMismatch => "CMIS certificate does not match the pin", "O certificado do CMIS não corresponde ao pin";
    StateTpmUnavailable => "TPM unavailable", "TPM indisponível";
    StateImaDisabled => "IMA appraisal is disabled", "A avaliação IMA está desativada";
    StateCrlStale => "Revocation list is stale", "A lista de revogação está desatualizada";
    StateAllowlistMissing => "No caller allowlist", "Sem lista de permissões de chamadores";
    StateAllowlistInvalid => "The caller allowlist is invalid", "A lista de permissões é inválida";
    StateSvidExpiring => "Machine identity is expiring", "A identidade da máquina está expirando";
    StateHealthy => "Healthy", "Saudável";
    StateAccessDenied => "Status not readable by this user", "Status não legível por este usuário";

    ExplainNotInstalled => "The tray could not find the mia program. Install the FerroGate MIA package for this platform.", "O tray não encontrou o programa mia. Instale o pacote FerroGate MIA desta plataforma.";
    ExplainNotRunning => "The agent's status endpoint is absent: the mia service is stopped. Start it (administrator approval is required).", "O endpoint de status do agente não existe: o serviço mia está parado. Inicie-o (requer aprovação do administrador).";
    ExplainNotConfigured => "No CMIS server or helper socket is configured, so the agent is idle. Open the setup wizard.", "Nenhum servidor CMIS ou socket do helper está configurado, então o agente está ocioso. Abra o assistente de configuração.";
    ExplainAttesting => "The agent is proving this machine's identity to CMIS. This normally takes a few seconds.", "O agente está provando a identidade desta máquina ao CMIS. Isso normalmente leva alguns segundos.";
    ExplainCmisUnreachable => "The agent cannot reach CMIS and keeps retrying. Run the self-test to see which step fails (DNS, network, TLS).", "O agente não consegue alcançar o CMIS e continua tentando. Execute o autoteste para ver qual etapa falha (DNS, rede, TLS).";
    ExplainNotEnrolled => "CMIS does not recognise this machine. Copy the machine identifiers and send them to your FerroGate operator.", "O CMIS não reconhece esta máquina. Copie os identificadores da máquina e envie-os ao operador do FerroGate.";
    ExplainPinMismatch => "CMIS presented a certificate whose key does not match the configured SPKI pin. Change the pin only if your operator confirms a key rotation.", "O CMIS apresentou um certificado cuja chave não corresponde ao pin SPKI configurado. Altere o pin somente se o operador confirmar uma rotação de chave.";
    ExplainTpmUnavailable => "The TPM backend is selected but the TPM is missing or busy. Run the self-test, or choose another attestation backend (auto falls back to host-key).", "O backend TPM está selecionado, mas o TPM está ausente ou ocupado. Execute o autoteste ou escolha outro backend de atestação (auto recorre ao host-key).";
    ExplainImaDisabled => "This Linux host requires IMA appraisal but the kernel does not enforce it, so the agent refuses to start. See the documentation (kernel command line).", "Este host Linux exige avaliação IMA, mas o kernel não a aplica, então o agente se recusa a iniciar. Veja a documentação (linha de comando do kernel).";
    ExplainCrlStale => "The cached revocation list is older than 5 minutes, so token minting is refused. The self-test tells whether CMIS or this agent is at fault.", "A lista de revogação em cache tem mais de 5 minutos, então a emissão de tokens é recusada. O autoteste indica se a falha é do CMIS ou deste agente.";
    ExplainAllowlistMissing => "No signed allowlist is loaded, so every local caller is denied. Resync it from CMIS, or enable allowlist.fetch / allowlist.propose in the wizard.", "Nenhuma lista de permissões assinada está carregada, então todo chamador local é negado. Ressincronize-a a partir do CMIS ou ative allowlist.fetch / allowlist.propose no assistente.";
    ExplainAllowlistInvalid => "The allowlist failed verification or expired, so every local caller is denied. Resync it from CMIS.", "A lista de permissões falhou na verificação ou expirou, então todo chamador local é negado. Ressincronize-a a partir do CMIS.";
    ExplainSvidExpiring => "The machine identity is past its renewal point and renewal is failing. Run the self-test; restarting the service retries attestation.", "A identidade da máquina passou do ponto de renovação e a renovação está falhando. Execute o autoteste; reiniciar o serviço tenta a atestação novamente.";
    ExplainHealthy => "The machine identity is valid, the revocation list is fresh and the allowlist is loaded.", "A identidade da máquina é válida, a lista de revogação está atualizada e a lista de permissões está carregada.";
    ExplainUnknownError => "The agent reported a problem this version of the tray does not recognise. Run the self-test for details.", "O agente relatou um problema que esta versão do tray não reconhece. Execute o autoteste para detalhes.";
    ExplainAccessDenied => "Your account may not read the agent's status: it is not in the status group (ferrogate-status, or FerroGateStatus on Windows). Ask an administrator to add you, then log out and back in.", "Sua conta não pode ler o status do agente: ela não está no grupo de status (ferrogate-status, ou FerroGateStatus no Windows). Peça a um administrador para incluí-lo e depois saia e entre novamente.";

    DetailState => "State", "Estado";
    DetailFor => "for {d}", "há {d}";
    DetailProblem => "Problem", "Problema";
    DetailIdentity => "Identity", "Identidade";
    DetailSvidTimes => "expires {expires}, renews {renews}", "expira {expires}, renova {renews}";
    DetailIn => "in {d}", "em {d}";
    DetailAgo => "{d} ago", "há {d}";
    DetailCmisNode => "CMIS node", "Nó CMIS";
    DetailCrlAge => "CRL age", "Idade da CRL";
    DetailCrlNone => "no CRL pulled yet", "nenhuma CRL obtida ainda";
    DetailAllowlist => "Allowlist", "Lista de permissões";
    AllowlistLoaded => "loaded ({n} entries, expires {when})", "carregada ({n} entradas, expira {when})";
    AllowlistMissingShort => "missing", "ausente";
    AllowlistInvalidShort => "invalid", "inválida";
    DetailAttestation => "Attestation", "Atestação";
    BackendAuto => "auto (not resolved yet)", "auto (ainda não resolvido)";
    BackendVirtualTpm => "virtual-tpm (INSECURE)", "virtual-tpm (INSEGURO)";
    DetailX509Store => "X.509 store", "Repositório X.509";
    DetailAgent => "Agent", "Agente";
    DefaultEnvironment => "default", "padrão";
    MarkerDefaultAddress => "[default address]", "[endereço padrão]";
    DetailDefaultAddress => "Helper API: serves the well-known default address — local applications reach this environment without configuration", "API do helper: atende o endereço padrão conhecido — as aplicações locais chegam a este ambiente sem configuração";
    SourceEndpoint => "from the status endpoint", "do endpoint de status";
    SourceCli => "from `mia status` (fallback)", "de `mia status` (alternativa)";
    SourceSynthesised => "agent not reachable", "agente inacessível";
    DetailSource => "Source", "Origem";

    ActionRunSelfTest => "Run self-test", "Executar autoteste";
    ActionShowMachineId => "Show machine ID", "Mostrar ID da máquina";
    ActionShowStatus => "Show status (mia status)", "Mostrar status (mia status)";
    ActionServiceStart => "Start the service", "Iniciar o serviço";
    ActionServiceStop => "Stop the service", "Parar o serviço";
    ActionServiceRestart => "Restart the service", "Reiniciar o serviço";
    ActionResyncAllowlist => "Resync the allowlist", "Ressincronizar a lista de permissões";
    ActionRefreshKey => "Re-fetch the enrollment key", "Obter novamente a chave de registro";
    ActionApplySetup => "Apply the configuration", "Aplicar a configuração";
    ActionSetDefaultEnvironment => "Set as default environment", "Definir como ambiente padrão";
    ActionClearDefaultEnvironment => "Use mia.toml as default", "Usar o mia.toml como padrão";
    RecoveryOpenWizard => "Open the setup wizard", "Abrir o assistente de configuração";
    RecoveryOpenWizardPins => "Update the SPKI pin", "Atualizar o pin SPKI";
    RecoveryOpenWizardAttestation => "Choose the attestation backend", "Escolher o backend de atestação";
    RecoveryCopyIds => "Copy machine identifiers", "Copiar identificadores da máquina";

    DocInstall => "Installation guide", "Guia de instalação";
    DocNetworking => "Networking guide", "Guia de rede";
    DocCrlStale => "CRL-stale runbook", "Runbook: CRL desatualizada";
    DocAllowlist => "Allowlist provisioning", "Provisionamento da lista de permissões";
    DocTpm => "TPM and attestation backends", "TPM e backends de atestação";
    DocHardening => "IMA and process hardening", "IMA e endurecimento do processo";
    DocPins => "SPKI pinning (TLS)", "Fixação SPKI (TLS)";
    DocEnrollment => "Enrolling a machine", "Registro de máquinas";
    DocTray => "mia-tray guide", "Guia do mia-tray";
    DocRunbooks => "All runbooks", "Todos os runbooks";

    OutcomeSucceeded => "done", "concluído";
    OutcomeFailed => "failed", "falhou";
    OutcomeCancelled => "cancelled", "cancelado";
    OutcomeNotAuthorized => "not authorized", "não autorizado";
    OutcomeTimedOut => "timed out", "tempo esgotado";
    OutcomeRunning => "running…", "executando…";
    ErrorMiaNotFound => "The mia program was not found.", "O programa mia não foi encontrado.";
    ErrorMiaUntrusted => "mia is installed where an unprivileged user could replace it, so the tray will not run it with administrator rights. Reinstall it from the package, or run the command yourself with sudo.", "O mia está instalado onde um usuário sem privilégios poderia substituí-lo, então o tray não o executará com direitos de administrador. Reinstale-o pelo pacote ou execute o comando você mesmo com sudo.";
    ErrorToolUntrusted => "A system tool this action needs is in a location an unprivileged user could modify, so the tray will not run it with administrator rights.", "Uma ferramenta do sistema necessária para esta ação está em um local que um usuário sem privilégios poderia alterar, então o tray não a executará com direitos de administrador.";
    ErrorNoElevationTool => "No administrator-approval tool is available on this system (pkexec / osascript / PowerShell).", "Nenhuma ferramenta de aprovação de administrador está disponível neste sistema (pkexec / osascript / PowerShell).";
    ErrorUnsupported => "This action is not available on this platform.", "Esta ação não está disponível nesta plataforma.";
    ErrorBadEnvironment => "Invalid environment name.", "Nome de ambiente inválido.";
    ErrorStartFailed => "Could not start the command.", "Não foi possível iniciar o comando.";
    ErrorUnexpectedOutput => "mia replied with output the tray could not read.", "O mia respondeu com uma saída que o tray não conseguiu ler.";
    NoteElevation => "This action needs administrator approval; your system will ask for it.", "Esta ação requer aprovação do administrador; o sistema irá solicitá-la.";
    NoteRestartToApply => "Restart the service to apply it: the default address moves only when the agent restarts.", "Reinicie o serviço para aplicar: o endereço padrão só muda quando o agente reinicia.";

    NotifyAttentionTitle => "FerroGate MIA needs attention", "O FerroGate MIA precisa de atenção";
    NotifySvidExpiringTitle => "Machine identity expiring", "Identidade da máquina expirando";
    NotifyCrlStaleTitle => "Revocation list stale", "Lista de revogação desatualizada";
    NotifyBody => "{env}: {state}", "{env}: {state}";

    TabStatus => "Status", "Status";
    TabRecovery => "Recovery", "Recuperação";
    TabSetup => "Setup", "Configuração";
    TabLogs => "Logs", "Logs";
    ButtonRefresh => "Refresh", "Atualizar";
    ButtonRun => "Run", "Executar";
    LabelEnvironment => "Environment", "Ambiente";
    LabelOutput => "Output", "Saída";
    LabelSuggested => "Suggested for the current state", "Sugerido para o estado atual";
    LabelAllActions => "All actions", "Todas as ações";
    LabelDocs => "Documentation", "Documentação";
    StatusNoData => "Waiting for the first status…", "Aguardando o primeiro status…";
    SelfTestPassed => "All checks passed.", "Todas as verificações passaram.";
    SelfTestFailed => "Some checks failed.", "Algumas verificações falharam.";
    CopiedIds => "Machine identifiers copied to the clipboard.", "Identificadores da máquina copiados para a área de transferência.";

    SetupTarget => "Configuration file", "Arquivo de configuração";
    ScopeSystem => "System (read by the service; needs administrator approval)", "Sistema (lido pelo serviço; requer aprovação do administrador)";
    ScopeUser => "Per-user", "Por usuário";
    SetupLoad => "Load the current configuration", "Carregar a configuração atual";
    SetupLoading => "Loading…", "Carregando…";
    SetupLoadFailed => "Could not read the current configuration. You can start from defaults; applying replaces only the settings this wizard manages (other keys are kept).", "Não foi possível ler a configuração atual. Você pode começar dos padrões; aplicar substitui apenas as opções gerenciadas por este assistente (as demais chaves são mantidas).";
    SetupStartFromDefaults => "Start from defaults", "Começar dos padrões";
    SetupFile => "File: {path}", "Arquivo: {path}";
    SetupFileAbsent => "(does not exist yet)", "(ainda não existe)";
    SetupReadOnly => "set by ${var} — read-only", "definido por ${var} — somente leitura";
    SetupCheck => "Check with mia", "Verificar com o mia";
    SetupCheckOk => "mia accepted the draft.", "O mia aceitou o rascunho.";
    SetupCheckRejected => "mia rejected the draft:", "O mia rejeitou o rascunho:";
    SetupApply => "Apply", "Aplicar";
    SetupReload => "Reload the agent after applying", "Recarregar o agente após aplicar";
    SetupFetchKey => "Fetch the enrollment public key from CMIS into this file", "Obter a chave pública de registro do CMIS e salvar neste arquivo";
    SetupApplied => "Configuration written.", "Configuração gravada.";
    SetupTargetChanged => "The selected file differs from the one loaded: load it before checking or applying.", "O arquivo selecionado é diferente do carregado: carregue-o antes de verificar ou aplicar.";
    SetupNeedsCheck => "Check the draft with mia before applying.", "Verifique o rascunho com o mia antes de aplicar.";
    SetupFixErrors => "Fix the highlighted fields first.", "Corrija primeiro os campos destacados.";
    StepCmis => "CMIS server", "Servidor CMIS";
    StepHelper => "Helper API", "API do helper";
    StepAllowlist => "Caller allowlist", "Lista de permissões de chamadores";
    StepAttestation => "Attestation and logging", "Atestação e logs";

    FieldLog => "Log level", "Nível de log";
    HelpLog => "tracing directive, e.g. info or mia=debug,info", "diretiva do tracing, por exemplo info ou mia=debug,info";
    FieldCmisEndpoint => "CMIS endpoint", "Endpoint do CMIS";
    HelpCmisEndpoint => "A single https://host:port. Leave blank when using an SRV record.", "Um único https://host:porta. Deixe em branco ao usar um registro SRV.";
    FieldCmisSrv => "CMIS SRV record", "Registro SRV do CMIS";
    HelpCmisSrv => "DNS SRV name such as _cmis._tcp.example.com, for a high-availability cluster.", "Nome SRV de DNS como _cmis._tcp.example.com, para um cluster de alta disponibilidade.";
    FieldCmisSpkiPin => "CMIS SPKI pin", "Pin SPKI do CMIS";
    HelpCmisSpkiPin => "Hex SHA-384 of the CMIS public key (96 characters), from your operator.", "SHA-384 em hexadecimal da chave pública do CMIS (96 caracteres), fornecido pelo operador.";
    FieldHelperSocket => "Helper socket / pipe", "Socket / pipe do helper";
    HelpHelperSocket => "Where local applications request tokens; leave blank for the platform default.", "Onde as aplicações locais solicitam tokens; deixe em branco para usar o padrão da plataforma.";
    FieldHelperSocketMode => "Socket mode (Unix)", "Modo do socket (Unix)";
    HelpHelperSocketMode => "Octal file mode of the helper socket, e.g. 660.", "Modo octal do socket do helper, por exemplo 660.";
    FieldHelperWindowsGroup => "Pipe group (Windows)", "Grupo do pipe (Windows)";
    HelpHelperWindowsGroup => "Local group allowed to open the helper pipe, e.g. FerroGateClients.", "Grupo local autorizado a abrir o pipe do helper, por exemplo FerroGateClients.";
    FieldAllowlistPath => "Allowlist file", "Arquivo da lista de permissões";
    HelpAllowlistPath => "Path of the signed caller allowlist; leave blank for the platform default.", "Caminho da lista de permissões assinada; deixe em branco para usar o padrão da plataforma.";
    FieldAllowlistKey => "Enrollment public key file (destination)", "Arquivo da chave pública de registro (destino)";
    HelpAllowlistKey => "Path where the CMIS enrollment public key is stored or will be fetched; without it every caller is denied.", "Caminho onde a chave pública de registro do CMIS está ou será salva; sem ela todo chamador é negado.";
    FieldEnrollmentKeyFingerprint => "Expected enrollment key fingerprint (text)", "Fingerprint esperado da chave de registro (texto)";
    HelpEnrollmentKeyFingerprint => "Optional 96-character hex fingerprint printed by `ferrogate enrollment-key`; when set, nothing is written unless the fetched key matches.", "Fingerprint hexadecimal opcional de 96 caracteres exibido por `ferrogate enrollment-key`; quando preenchido, nada é gravado se a chave obtida não corresponder.";
    FieldAllowlistMaxAge => "Allowlist maximum age (seconds)", "Idade máxima da lista de permissões (segundos)";
    HelpAllowlistMaxAge => "Oldest allowlist accepted, in seconds; blank for the default.", "Lista de permissões mais antiga aceita, em segundos; em branco para o padrão.";
    FieldAllowlistFetch => "Fetch the allowlist from CMIS at startup", "Obter a lista de permissões do CMIS ao iniciar";
    HelpAllowlistFetch => "allowlist.fetch — keeps the file in sync with what the operator provisioned.", "allowlist.fetch — mantém o arquivo sincronizado com o que o operador provisionou.";
    FieldAllowlistPropose => "Propose observed callers to CMIS", "Propor ao CMIS os chamadores observados";
    HelpAllowlistPropose => "allowlist.propose — lets a fresh host bootstrap its allowlist.", "allowlist.propose — permite que um host novo inicialize sua lista de permissões.";
    FieldImaLog => "IMA log path (Linux)", "Caminho do log IMA (Linux)";
    HelpImaLog => "Override of the IMA runtime-measurement log; usually blank.", "Substitui o log de medições do IMA; normalmente em branco.";
    FieldAttestationBackend => "Attestation backend", "Backend de atestação";
    HelpAttestationBackend => "auto: TPM when present, else host-key. virtual-tpm is INSECURE (development only).", "auto: TPM quando presente, senão host-key. virtual-tpm é INSEGURO (apenas desenvolvimento).";

    ValTooLong => "too long (at most 4096 bytes)", "muito longo (no máximo 4096 bytes)";
    ValLiteral => "must not contain a single quote (') or control characters", "não pode conter aspas simples (') nem caracteres de controle";
    ValSrv => "an SRV owner name, e.g. _cmis._tcp.example.com", "um nome SRV, por exemplo _cmis._tcp.example.com";
    ValEndpoint => "must start with https:// or http:// (or be left blank)", "deve começar com https:// ou http:// (ou ficar em branco)";
    ValPin => "must be a hex SHA-384 (96 hex characters), or blank", "deve ser um SHA-384 em hexadecimal (96 caracteres), ou em branco";
    ValOctal => "not an octal mode (e.g. 660)", "não é um modo octal (por exemplo 660)";
    ValUint => "must be a whole number of seconds", "deve ser um número inteiro de segundos";
    ValBackend => "must be one of auto, tpm, host-key, virtual-tpm", "deve ser auto, tpm, host-key ou virtual-tpm";
    ValLogDirective => "not a valid log directive (e.g. info or mia=debug,info)", "diretiva de log inválida (por exemplo info ou mia=debug,info)";
    ValEndpointSrvExclusive => "set either the endpoint or the SRV record, not both", "defina o endpoint ou o registro SRV, não ambos";
    ValPinRequired => "required with an https:// endpoint or an SRV record", "obrigatório com um endpoint https:// ou um registro SRV";
    ValKeyRequired => "required whenever the allowlist file is set", "obrigatório sempre que o arquivo da lista de permissões for definido";
    ValKeyRequiredForFetch => "choose a destination file to fetch the enrollment key", "escolha um arquivo de destino para obter a chave de registro";
    ValEnrollmentKeyFingerprint => "must be the full 96-character hex fingerprint printed by `ferrogate enrollment-key`", "deve ser o fingerprint hexadecimal completo de 96 caracteres exibido por `ferrogate enrollment-key`";
    ValDraftTooLarge => "the draft is larger than 64 KiB", "o rascunho é maior que 64 KiB";

    LogsLevel => "Level", "Nível";
    LogsAll => "All", "Todos";
    LogsSearch => "Search", "Buscar";
    LogsFollow => "Follow", "Acompanhar";
    LogsPaused => "Paused — {n} new record(s)", "Pausado — {n} registro(s) novo(s)";
    LogsGap => "… {n} record(s) dropped by the agent's buffer …", "… {n} registro(s) descartado(s) pelo buffer do agente …";
    LogsRestarted => "— the agent restarted —", "— o agente reiniciou —";
    LogsOpenFull => "Open full log", "Abrir log completo";
    LogsSaveBundle => "Save diagnostics bundle…", "Salvar pacote de diagnóstico…";
    LogsBundleSaved => "Diagnostics bundle saved.", "Pacote de diagnóstico salvo.";
    LogsBundleFailed => "Could not save the diagnostics bundle.", "Não foi possível salvar o pacote de diagnóstico.";
    LogsUnavailable => "The log tail is unavailable: the agent is not reachable.", "O log não está disponível: o agente está inacessível.";
    LogsJournalNote => "On Linux the full log is the systemd journal (journalctl -u mia). Reading it needs membership in the systemd-journal or adm group — ask an administrator to add you; the tray does not elevate for this.", "No Linux o log completo é o journal do systemd (journalctl -u mia). Lê-lo requer participação no grupo systemd-journal ou adm — peça a um administrador para incluí-lo; o tray não pede elevação para isso.";
    LogsNoViewer => "No log viewer could be started; run: journalctl -u mia -f", "Não foi possível abrir um visualizador; execute: journalctl -u mia -f";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_has_both_languages() {
        for m in Msg::ALL {
            for lang in [Lang::En, Lang::Pt] {
                assert!(!m.text(lang).trim().is_empty(), "{m:?} empty in {lang:?}");
            }
            // Placeholders must match between languages.
            let holes = |s: &str| {
                let mut v: Vec<String> = s
                    .split('{')
                    .skip(1)
                    .filter_map(|p| p.split_once('}').map(|(k, _)| k.to_string()))
                    .collect();
                v.sort();
                v
            };
            assert_eq!(holes(m.text(Lang::En)), holes(m.text(Lang::Pt)), "{m:?}");
        }
    }

    #[test]
    fn language_detection() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        assert_eq!(
            Lang::detect_from(env(&[("LANG", "pt_BR.UTF-8")]), None),
            Lang::Pt
        );
        assert_eq!(
            Lang::detect_from(env(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "pt_BR")]), None),
            Lang::En
        );
        assert_eq!(
            Lang::detect_from(env(&[("LANGUAGE", "fr:pt_PT:en")]), None),
            Lang::Pt
        );
        assert_eq!(Lang::detect_from(env(&[]), Some("pt-BR".into())), Lang::Pt);
        assert_eq!(Lang::detect_from(env(&[]), Some("de-DE".into())), Lang::En);
        assert_eq!(Lang::detect_from(env(&[("LANG", "")]), None), Lang::En);
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(
            fill(
                Msg::MenuForEnv.text(Lang::En),
                &[("action", "Run"), ("env", "prod")]
            ),
            "Run (prod)"
        );
    }
}
