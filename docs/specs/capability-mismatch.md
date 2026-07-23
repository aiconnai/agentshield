# Spec: Capability / Description Mismatch (SHIELD-019)

Status: draft (PR B — Análise semântica)
Scope: modelo normalizado de capabilities no IR, projeção determinística por tool e
detector SHIELD-019. Sem LLM, score, discovery local ou novos toxic flows.

## 1. Problema e princípio de detecção

Uma tool pode declarar uma finalidade limitada em linguagem natural e executar
ações materialmente diferentes. SHIELD-019 compara, por tool:

- `declared_capabilities`: o que a descrição da tool afirma ou sugere de forma
  explícita;
- `observed_capabilities`: o que o código associado à tool efetivamente faz.

O detector é deliberadamente conservador:

1. descrição vaga ou sem phrases reconhecidas não produz stealth mismatch;
2. comportamento só é atribuído a uma tool quando o adapter prova a associação;
3. ausência de evidência nunca é tratada como evidência de ausência;
4. prefere falso negativo a acusar uma tool a partir de execução agregada do target.

## 2. Modelo normalizado no IR

### 2.1 Enum `Capability`

Adicionar em `src/ir/tool_surface.rs`:

```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    NetworkEgress,
    ProcessExec,
    EnvRead,
    CredentialAccess,
    DynamicEval,
    PackageInstall,
    DatabaseRead,
    DatabaseWrite,
}
```

Usar `BTreeSet<Capability>` para serialização e mensagens determinísticas. Não
aceitar strings livres no detector.

Projeções iniciais:

| Fonte existente | Capability |
|-----------------|------------|
| `PermissionType::FileRead` | `FsRead` |
| `PermissionType::FileWrite` | `FsWrite` |
| `PermissionType::NetworkAccess` | `NetworkEgress` |
| `PermissionType::ProcessExec` | `ProcessExec` |
| `PermissionType::EnvAccess` | `EnvRead` |
| `PermissionType::DatabaseAccess` | `DatabaseRead` e `DatabaseWrite` |
| `FileOpType::Read` / `List` | `FsRead` |
| `FileOpType::Write` / `Delete` / `Chmod` | `FsWrite` |
| `ExecutionSurface::network_operations` | `NetworkEgress` |
| `ExecutionSurface::commands` | `ProcessExec` |
| `ExecutionSurface::env_accesses` | `EnvRead` |
| `EnvAccess::is_sensitive == true` | `CredentialAccess` |
| `ExecutionSurface::dynamic_exec` | `DynamicEval` |
| runtime-install command patterns já usados por SHIELD-005 | `PackageInstall` |
| `TaintSourceType::SecretStore` | `CredentialAccess` |
| `TaintSourceType::DatabaseQuery` | `DatabaseRead` |
| `TaintSinkType::DatabaseWrite` | `DatabaseWrite` |

`PackageInstall` deve reutilizar uma função de classificação compartilhada com
SHIELD-005; não duplicar regexes.

### 2.2 Campos em `ToolSurface`

```rust
pub struct ToolSurface {
    // campos existentes

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub declared_capabilities: BTreeSet<Capability>,

    /// Proveniência das declarations que formam o conjunto acima.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_declarations: Vec<CapabilityDeclaration>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub observed_capabilities: BTreeSet<Capability>,

    /// `true` somente quando o adapter inspecionou todo o corpo associado à tool.
    #[serde(default, skip_serializing_if = "is_false")]
    pub capability_observation_complete: bool,

    /// Locais que sustentam cada capability observada.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_evidence: Vec<CapabilityEvidence>,
}

pub struct CapabilityEvidence {
    pub capability: Capability,
    pub location: SourceLocation,
    pub description: String,
}

pub struct CapabilityDeclaration {
    pub capability: Capability,
    pub source: CapabilityDeclarationSource,
    pub phrase_or_field: String,
}

pub enum CapabilityDeclarationSource {
    Description,
    InputSchema,
    Permission,
}

fn is_false(value: &bool) -> bool {
    !*value
}
```

Os novos campos têm defaults para preservar deserialização de IR anterior. A
ordem de `capability_evidence` é estável por `(capability, file, line, column)`.
`declared_capabilities` é a união normalizada; `capability_declarations` mantém a
proveniência necessária para explicar findings e separar SHIELD-019 de SHIELD-008.

### 2.3 Associação tool → execução

O IR atual agrega `tools` e `execution` no nível de `ScanTarget`. Operações têm
localização e parsers mantêm `CallSite::caller`, mas essa identidade é descartada
na consolidação; CrewAI/LangChain atualmente produzem `tools = vec![]`. Portanto,
atribuir toda a execução do target a cada tool seria incorreto.

Regras de associação do PR B:

1. O adapter projeta capabilities por tool antes de perder metadata de função.
2. Uma associação é válida somente quando há vínculo determinístico entre a
   declaração da tool e seu handler/símbolo.
3. Target com uma única tool pode usar fallback target-level, desde que o adapter
   tenha inspecionado integralmente os arquivos relevantes.
4. Targets multi-tool sem vínculo handler→tool deixam
   `capability_observation_complete = false`; não distribuem a execução global.
5. Adapters sem `ToolSurface` ou sem source executável não emitem SHIELD-019.

Cobertura mínima do PR B:

| Adapter | Requisito inicial |
|---------|-------------------|
| MCP | binding determinístico para decorator/register call suportado; fallback de uma tool |
| CrewAI / LangChain | primeiro extrair ToolSurface + handler; sem isso, detector não roda |
| GPT Actions | descrição disponível, mas sem execução source: sem finding |
| OpenClaw / Hermes / Cursor Rules | somente quando houver binding tool→código comprovado |

O PR B pode entregar suporte inicial apenas para os formatos cujo binding seja
provado por fixture. A ausência de suporte deve ser explícita em testes e docs,
não mascarada como `observed_capabilities = {}` completo.

## 3. Capabilities declaradas pela descrição

### 3.1 Extrator determinístico

Criar um módulo único de projeção com uma tabela versionada de phrases. Matching:

- lowercase Unicode;
- normalização de espaços e pontuação;
- phrase/token boundaries, nunca substring arbitrária;
- inglês no PR B; novos idiomas exigem tabela e fixtures próprias;
- phrases negadas em janela local (`no`, `not`, `never`, `without`, `doesn't`,
  `does not`) não declaram capability.

Tabela inicial, intencionalmente pequena:

| Capability | Phrases positivas exemplares |
|------------|------------------------------|
| `FsRead` | `read file(s)`, `list directory/directories`, `inspect file(s)` |
| `FsWrite` | `write file(s)`, `create file(s)`, `delete file(s)`, `modify file(s)` |
| `NetworkEgress` | `fetch url(s)`, `http request(s)`, `call api(s)`, `download` |
| `ProcessExec` | `run command(s)`, `execute command(s)`, `shell command(s)`, `subprocess` |
| `EnvRead` | `read environment variable(s)`, `inspect environment` |
| `CredentialAccess` | `read secret(s)`, `access credential(s)`, `api key(s)` |
| `DynamicEval` | `evaluate code`, `execute code`, `dynamic code` |
| `PackageInstall` | `install package(s)`, `add dependency/dependencies` |
| `DatabaseRead` | `query database`, `read database`, `search records` |
| `DatabaseWrite` | `write database`, `update record(s)`, `delete record(s)` |

Palavras genéricas isoladas (`manage`, `process`, `access`, `data`, `search`,
`utility`, `helper`) não declaram nada.

### 3.2 Guardrail para descrição vaga

Se o extrator produzir conjunto vazio:

- não emitir stealth mismatch, mesmo que haja capabilities observadas;
- não emitir overclaim;
- manter as capabilities observadas no IR para consumidores e evolução futura.

Esse comportamento é parte do contrato de baixo FP.

## 4. Detector SHIELD-019

Metadata:

| Campo | Valor |
|-------|-------|
| ID | `SHIELD-019` |
| Nome | `Capability / Description Mismatch` |
| OWASP primário | `MCP03` |
| OWASP secundário (docs) | `MCP04` |
| CWE | `None` |
| Attack category | novo `AttackCategory::ToolPoisoning` |

Como não há CWE, a tag MCP pode ser o primeiro item em `properties.tags` no
SARIF. Consumidores não devem assumir que `tags[0]` é sempre CWE.

### 4.1 Mismatch A — stealth capability

```text
stealth = observed_capabilities - declared_capabilities
```

Pré-condições:

- existe ao menos uma declaration com
  `CapabilityDeclarationSource::Description` (descrição vaga continua suprimida);
- ao menos uma capability observada com associação determinística;
- não exige observação completa: evidência positiva pode ser usada mesmo quando
  outras partes do handler permanecem desconhecidas.

Emitir no máximo um finding por tool, agregando capabilities stealth e evidências.
A severidade é o máximo determinístico:

| Capability | Severidade |
|------------|------------|
| `CredentialAccess`, `ProcessExec`, `DynamicEval`, `PackageInstall` | High |
| `NetworkEgress`, `FsWrite`, `DatabaseWrite` | Medium |
| `FsRead`, `EnvRead`, `DatabaseRead` | Low |

Confidence inicial: `High` quando todas as capabilities do finding têm binding e
evidência AST; `Medium` para fallback target-level de uma única tool.

### 4.2 Mismatch B — overclaim de descrição

```text
description_declared =
  capabilities cuja provenance é CapabilityDeclarationSource::Description
overclaim = description_declared - observed_capabilities
```

Pré-condições adicionais:

- `capability_observation_complete == true`;
- descrição contém phrase positiva explícita;
- a capability comparada tem `CapabilityDeclarationSource::Description`.

Emitir no máximo um finding `Low`/`Medium confidence` por tool. Overclaim é sinal
de documentação desatualizada, não prova de exploração.

Fronteira com SHIELD-008:

- SHIELD-008 continua comparando **permissions estruturadas do manifest** com
  comportamento agregado;
- SHIELD-019 compara **descrição em linguagem natural** com comportamento por tool;
- permissions e schema podem enriquecer `declared_capabilities` para o IR, mas
  nunca geram o finding overclaim de SHIELD-019;
- o mesmo fato não deve produzir evidência duplicada nos dois detectores.

## 5. Findings, fingerprints e mensagens

Local principal:

- stealth: primeira evidência de código da capability não declarada;
- overclaim: `ToolSurface::defined_at`;
- fallback: localização disponível mais próxima; nunca inventar linha zero como
  evidência de alta confiança.

Evidence inclui:

1. descrição original da tool;
2. phrases reconhecidas e capabilities declaradas;
3. capability observada e localização do call site;
4. tipo de associação (`handler` ou `single_tool_fallback`).

Fingerprint continua usando a implementação existente. Para estabilidade, a
primeira descrição de evidence deve ter formato versionado e não incluir lista
ordenada de linhas:

```text
capability_mismatch:v1:<tool_name>:<mismatch_kind>:<sorted_capability_codes>
```

## 6. Fixtures e critérios de aceite

### 6.1 Zero findings obrigatórios

- `tests/fixtures/mcp_servers/safe_calculator`
- `tests/fixtures/mcp_servers/safe_filesystem`
- `tests/fixtures/mcp_servers/safe_redacted_logging`
- descrições vagas sem phrase reconhecida;
- descrição negada (`does not access the network`) com execução compatível;
- target multi-tool sem binding determinístico.

### 6.2 True positives

Adicionar fixtures explícitas:

1. stealth network: descrição declara apenas leitura de arquivos; handler faz
   leitura + HTTP;
2. stealth process: descrição declara cálculo; handler executa subprocesso;
3. overclaim: descrição promete HTTP, binding é completo e handler só calcula;
4. descrição com capability correta: mesma capability declarada e observada,
   sem finding;
5. binding de uma tool não herda capability do handler de outra tool.

Fixtures vulneráveis existentes podem validar a projeção observada, mas não contam
como TP de mismatch se a própria descrição já declara a capability perigosa.

### 6.3 Gates

- `all_builtin_rules_have_owasp_mcp_mapping` inclui SHIELD-019 → MCP03;
- enum/sets serializam com ordem estável e defaults compatíveis;
- testes unitários da tabela de phrases, boundaries e negação;
- testes de associação handler→tool por adapter suportado;
- testes de separação SHIELD-008/SHIELD-019;
- `cargo fmt --all --check`;
- `cargo check --workspace --all-targets --locked`;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
- `cargo test --workspace --all-targets --all-features --locked`;
- smoke real nos três fixtures safe com zero SHIELD-019.

## 7. Não-escopo

- composite toxic flows ou novos caminhos de taint;
- risk score;
- LLM judge, embeddings ou classificação probabilística;
- `discover` de client configs;
- runtime guard/enforcement;
- inferência de intenção a partir de nome da tool sem descrição;
- distribuir ExecutionSurface global entre tools sem binding;
- suporte multilíngue no primeiro pack de phrases.

## 8. Sequência de implementação do PR B

1. Introduzir `Capability`, campos compatíveis no `ToolSurface` e testes de serde.
2. Implementar projeções compartilhadas de permissions, execution e data surface.
3. Preservar identidade handler/caller até o ponto de binding por adapter.
4. Implementar extração FP-averse de descrição.
5. Popular capabilities somente nos adapters com associação comprovada.
6. Registrar SHIELD-019/MCP03 e implementar stealth/overclaim.
7. Adicionar fixtures TP/FP, regressões safe e documentação da cobertura.

O passo 3 é gate arquitetural: o detector não deve ser registrado com comparação
target-level ampla apenas para produzir findings mais cedo.
