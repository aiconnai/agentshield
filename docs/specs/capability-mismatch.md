# Spec: Capability / Description Mismatch (SHIELD-019)

Status: implemented for MCP TypeScript stealth and conservatively complete overclaim detection

Scope: modelo normalizado de capabilities no IR, projeção determinística por tool e
detector SHIELD-019. Sem LLM, score, discovery local ou novos toxic flows.

## 1. Problema e princípio de detecção

Uma tool pode declarar uma finalidade limitada em linguagem natural e executar
ações materialmente diferentes. SHIELD-019 compara, por tool:

- `declared_capabilities`: união normalizada do que description e permissions
  estruturadas declaram;
- `description_declared`: subconjunto com provenance `Description`, usado pelo
  detector para comparar a promessa em linguagem natural;
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
aceitar strings livres no detector. A ordem dos variants acima define a ordem
serializada e de apresentação dos conjuntos; não reordenar variants existentes.
Novos variants devem ser acrescentados ao final para preservar estabilidade.

Projeções iniciais:

| Fonte existente | Capability |
|-----------------|------------|
| `PermissionType::FileRead` | `FsRead` |
| `PermissionType::FileWrite` | `FsWrite` |
| `PermissionType::NetworkAccess` | `NetworkEgress` |
| `PermissionType::ProcessExec` | `ProcessExec` |
| `PermissionType::EnvAccess` | `EnvRead` |
| `PermissionType::DatabaseAccess` | `DatabaseRead` |
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

`PermissionType::DatabaseAccess` é projetada conservadoramente como
`DatabaseRead`: a permission atual não distingue leitura de escrita, e projetar
ambas superestimaria a declaração. Uma capability genérica de database fica fora
do PR B; uma futura distinção exige mudança no modelo de permissions.

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

No PR B, somente `Description` e `Permission` são projetadas.
`CapabilityDeclarationSource::InputSchema` fica reservado para evolução do IR e
não produz declaration: nomes como `url`, `path` ou `api_key` descrevem formato
de entrada, não autorização nem comportamento. Testes devem garantir zero
projeção a partir de schema no v1.

### 2.3 Associação tool → execução

O IR atual agrega `tools` e `execution` no nível de `ScanTarget`. Operações têm
localização e parsers mantêm `CallSite::caller`, mas essa identidade é descartada
na consolidação; CrewAI/LangChain atualmente produzem `tools = vec![]`. Portanto,
atribuir toda a execução do target a cada tool seria incorreto.

Pré-requisitos de adapter do PR B:

1. TypeScript/JavaScript: capturar description tanto no segundo argumento string
   quanto no objeto de configuração de `.tool(...)`/`.registerTool(...)`, e
   preservar a identidade do callback/terceiro argumento ou function expression.
2. Python: extrair `ToolSurface` para `@server.tool("name")`,
   `@server.tool(name=..., description=...)` e formas equivalentes suportadas;
   usar docstring como description somente quando não houver `description=`.
3. Preservar handler, `CallSite::caller` e localizações até a projeção por tool,
   em vez de descartar essa identidade no merge.
4. Resolver operações no corpo do handler e em callees in-project por um hop,
   alinhado ao limite atual da análise cross-file.

Regras de associação:

1. O adapter projeta capabilities por tool antes de perder metadata de função.
2. Uma associação é válida somente quando há vínculo determinístico entre a
   declaração da tool e seu handler/símbolo.
3. O escopo observado é o corpo do handler unido às operações de callees
   in-project resolvidos por um hop; operações de outro handler, setup,
   module-level side effects, `main` e dead code não são herdadas.
4. Targets multi-tool sem vínculo handler→tool deixam
   `capability_observation_complete = false`; não distribuem a execução global.
5. Adapters sem `ToolSurface` ou sem source executável não emitem SHIELD-019.
6. Fallback target-level de uma única tool é último recurso e só é permitido
   quando há exatamente uma tool, um único source file handler-like e nenhum
   outro entrypoint, setup/module-level operation ou símbolo executável não
   associado. O fallback tem confidence `Medium` e
   `capability_observation_complete = false`.

Cobertura mínima do PR B:

| Adapter | Requisito inicial |
|---------|-------------------|
| MCP TS/JS | config/string description + binding determinístico do callback de `.tool`/`.registerTool`; superfície inicial recomendada para fixtures MVP |
| MCP Python | decorator, nome, description/docstring e binding ao corpo antes de usar fixtures Python como aceite |
| CrewAI / LangChain | primeiro extrair ToolSurface + handler; sem isso, detector não roda |
| GPT Actions | descrição disponível, mas sem execução source: sem finding |
| OpenClaw / Hermes / Cursor Rules | somente quando houver binding tool→código comprovado |

O PR B pode entregar suporte inicial apenas para os formatos cujo binding seja
provado por fixture. A ausência de suporte deve ser explícita em testes e docs,
não mascarada como `observed_capabilities = {}` completo. Os fixtures Python
existentes (`safe_calculator`, `vuln_ssrf`, `vuln_cmd_inject`) não contam como
fixtures de SHIELD-019 enquanto o adapter não produzir `ToolSurface` e handler
para eles.

### 2.4 Completude operacional

`capability_observation_complete = true` somente quando:

1. o handler foi resolvido;
2. todo o corpo do handler foi analisado;
3. callees in-project foram resolvidos até profundidade 1 e seus corpos
   analisados;
4. não restaram calls potencialmente relevantes sem body no grafo;
5. não há execução dinâmica ou resolução opaca, incluindo `eval`,
   `require(dynamic)`, imports dinâmicos não literais ou wrappers externos de
   HTTP/process/filesystem que o classificador não consegue resolver.

Qualquer símbolo opaco relevante torna a observação incompleta. Evidência
positiva continua válida para stealth; incompletude sempre suprime overclaim.

## 3. Capabilities declaradas pela descrição

### 3.1 Extrator determinístico

Criar um módulo único de projeção com uma tabela versionada de phrases. Matching:

- lowercase Unicode;
- normalização de espaços e pontuação;
- phrase/token boundaries, nunca substring arbitrária;
- artigos comuns (`a`, `an`, `the`) são ignorados e somente uma lista fechada
  de infleções verbais simples é normalizada (`reads` → `read`, `fetches` →
  `fetch`, etc.);
- inglês no PR B; novos idiomas exigem tabela e fixtures próprias;
- phrases negadas quando um marcador (`no`, `not`, `never`, `without`,
  `doesn't`, `does not`) aparece nos quatro tokens anteriores não declaram
  capability; a janela para em limites de sentença/cláusula e em adversativos
  (`but`, `however`, `yet`).

Tabela inicial, intencionalmente pequena:

| Capability | Phrases positivas exemplares |
|------------|------------------------------|
| `FsRead` | `read file(s)`, `list directory/directories`, `inspect file(s)` |
| `FsWrite` | `write file(s)`, `create file(s)`, `delete file(s)`, `modify file(s)` |
| `NetworkEgress` | `fetch url(s)`, `http request(s)`, `call api(s)`, `download from`, `download url(s)` |
| `ProcessExec` | `run command(s)`, `execute command(s)`, `shell command(s)`, `subprocess` |
| `EnvRead` | `read environment variable(s)`, `inspect environment` |
| `CredentialAccess` | `read secret(s)`, `load secret(s)`, `access credential(s)`, `read api key(s) from store`, `load api key(s) from store` |
| `DynamicEval` | `evaluate arbitrary code`, `execute arbitrary code`, `dynamic code evaluation` |
| `PackageInstall` | `install package(s)`, `add dependency/dependencies` |
| `DatabaseRead` | `query database`, `read database`, `search records` |
| `DatabaseWrite` | `write database`, `update record(s)`, `delete record(s)` |

Palavras genéricas isoladas (`manage`, `process`, `access`, `data`, `search`,
`utility`, `helper`) não declaram nada.

`api key` sem verbo de leitura de secret store não declara
`CredentialAccess`: frases como “requires/accepts an API key” normalmente
descrevem um parâmetro fornecido pelo caller. Da mesma forma, `download` sem
origem HTTP/URL e `execute code` sem qualificador de execução dinâmica não
declaram capabilities. `download from` somente declara `NetworkEgress` quando
o objeto normalizado explicita `url`, `http`, `https` ou `web`; fontes locais
como disk, cache e local storage permanecem sem declaration de rede.

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
| OWASP secundário (docs) | nenhum |
| CWE | `None` |
| Attack category | novo `AttackCategory::CapabilityMismatch` |

Como não há CWE, a tag MCP pode ser o primeiro item em `properties.tags` no
SARIF. Consumidores não devem assumir que `tags[0]` é sempre CWE.

### 4.1 Mismatch A — stealth capability

```text
description_declared =
  capabilities cuja provenance é CapabilityDeclarationSource::Description
stealth = observed_capabilities - description_declared
```

Pré-condições:

- existe ao menos uma declaration com
  `CapabilityDeclarationSource::Description` (descrição vaga continua suprimida);
- ao menos uma capability observada com associação determinística;
- não exige observação completa: evidência positiva pode ser usada mesmo quando
  outras partes do handler permanecem desconhecidas.

Emitir no máximo um finding por tool, agregando capabilities stealth e evidências.
A união `declared_capabilities` permanece disponível no IR, mas declarations de
`Permission` e o variant reservado `InputSchema` nunca entram na subtração de
stealth. Assim, uma permission estruturada `NetworkAccess`, uma descrição que
declara somente leitura de arquivos e comportamento HTTP ainda produz stealth
`NetworkEgress`, que é o contrato MCP03 de descrição enganosa.

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
- permissions podem enriquecer `declared_capabilities` para o IR, mas não entram
  em stealth nem geram overclaim de SHIELD-019;
- input schema não é projetado no PR B;
- o mesmo fato não deve produzir evidência duplicada nos dois detectores.

Fixtures de separação devem provar eixos diferentes: SHIELD-008 cobre permission
estruturada versus uso agregado, enquanto SHIELD-019 cobre description versus
comportamento por tool. A implementação atual de SHIELD-008 trata qualquer file
operation como uso de FileRead e FileWrite; o teste não deve pressupor uma
granularidade que SHIELD-008 ainda não oferece.

## 5. Findings, fingerprints e mensagens

Cada tool produz de zero a dois findings SHIELD-019:

1. no máximo um `stealth`, agregando todas as capabilities stealth;
2. no máximo um `overclaim`, agregando todas as capabilities overclaimed.

Os dois kinds podem coexistir na mesma tool e compartilham o mesmo rule ID para
policy/suppression. A mensagem começa com `[stealth]` ou `[overclaim]` para que
console, SARIF, baseline e suppressions permaneçam legíveis. A attack category
única `CapabilityMismatch` cobre ambos sem classificar overclaim como poisoning.

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

Fingerprint continua usando a implementação existente. Para estabilidade,
`evidence[0].description` deve ter formato versionado e não incluir lista
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
6. permission declara network, description declara somente leitura de arquivos
   e handler faz HTTP: stealth `NetworkEgress`;
7. a mesma tool tem stealth e overclaim em capabilities distintas: dois findings
   com mensagens e fingerprints distintos.

Fixtures vulneráveis existentes podem validar a projeção observada, mas não contam
como TP de mismatch se a própria descrição já declara a capability perigosa.

### 6.3 Falsos positivos e gates negativos

- “Accepts/requires an API key and reads a local file” não declara
  `CredentialAccess` e não produz mismatch por essa phrase;
- `download` sem contexto HTTP/URL não declara `NetworkEgress`;
- `execute code review` e `execute code path` não declaram `DynamicEval`;
- description negada com marcador até quatro tokens antes da phrase não declara
  capability;
- single-tool com network apenas em setup, module-level side effect ou
  `if __name__ == "__main__"` não observa `NetworkEgress` para a tool;
- TS `.registerTool` com description em objeto preserva description e binding do
  callback;
- Python decorator + docstring só entra no aceite se a extração e o binding
  Python fizerem parte do MVP implementado;
- `capability_observation_complete = false` sempre suprime overclaim;
- input schema isolado produz zero capability declarations no v1.

### 6.4 Gates

- `all_builtin_rules_have_owasp_mcp_mapping` inclui SHIELD-019 → MCP03;
- enum/sets serializam com ordem estável e defaults compatíveis;
- testes unitários da tabela de phrases, boundaries e negação;
- testes de associação handler→tool por adapter suportado;
- testes de separação SHIELD-008/SHIELD-019, incluindo permission network que não
  suprime stealth description-only;
- teste multi-tool com paths de evidence provando que tool A não herda a
  capability da tool B;
- testes de fallback e completude operacional;
- teste de coexistência stealth + overclaim com dois fingerprints distintos;
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
3. Fechar os gaps do adapter MCP para o MVP:
   - TS/JS: description string/config object e identidade do callback;
   - Python, se incluído: decorator, nome, description/docstring e handler;
   - não contar fixtures Python como cobertura antes dessa extração.
4. Preservar identidade handler/caller e implementar o escopo
   handler + callees in-project por um hop.
5. Implementar extração FP-averse de descrição, incluindo boundaries, janela de
   negação e casos negativos de API key/download/dynamic eval.
6. Popular capabilities somente nos adapters com associação comprovada.
7. Registrar SHIELD-019/MCP03 e implementar stealth description-only e
   overclaim condicionado à completude.
8. Adicionar fixtures TP/FP, regressões safe e documentação da cobertura.

Os passos 3 e 4 são gates arquiteturais: o detector não deve ser registrado com
comparação target-level ampla apenas para produzir findings mais cedo. Se esses
work items crescerem além do PR B, devem sair como PR B.0 de adapter/binding,
mantendo SHIELD-019 desregistrado até sua conclusão.
