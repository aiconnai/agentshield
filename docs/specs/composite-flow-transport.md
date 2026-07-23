# Decision: Composite Flow Transport

Status: proposed (C.0 → C.1 architecture gate)

Scope: decidir como candidates crate-private produzidos pela análise de value
flow chegam ao detector SHIELD-020 sem alterar os contratos públicos ou
serializados atuais. Este documento não registra o detector, não cria findings
e não muda fingerprints.

## 1. Contexto

C.0 introduziu `build_composite_flow_candidates` como uma primitive
crate-private e provou por testes que o grafo preserva:

- identidade de valor por definição/version;
- ownership por tool;
- arestas tipadas de path controlado, file content e network payload;
- limites conservadores de escopo, reassignment, shadowing e depth.

O pipeline público, porém, transporta somente `Vec<ScanTarget>`:

```text
Adapter::load
  -> auto_detect_and_load_with_filter
  -> Vec<ScanTarget>
  -> RuleEngine::run(&ScanTarget)
```

Os dados necessários para construir o grafo MCP — em especial o binding
tool → handler — são conhecidos dentro do adapter e descartados antes de
`RuleEngine::run`. Eles não podem ser reconstruídos corretamente a partir da
`ExecutionSurface` agregada.

Os seguintes contratos já são públicos e devem permanecer estáveis em C.1:

- `Adapter::load(...) -> Result<Vec<ScanTarget>>`;
- `auto_detect_and_load*() -> Result<Vec<ScanTarget>>`;
- `ScanTarget` e seus campos serializados;
- `Detector::run(&ScanTarget)`;
- `RuleEngine::run(&ScanTarget)`;
- `ScanReport::targets`.

## 2. Decisão

Adotar um **analysis bundle crate-private** como sidecar do `ScanTarget` no
pipeline interno de scan.

```rust
pub(crate) struct AnalysisBundle {
    pub target: ScanTarget,
    pub composite_flows: Vec<CompositeFlowCandidate>,
}

pub(crate) struct DetectionInput<'a> {
    pub target: &'a ScanTarget,
    pub composite_flows: &'a [CompositeFlowCandidate],
}
```

O bundle é ownership de pipeline, não IR público. Ele existe somente entre o
load do adapter e a execução das regras, não implementa `Serialize`/
`Deserialize` e não é retornado em `ScanReport`.

### 2.1 Loading interno

Adicionar uma lane crate-private para built-in adapters:

```rust
trait AnalysisAdapter: Send + Sync {
    fn framework(&self) -> Framework;
    fn detect(&self, root: &Path) -> bool;
    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>>;
}
```

Essa trait não substitui nem é exposta pela trait pública `Adapter`.

- MCP usa um único caminho de load interno que constrói `ScanTarget` e
  candidates a partir das mesmas declarations, parsed files e bindings.
- O contrato C.1.0 aceita os dois parser-pass existentes hoje: parser normal MCP
  para construir `ScanTarget` e parser de fluxo composto para `build_composite_flow_candidates`;
  o requisito é que `build_composite_flow_candidates` execute no máximo uma vez por bundle.
- Os métodos públicos de MCP projetam esse resultado para `Vec<ScanTarget>`,
  descartando a sidecar.
- Outros built-in adapters inicialmente embrulham cada target em um bundle com
  `composite_flows = []`.
- `auto_detect_and_load_with_filter` reutiliza a lane interna e projeta os
  bundles para targets, preservando sua assinatura e semântica pública.
- `scan()` consome diretamente os bundles. A partir deste ponto, não há reparsing no detector para atender SHIELD-020.

A ordem de adapters, comportamento de detecção, path filtering e política de
erro permanecem iguais à função pública atual.

### 2.1.1 Registro de adapters em uma fonte de verdade

- O registro de `Adapter` público e `AnalysisAdapter` interno nasce do mesmo
  conjunto canônico de descritores de framework, ordenado determinísticamente.
- Uma camada de projeção interna deve derivar cada visão (`all_adapters` e
  `all_analysis_adapters`) desse mesmo conjunto.
- Se a projeção não vier de um único descritor, C.1.0 exige teste de
  integridade na ordem e no conteúdo dos frameworks para impedir drift entre
  os registries.

Implementações externas de `Adapter` não precisam implementar
`AnalysisAdapter`; a lane é deliberadamente limitada aos built-ins registrados
por AgentShield.

### 2.2 Execução de regras

Manter a trait pública `Detector` e os detectors SHIELD-001..019 inalterados.
Adicionar uma lane crate-private para regras que exigem sidecars:

```rust
pub(crate) trait ContextDetector: Send + Sync {
    fn metadata(&self) -> RuleMetadata;
    fn run(&self, input: &DetectionInput<'_>) -> Vec<Finding>;
}
```

`RuleEngine` mantém duas coleções internas:

- `detectors`: a coleção pública atual;
- `context_detectors`: detectors que dependem de analysis sidecars.

Para manter contrato claro entre execução e catálogo:

- `RuleEngine::run(&ScanTarget)` e `RuleEngine::list_rules()` operam apenas em
  `detectors` e continuam em total alinhamento público.
- Um registro interno de scanner mantém metadados de:
  - regras públicas (`detectors`);
  - regras contextuais (`context_detectors`), incluindo `run` apenas via `scan()`.

Comportamento:

- `RuleEngine::run(&ScanTarget)` continua executando somente o contrato que pode
  ser provado pelo target público e preserva o resultado atual;
- um novo `pub(crate) RuleEngine::run_with_context(&DetectionInput)` executa os
  detectors públicos contra `input.target` e os context detectors contra o
  bundle;
- `scan()` usa `run_with_context`;
- `scan()` e o pipeline de saída (CLI, SARIF, certification) consomem o
  registro de scanner completo para expor `context_detectors` também.

SHIELD-020 pertence exclusivamente a `context_detectors`. Ele nunca repassa source e nunca tenta inferir uma chain a partir do target agregado.

## 3. Lifecycle e invariantes

Para cada bundle:

1. o adapter lê e parseia cada source para o parse normal MCP;
2. se habilitado e suportado, o parser de fluxo composto é executado uma vez para construir candidates;
3. constrói o `ScanTarget` público;
4. enquanto declarations e handler bindings ainda existem, constrói os
   `ToolFlowInput` e candidates; não há reparsing adicional aqui;
5. move target e candidates para o bundle;
6. `scan()` cria um `DetectionInput` emprestado;
7. o engine produz findings;
8. a sidecar é descartada antes de montar `ScanReport`.

Invariantes obrigatórios:

- candidate e target vêm do mesmo root, path filter e invocation;
- nenhum estado global/thread-local guarda sidecar;
- construção de candidates é não-fallível (faltas estruturais, ambiguidade,
  parse por unidade inválido, feature/parser indisponível ou unsupported
  source retorna `composite_flows = []`);
- ausência de candidates significa “sem prova de fluxo composto”;
- candidatos não cruzam targets, adapters ou invocations;
- ordenação de bundles e candidates é determinística;
- `ScanTarget` continua preservado mesmo com sidecar vazia; o `ScanReport` segue idêntico;
- nenhum field, schema JSON/SARIF/HTML, attestation ou fingerprint existente
  muda apenas por introduzir o transporte.

## 4. Compatibilidade

### 4.1 APIs públicas

C.1 não muda assinaturas públicas nem exige novos fields em struct literals de
`ScanTarget`. Chamadores que usam diretamente:

```rust
adapter.load(...)
RuleEngine::run(&target)
```

continuam compilando e recebem o comportamento anterior. SHIELD-020 é um
detector do pipeline completo `scan()`, porque sua prova depende de contexto
intencionalmente não representado no IR público.

Expor contextual detection para library consumers fica fora de C.1. Uma futura
API pública exige proposta própria de semver, ownership e serialization; não
deve tornar `CompositeFlowCandidate` público por acidente.

### 4.2 Formatos e fingerprints

O bundle e seus candidates não são serializados. Somente findings emitidos por
SHIELD-020 entram nos outputs existentes quando o detector for registrado.

Adicionar SHIELD-020 altera naturalmente o catálogo completo de scanner usado por
`scan()`/CLI/SARIF/attestation, mas não modifica findings ou fingerprints das
regras SHIELD-001..019 nem o contrato de `RuleEngine::list_rules()`.

## 5. Alternativas rejeitadas

### Campo em `ScanTarget`

Rejeitado porque mistura analysis sidecar com IR cross-framework, altera uma
struct pública usada em literals e cria risco de schema/attestation drift,
mesmo com `#[serde(skip)]`.

### Mudar `Detector::run`

Rejeitado em C.1 porque a trait é pública. Substituir `&ScanTarget` por um
contexto quebra implementações externas e todos os detectors existentes.

### Reparse no detector

Rejeitado porque duplica parser, binding e path filtering, pode divergir do
target analisado e adiciona custo em cada execução da regra.

### Cache global ou thread-local

Rejeitado por lifecycle implícito, colisão entre scans, concorrência,
invalidação e testes não isolados.

### Correlação somente por `ScanTarget`

Rejeitado porque a execution surface é target-wide e não preserva handler,
`ValueId` nem payload identity. Coocorrência não prova chain.

### Tornar todo o IR de value flow público

Rejeitado para o MVP: fixa cedo um schema de SSA/value graph ainda estreito ao
MCP TypeScript e amplia a superfície de compatibilidade sem consumidor público
estável.

## 6. Plano de implementação

### C.1.0 — Transporte, sem detector

1. introduzir `AnalysisBundle`, `DetectionInput` e `AnalysisAdapter`;
2. refatorar MCP para produzir target + sidecar em um único load;
3. embrulhar demais built-ins com sidecar vazia;
4. fazer `scan()` consumir bundles via `run_with_context`;
5. manter `context_detectors` vazio e provar zero mudança em findings;
6. testar public adapter API, public engine API e serialization invariantes.

### C.1.1 — SHIELD-020

1. implementar `ContextDetector` para os candidates já transportados;
2. registrar metadata SHIELD-020/MCP06;
3. produzir evidence e fingerprint conforme a spec de toxic flows;
4. adicionar fixtures TP/FP, multi-tool e feature-off;
5. atualizar `docs/RULES.md` e o mapa OWASP;
6. provar que SHIELD-004 e SHIELD-020 coexistem sem evidence duplicada.

O split é obrigatório: C.1.0 deve ser behavior-preserving e revisável antes de
qualquer novo finding.

## 7. Critérios de aceite da decisão

- [ ] nenhum contrato público listado na seção 1 muda;
- [ ] construção de `composite_flows` por `build_composite_flow_candidates` é invocada no máximo uma vez por bundle MCP suportado;
- [ ] MCP preserva declarations/bindings até construir os candidates;
- [ ] outros adapters produzem bundle vazio sem comportamento especial;
- [ ] `RuleEngine::run(&ScanTarget)` mantém resultados byte-for-byte
      equivalentes;
- [ ] `RuleEngine::list_rules()` permanece alinhada a `RuleEngine::run()`;
- [ ] catálogo completo usado por scan/CLI/SARIF/attestation está no registro de scanner interno;
- [ ] serialização de `ScanTarget` e `ScanReport::targets` permanece idêntica;
- [ ] scans concorrentes não compartilham state;
- [ ] feature `typescript` desligada produz sidecar vazia e zero SHIELD-020;
- [ ] C.1.0 não registra SHIELD-020 no catálogo público (`RuleEngine::list_rules`);
- [ ] C.1.0 não faz parse adicional em detector para SHIELD-020;
- [ ] C.1.1 só começa após review e merge de C.1.0.
