# Spec: Composite Toxic Flows

Status: proposed (PR C — contrato antes do IR e do detector)
Scope: definir o primeiro flow composto, seus gates de atribuição e os gaps de
IR necessários. Sem detector registrado, finding novo ou mudança de severidade
neste PR.

## 1. Problema

Findings isolados mostram operações perigosas, mas não provam que elas formam
uma cadeia. O valor de um toxic flow é demonstrar que:

1. uma origem controlável ou sensível produz um valor;
2. esse mesmo valor atravessa operações intermediárias identificáveis;
3. o valor alcança um sink de impacto;
4. toda a cadeia pertence à mesma tool.

Coocorrência por arquivo, target ou proximidade de linhas não satisfaz esse
contrato. O detector prefere falso negativo a combinar operações independentes.

## 2. Primeiro incremento: SHIELD-020

Nome proposto: **Arbitrary Read Exfiltration Chain**.

Chain mínima:

```text
ToolArgument
  -> FileRead(path controlado)
  -> FileContent(result value)
  -> HttpRequest(payload/body)
```

SHIELD-020 só emite quando todas as arestas acima são comprovadas. Em particular:

- o argumento controla o **path** da leitura sem containment/allowlist guard
  comprovado;
- a leitura produz uma identidade de valor;
- a mesma identidade, ou uma derivação rastreada dela, entra no payload de uma
  operação de rede com `sends_data = true`;
- leitura e envio pertencem à mesma tool por binding determinístico;
- não existe fallback target-level ou correlação por proximidade.

Esse flow é novo porque combina acesso arbitrário e exfiltração do conteúdo.
SHIELD-004 continua responsável pelo path controlado isolado; SHIELD-020 prova o
impacto adicional de o conteúdo lido sair do processo.

Para SHIELD-020, normalização (`path.resolve`, `normalize` ou equivalente) não
prova autorização. O edge `ControlsFilePath` só é elegível quando não existe
prova de containment em root permitido ou allowlist equivalente. Essa exigência
é deliberadamente mais forte que confiar apenas no nome de um sanitizer.

### 2.1 Metadata

| Campo | Valor |
|-------|-------|
| Rule ID | `SHIELD-020` |
| Nome | `Arbitrary Read Exfiltration Chain` |
| Severidade default | `High` |
| Confidence | `High` quando todas as arestas são explícitas |
| Attack category | `AttackCategory::DataExfiltration` |
| CWE | `CWE-200` |
| OWASP MCP primário | `MCP06` |
| OWASP MCP secundário (docs) | `MCP02` |

`CWE-200` representa o impacto de disclosure; `CWE-22` continua documentado em
SHIELD-004 como a fraqueza que habilita a leitura arbitrária.

O MVP emite `High`. Escalonar um finding individual para `Critical` exige prova
adicional de que o destino cruza uma trust/authorization boundary (por exemplo,
destino controlado pelo atacante ou explicitamente fora da policy permitida).
`sends_data = true` sozinho não prova essa boundary e não autoriza escalation.
C.1 v1 sempre emite `High`; escalation para `Critical` fica pós-MVP e exige
contrato, representação de boundary e fixtures próprios.

O teste de integridade `all_builtin_rules_have_owasp_mcp_mapping` deve continuar
verde quando SHIELD-020 for registrado.

## 3. Fronteiras com regras existentes

SHIELD-020 não reemite operações isoladas sob outro ID.

| Caso | Owner | SHIELD-020 |
|------|-------|------------|
| Tool argument controla path de file read/write | SHIELD-004 | não, sem exfil comprovada |
| Env/secret flui diretamente para HTTP/LLM | SHIELD-002 | não |
| URL controlada chega a request | SHIELD-003 | não |
| Download → file write → process exec | SHIELD-014 | não |
| File read e HTTP existem, mas usam valores diferentes | regras isoladas aplicáveis | não |
| Tool argument → file read → mesmo conteúdo → HTTP payload | SHIELD-020 | sim |

Se uma chain de SHIELD-020 também satisfizer SHIELD-004, ambos podem existir:
eles comunicam contratos diferentes. SHIELD-004 identifica a entrada arbitrária;
SHIELD-020 prova o impacto composto. O finding de SHIELD-020 deve referenciar
SHIELD-004 na evidência, sem copiar sua mensagem ou fingerprint.

## 4. IR de identidade e fluxo

O IR atual não consegue provar SHIELD-020:

- `FileOperation` preserva o argumento de path, mas não o valor retornado;
- `NetworkOperation` preserva URL e `sends_data`, mas não payload/body;
- `TaintPath` representa uma origem e um sink, porém não preserva identidade de
  valor, ownership por tool nem arestas tipadas;
- `build_data_surface` cria paths de um hop a partir do argumento do próprio
  sink, não conecta resultado de uma operação à seguinte.

O PR de implementação deve introduzir uma representação normalizada, sem usar
descrições humanas como chave. Um symbol não é uma identidade de valor:
reassignment e shadowing criam definições diferentes. Shape recomendado:

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ScopeId {
    relative_file: PathBuf,
    lexical_owner: LexicalOwnerId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DefinitionId {
    scope: ScopeId,
    definition_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ValueId {
    definition: DefinitionId,
    version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowEdgeKind {
    ControlsFilePath,
    ProducesFileContent,
    Propagates,
    EntersNetworkPayload,
}

pub(crate) struct CompositeFlowCandidate {
    tool_name: String,
    source: TaintSource,
    sink: TaintSink,
    edges: Vec<FlowEdge>,
    observation_complete: bool,
}
```

Os nomes são indicativos; o contrato é obrigatório:

- `ScopeId` usa relative file + owner lexical resolvido, não somente function
  name global;
- `ValueId` aponta para uma definição/version específica, não para um symbol
  scoped;
- symbol text é metadata de display e nunca chave de união;
- edges carregam `SourceLocation` e identidade de entrada/saída;
- candidate carrega ownership por tool;
- reassignment cria nova version e mata a propagação da version anterior;
- shadowing cria outro `DefinitionId`;
- merges condicionais, closures e múltiplas reaching definitions são opacos em
  v1 e não produzem candidate;
- o grafo e os candidates ficam crate-private em C.0 e não entram em
  `ScanTarget`, `DataSurface`, `ExecutionSurface`, `FileOperation` ou
  `NetworkOperation` serializados.

Não preencher `TaintPath::through` com locations não relacionadas apenas para
simular uma chain.

C.0 prova extração e graph construction por API crate-private + testes. O
transporte C.0 → C.1 é definido em
[`composite-flow-transport.md`](composite-flow-transport.md): sidecar
crate-private, lane interna de built-in adapters, registro de regras de scanner
separado e context detector separado, sem campo público/serializado nem mudança
do contrato `Detector`. Não duplicar parsing dentro de SHIELD-020 nem usar
cache global.

## 5. Extração mínima

### 5.1 File read

O parser/analyzer deve preservar:

- o `ArgumentSource` usado como path;
- a identidade do valor que recebe o resultado;
- a localização da leitura;
- o caller/handler associado.

A origem `ToolArgument` precisa ser provada, não inferida de qualquer
`ArgumentSource::Parameter`. Para o MVP MCP TypeScript:

- handler named/inline deve estar deterministicamente bound à tool;
- o primeiro parâmetro de input do callback (inclusive object destructuring)
  é ligado aos argumentos da tool;
- parâmetros adicionais de context/extra não são `ToolArgument`;
- ausência ou ambiguidade dessa ligação impede o candidate.

Formas mínimas de TypeScript para o MVP:

```typescript
const content = await readFile(path, "utf8")
const content = readFileSync(path, "utf8")
```

Destructuring, property assignment, streams e aliases importados ficam fora do
MVP até terem fixtures próprias.

As APIs produtoras também precisam ser resolvidas:

- imports conhecidos de `fs`/`node:fs` e members desses imports;
- global/user-defined function com o mesmo nome não conta;
- alias importado só entra depois de resolução explícita e fixture própria.

### 5.2 Network payload

`NetworkOperation` ou um side-table de análise deve preservar os argumentos que
carregam dados, separados de `url_arg`.

Formas mínimas:

```typescript
fetch(url, { method: "POST", body: content })
axios.post(url, content)
```

O booleano `sends_data` sozinho não prova que o file content foi enviado.
O object literal de `fetch` é uma regra específica de extração do campo `body`,
não suporte genérico a property propagation.

Para sinks:

- `fetch` deve ser o global não shadowed;
- `axios` deve resolver para import conhecido;
- função/method user-defined com o mesmo spelling é opaco;
- `http.request(options).end(content)` fica fora do MVP porque exige identidade
  do request handle/receiver.

### 5.3 Propagação

V1 permite:

- atribuição direta;
- aliases locais simples (`const payload = content`);
- um hop por helper in-project somente com callee único e edges explícitas
  caller actual → callee formal e callee return → caller binding.

Regras de kill/reject:

- reassignment cria outra version; o valor anterior não alcança usos posteriores;
- shadowing cria definição independente;
- mixed call sites só propagam o actual correspondente àquele call site;
- duplicate/ambiguous callee names rejeitam o hop;
- argumento reordenado usa posição formal, nunca nome aproximado;
- return múltiplo/condicional ou sem identidade única rejeita o hop.

V1 não permite:

- propagação por propriedades de objeto sem identidade preservada;
- containers, arrays ou callbacks opacos;
- depth > 1;
- imports/métodos não resolvidos;
- execução dinâmica.

Qualquer boundary opaco mantém evidência positiva para regras isoladas, mas
impede SHIELD-020.

## 6. Atribuição por tool e completude

Reutilizar o princípio do binding MCP entregue por SHIELD-019:

1. resolver tool → handler;
2. incluir callees in-project até depth 1;
3. associar cada node/edge ao escopo resolvido;
4. rejeitar candidates que cruzem tools;
5. não usar a `ExecutionSurface` agregada do target como prova.

Helper compartilhado por duas tools só pode produzir candidates separados quando
cada call edge preserva identities distintas. Se uma operação puder ser
atribuída a mais de uma tool, falhar fechado e não emitir candidate.

O MVP pode começar apenas em MCP TypeScript. Outros adapters ficam sem
SHIELD-020 até produzirem tool identity, handler binding e value edges
equivalentes.

Confidence em v1 é binária: chain com todos os predicates explícitos emite
`High`; qualquer edge opaca, ambígua ou incompleta não emite. Não existe
Confidence `Medium` por coocorrência.

## 7. Finding e estabilidade

Cardinalidade: no máximo um finding por:

```text
(tool, flow_kind, source_location, sink_location)
```

Ordenação determinística por tool, source location e sink location.

Cardinalidade interna usa `DefinitionId`s. O fingerprint público não usa line,
column ou byte span. Cada source/sink recebe um semantic anchor:

```text
relative file
+ lexical owner
+ operation kind
+ resolved API identity
+ normalized AST subtree hash (sem trivia/location)
+ ordinal somente entre anchors normalizados idênticos no mesmo owner
```

Inserir linhas/comentários ou mover a mesma expressão dentro do owner não muda
o anchor. Duas expressões semanticamente distintas, mesmo na mesma tool/file,
não compartilham anchor.

Limite de estabilidade v1: inserir ou remover uma operação byte-identical antes
de outra operação com o mesmo anchor normalizado no mesmo owner pode alterar o
ordinal das operações seguintes e, portanto, seus fingerprints/suppressions.
Esse churn é aceitável para duplicatas semanticamente indistinguíveis; C.0/C.1
não devem prometer estabilidade além dessa fronteira.

Primeira evidence, usada pelo fingerprint:

```text
composite_flow:v1:arbitrary_read_exfiltration:<tool>:<source_anchor>:<sink_anchor>
```

Evidence adicional, nesta ordem:

1. tool argument controla o path;
2. file read produz o content value;
3. cada alias/helper edge;
4. network payload recebe o mesmo value.

Line/column não entram no texto da primeira evidence. A location primária é o
sink HTTP; locations completas permanecem nas evidence entries.

Mensagem:

```text
Tool '<name>' can read an attacker-controlled file and send its contents over HTTP
```

Renomear a tool ou alterar semanticamente source/sink pode rotacionar o
fingerprint; deslocar linhas não. Suppressions continuam pelo fingerprint
existente de SHIELD-020; não criar formato paralelo.

## 8. Critérios de aceite

### 8.1 True positives

1. direct: parameter path → `readFile` result → `fetch(... body: result)`;
2. local alias: `content` → `payload` → axios POST;
3. one-hop helper: handler lê; helper resolvido envia o mesmo value;
4. multi-tool: somente a tool que contém a chain recebe o finding.

Cada fixture declara:

- exact candidate count;
- tool owner;
- ordered edge kinds;
- source/sink semantic anchors;
- expected SHIELD-020 count;
- expected counts das regras legacy relevantes.

### 8.2 False-positive guards

1. file read e POST na mesma função, mas payload não usa o content → zero;
2. tool A lê e tool B envia → zero;
3. path literal → zero SHIELD-020;
4. containment/allowlist guard comprovado → zero; normalização isolada não basta;
5. secret/env → HTTP direto → somente SHIELD-002;
6. parameter → command/dynamic eval direto → somente regras existentes;
7. download → write → execute → somente SHIELD-014;
8. network request sem payload identificado → zero;
9. helper opaco ou depth 2 → zero;
10. fixtures safe existentes → zero SHIELD-020.
11. reassignment de `content` antes do send → zero;
12. shadowed `readFile`, `fetch` ou `axios` → zero;
13. duplicate/ambiguous helper names → zero;
14. helper com mixed safe/tainted call sites → só o call edge comprovado;
15. duas chains na mesma tool/file → dois fingerprints distintos;
16. fixed-endpoint upload legítimo sem path arbitrário → zero.

Metamorphic tests:

- renomear local preserva finding count e flow semantics;
- inserir linhas/comentários preserva fingerprint;
- inserir/remover operação byte-identical anterior pode rotacionar fingerprints
  posteriores conforme o limite de estabilidade v1;
- trocar body pelo valor não relacionado remove o finding;
- mover o send para outra tool remove o finding;
- adicionar reads/requests não relacionados não altera cardinalidade;
- duplicar sink válido segue a cardinalidade definida.

Criar um corpus near-miss MCP TypeScript com pelo menos oito casos elegíveis
(file read + network no mesmo projeto) e oracle adjudicado. Gate de C.1:
**0 SHIELD-020 false positives em 8/8 casos**, além dos fixtures safe existentes.

### 8.3 Compatibilidade

- C.0 não adiciona campo público/serializado;
- findings e fingerprints SHIELD-001..019 permanecem idênticos;
- feature `typescript` off não produz candidate;
- no public API, dependency, `unsafe` ou `Cargo.lock` change sem PR explícito;
- `cargo fmt`, check, clippy, default tests, no-default tests e feature matrix verdes.

## 9. Sequência de implementação

### PR C.0 — Value edges

1. introduzir `ScopeId`, definition/versioned `ValueId`, `FlowEdge` e ownership
   por tool em módulo crate-private;
2. provar tool input → handler parameter/destructured field;
3. extrair result binding de imports `fs` resolvidos;
4. extrair payload de global `fetch` e import `axios` resolvidos;
5. implementar alias kill rules;
6. implementar actual→formal e return→binding para helper depth 1;
7. provar ambiguity/cross-tool fail-closed e ordering determinístico;
8. entregar exact graph + metamorphic tests;
9. não registrar SHIELD-020 e não alterar schema público.

### PR C.1 — Detector

1. fechar em PR próprio como candidates chegam ao detector sem duplicar parsing;
2. se houver mudança pública, realizar revisão explícita de API/serde/semver;
3. construir finding apenas com chain completa;
4. registrar metadata SHIELD-020/MCP06/DataExfiltration;
5. emitir evidence e fingerprint determinísticos;
6. adicionar TP/FP, suppression-isolation e corpus 0/8;
7. documentar SHIELD-020 em `docs/RULES.md`.

## 10. Flows posteriores

Cada novo impacto deve ter rule ID e metadata próprios; não colocar categorias
OWASP heterogêneas em SHIELD-020.

| Flow futuro | Chain | Motivo para regra separada |
|-------------|-------|----------------------------|
| Remote content execution | `HttpResponse → DynamicEval/ProcessExec` | impacto MCP05/CWE-94 |
| Database exfiltration | `DatabaseQuery → HttpRequest` | requer produtor DB real e MCP06 |
| Prompt-driven secret exfiltration | `PromptContent → SecretStore → HttpRequest` | requer edges de autorização/acesso, não mera coocorrência |

## 11. Não-escopo

- risk score;
- `discover` de client configs;
- LLM judge ou inferência probabilística;
- runtime enforcement;
- correlação target-level;
- flow inter-tool;
- análise de streams/containers;
- request-handle/receiver correlation (`http.request().end()`);
- suporte Python antes de binding e value identity equivalentes;
- transformar SHIELD-002/003/004/014 em aliases de SHIELD-020.
