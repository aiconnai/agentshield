# Spec: OWASP MCP Top 10 mapping for AgentShield rules

Status: draft (PR A — Taxonomia)
Scope: registry (`RuleMetadata`) + SARIF + `list-rules` + docs. Sem mudanças em detectors,
severidades, fingerprints ou conteúdo de findings.

## 1. Taxonomia de referência

Adotamos o **OWASP MCP Top 10 (2025)**:

| Código | Nome |
|--------|------|
| MCP01 | Token Mismanagement & Session Hijacking |
| MCP02 | Unauthorized / Excessive Scope & Privilege Escalation |
| MCP03 | Tool Poisoning & Malicious Tool Descriptions |
| MCP04 | Prompt Injection via Tool Metadata & Content |
| MCP05 | Command Injection & Arbitrary Code Execution |
| MCP06 | Data Exfiltration & Sensitive Information Disclosure |
| MCP07 | Supply Chain & Dependency Compromise |
| MCP08 | Insecure Server-to-Server Communication |
| MCP09 | Malicious Updates / Rug Pulls |
| MCP10 | Insufficient Logging, Monitoring & Auditability |

## 2. Mapeamento SHIELD → OWASP MCP

Cardinalidade: **uma categoria primária por regra** (`Option<OwaspMcp>`). Justificativa:
manter explicabilidade e score futuro determinístico. Regras que tocam duas categorias
recebem a categoria do *impacto principal*; a secundária fica documentada em RULES.md.

| Regra | Nome | OWASP primário | Secundário (docs) |
|-------|------|----------------|-------------------|
| SHIELD-001 | Command Injection | MCP05 | MCP02 |
| SHIELD-002 | Credential Exfiltration | MCP06 | MCP01 |
| SHIELD-003 | SSRF | MCP05 | MCP08 |
| SHIELD-004 | Arbitrary File Access | MCP02 | MCP06 |
| SHIELD-005 | Runtime Package Install | MCP07 | MCP09 |
| SHIELD-006 | Self-Modification | MCP09 | MCP05 |
| SHIELD-007 | Prompt Injection Surface | MCP04 | MCP03 |
| SHIELD-008 | Excessive Permissions | MCP02 | — |
| SHIELD-009 | Unpinned Dependencies | MCP07 | MCP09 |
| SHIELD-010 | Typosquat Detection | MCP07 | — |
| SHIELD-011 | Dynamic Code Execution | MCP05 | — |
| SHIELD-012 | No Lockfile | MCP07 | MCP09 |
| SHIELD-013 | Metadata SSRF | MCP05 | MCP08 |
| SHIELD-014 | Download-Write-Execute Chain | MCP07 | MCP05 |
| SHIELD-015 | Overbroad Filesystem Scope | MCP02 | MCP06 |
| SHIELD-016 | Unsafe Deserialization | MCP05 | — |
| SHIELD-017 | Archive Traversal (Zip Slip) | MCP02 | MCP05 |
| SHIELD-018 | Secret Leakage | MCP06 | MCP10 |
| SHIELD-019 | Capability / Description Mismatch | MCP03 | — |

Regras futuras sem mapeamento natural: `owasp_mcp: None` é permitido — o campo é
`Option`, não obrigatório.

## 3. Mudanças de schema

### 3.1 `RuleMetadata` (src/rules/finding.rs)

```rust
pub struct RuleMetadata {
    // ... campos existentes inalterados ...
    /// OWASP MCP Top 10 category, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp_mcp: Option<OwaspMcp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspMcp {
    #[serde(rename = "MCP01")] TokenMismanagement,
    #[serde(rename = "MCP02")] ExcessiveScope,
    #[serde(rename = "MCP03")] ToolPoisoning,
    #[serde(rename = "MCP04")] PromptInjection,
    #[serde(rename = "MCP05")] CommandExecution,
    #[serde(rename = "MCP06")] DataExfiltration,
    #[serde(rename = "MCP07")] SupplyChain,
    #[serde(rename = "MCP08")] InsecureCommunication,
    #[serde(rename = "MCP09")] MaliciousUpdate,
    #[serde(rename = "MCP10")] InsufficientLogging,
}
```

- Serialização: `"owasp_mcp": "MCP05"` (string do código, não o nome longo).
- `Finding` **não** muda neste PR — fingerprints e JSON de findings preservados.
  O consumidor resolve OWASP via rule metadata (registry) ou via SARIF rule properties.

### 3.2 SARIF (src/output/sarif.rs)

Hoje o renderer deriva rules a partir dos findings. Mudança:

1. `render` passa a receber também `&[RuleMetadata]` (ou um lookup `rule_id → metadata`)
   para enriquecer a seção `tool.driver.rules`.
2. Cada rule em SARIF ganha:

```json
{
  "id": "SHIELD-001",
  "properties": {
    "tags": ["CWE-78", "MCP05"],
    "owasp_mcp": "MCP05"
  },
  "relationships": [{
    "target": { "id": "MCP05", "toolComponent": { "name": "OWASP MCP Top 10" } },
    "kinds": ["superset"]
  }]
}
```

3. Adicionar `tool.driver.taxonomies` declarando a taxonomia OWASP MCP Top 10:

```json
"taxonomies": [{
  "name": "OWASP MCP Top 10",
  "version": "2025",
  "informationUri": "https://owasp.org/www-project-mcp-top-10/",
  "taxa": [
    { "id": "MCP01", "name": "Token Mismanagement & Session Hijacking" },
    { "id": "MCP02", "name": "..." },
    "... todas as 10 ..."
  ]
}]
```

Compatibilidade:
- `properties.tags` mantém CWE como primeiro elemento (consumidores atuais usam tags).
- Findings/`results` não mudam — `fingerprint` intacto.
- Se uma regra não tem `owasp_mcp`, omite `relationships` e a tag MCP.

### 3.3 `list-rules`

- Texto: nova coluna `OWASP` entre CWE e CATEGORY (`-` quando ausente).
- JSON: campo `owasp_mcp` serializado (3.1). Sem quebra: campos existentes mantidos.

## 4. Onde o metadata vive

Cada detector preenche `owasp_mcp` no próprio `RuleMetadata` (constante por arquivo,
ao lado de `cwe_id`). Sem tabela central paralela — a fonte de verdade continua sendo
o `metadata()` do detector.

## 5. Testes (critérios de aceite)

1. **Serialização `RuleMetadata`**: round-trip JSON com e sem `owasp_mcp`;
   `None` omite a chave (`skip_serializing_if`).
2. **SARIF**:
   - rule com `owasp_mcp` contém tag `MCPxx` + entrada em `taxonomies` + `relationships`;
   - rule sem `owasp_mcp` (construída manualmente no teste) não tem `relationships`;
   - CWE tag preservada;
   - fingerprints/results idênticos ao comportamento anterior (regressão de compat).
3. **`list-rules`**: saída JSON contém `owasp_mcp` em todas as 19 regras; saída texto
   contém coluna OWASP.
4. **Integridade do mapeamento**: teste que itera `RuleEngine::list_rules()` e garante
   que toda regra `SHIELD-*` tem `owasp_mcp: Some(_)` (previne regras novas órfãs);
   códigos MCP válidos (enum garante em compile time).
5. **Docs**: RULES.md mantém uma linha "OWASP MCP" na tabela de cada regra.

## 6. Não-escopo (explícito)

- Sem score/risk (épico posterior).
- Sem mudança de severidade, confidence, fingerprints, mensagens.
- Sem novos detectors; sem `relationships` em `results` (só em `rules`).
- `Finding` não ganha campo novo.
