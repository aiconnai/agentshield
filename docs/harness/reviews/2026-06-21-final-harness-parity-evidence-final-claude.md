O fluxo está correto: `tee "$TMP_RAW"` captura o output do `run_reviewer` em `TMP_RAW` enquanto também envia para stderr (para que o operador veja o progresso em tempo real). O `save_reviewer_artifacts` depois copia `TMP_RAW` para o artefato permanente. Isso é um padrão válido — `TMP_RAW` tem o conteúdo completo.

Porém noto que `run_reviewer "$PROMPT" 2>&1` funde stderr+stdout antes de fazer pipe, então o arquivo TMP_RAW contém o output combinado stderr+stdout do reviewer, que é o comportamento esperado para capturar a transcrição completa do codex.

Agora verifico um detalhe sutil: o `run_reviewer` internamente captura stdout via `output="$(run_reviewer_once "$prompt" 2>&1)"` e depois faz `printf '%s\n' "$output"`. Então quando o caller faz `run_reviewer "$PROMPT" 2>&1 | tee "$TMP_RAW"`, o que chega ao pipe é o stdout do `run_reviewer` (que já inclui stderr do `run_reviewer_once` fundido via `2>&1` interno). O `2>&1` no caller também redireciona stderr do `run_reviewer` (o WARN de retry) para o pipe. Isso resulta em `TMP_RAW` contendo tanto a saída do reviewer quanto as mensagens de WARN de retry — isso é uma observação menor mas não é um defeito funcional já que `write_review` usa grep/awk para encontrar a linha `REVIEW_VERDICT` no arquivo.

Verificação completa. Posso emitir o veredicto final.

---

REVIEW_VERDICT: PASS

**Verificação dos dois achados MED corrigidos em HEAD:**

- **[RESOLVIDO] check-commit-msg.sh — args não-arquivo desconhecidos silenciados:** O arm `*)` no loop while agora verifica `[ -f "$1" ]`; se o arg não for um arquivo existente, emite erro e sai com exit 2 (`check-commit-msg.sh:23-26`). O caminho do hook git (que passa um path de arquivo existente) permanece intacto.

- **[RESOLVIDO] review-gate.sh — manual post sem fallback defensivo:** O `case "$VERDICT"` após `write_manual_review` agora tem arm `*)` (`review-gate.sh:480-483`) que emite mensagem de erro e sai com exit 1. Os paths PASS e FAIL permanecem inalterados.

**Nenhum defeito residual encontrado nas áreas revisadas:**

- `run_reviewer` retenta apenas em saída vazia; output não-vazio (incluindo FAIL) retorna imediatamente sem retry.
- Codex é invocado com `--sandbox read-only -C "$REPO_ROOT" -` via stdin (`review-gate.sh:214`).
- Backends reservados `claude|grok|ollama` falham com exit 2 antes de qualquer invocação.
- Re-injeção de prior findings filtra exclusivamente `[BLOCKER]` e `[HIGH]` via regex (`review-gate.sh:272`).
- `doctor.sh --json` usa word-splitting puro sem here-string (`doctor.sh:266-272`); usage errors são order-independent.
- `check_latest_review_verdict` exclui `*-pre-manual.md` na busca (`doctor.sh:106`).
- `sensors.sh status --json` sempre sai com código 0 mesmo quando o estado salvo é FAIL (`sensors.sh:88`).
- Contrato `harness-json-v1` e política de REVIEWER_CLI estão documentados corretamente em `JSON_OUTPUTS.md` e `CODE_REVIEW_POLICY.md`.
