# ADR: Descoberta local read-only de configurações de clientes

- **Status:** Proposed
- **Date:** 2026-07-23
- **Decision owners:** AgentShield maintainers
- **Implementation gate:** nenhum código de discovery antes deste ADR ser
  revisado e aceito

## 1. Contexto

AgentShield hoje analisa um path escolhido pelo usuário. Ele não procura
automaticamente configurações de clientes MCP ou outras extensões no ambiente
local.

O próximo incremento do roadmap é um comando `agentshield discover` que ajude o
usuário a encontrar configurações locais sem abandonar os princípios atuais:

- offline-first;
- source e configuração permanecem locais;
- comportamento determinístico;
- nenhuma execução de código ou comando descoberto;
- preferência por omissão a atribuição incorreta;
- nenhuma alteração implícita no contrato público de `scan()`, `ScanTarget`,
  `ScanReport`, JSON, SARIF ou attestation.

Mesmo uma operação read-only tem impacto de privacidade: abrir um arquivo de
configuração pode revelar nomes, paths, argumentos, endpoints, headers ou
variáveis de ambiente. Portanto, "não escrever" não é uma garantia suficiente.

## 2. Decisão

Adotar descoberta híbrida e conservadora:

1. por padrão, inspecionar somente uma allowlist versionada e documentada de
   paths exatos de configuração por cliente e plataforma;
2. permitir roots adicionais somente quando fornecidos explicitamente na
   invocação atual;
3. permitir desativar todos os paths padrão com `--no-default-paths`;
4. nunca fazer busca recursiva implícita em `$HOME`, no filesystem inteiro ou
   em diretórios derivados de um arquivo descoberto;
5. manter discovery separado de scan: encontrar uma entrada não executa nem
   inicia sua análise automaticamente.

O primeiro incremento é CLI-only. Não será adicionada API pública Rust até que
ownership, compatibilidade e casos reais do resultado v1 sejam comprovados.

Interface proposta:

```text
agentshield discover
agentshield discover --no-default-paths --root <PATH> [--root <PATH>...]
agentshield discover --format console|json
agentshield discover --explain
```

`--explain` lista, antes da leitura, os descritores de paths padrão, roots
explícitos, limites e política de symlinks. Ele não imprime conteúdo de
configuração.

## 3. Registro de paths e formatos

Existe uma única fonte de verdade crate-private para paths conhecidos. Cada
entrada do registro contém:

- identificador estável do cliente;
- plataformas aplicáveis;
- template exato do path, resolvido apenas contra diretórios de sistema
  conhecidos e injetáveis em testes;
- formato/parser esperado;
- scope esperado, como user ou workspace;
- versão do descritor.

Regras do registro:

- paths padrão são arquivos exatos; não são roots recursivos;
- um novo path ou parser exige fixture, referência à documentação upstream e
  teste de integridade;
- o registro tem versão de cobertura separada da versão do schema de output;
- testes não leem o home real do desenvolvedor ou do runner;
- as projeções de help, discovery e testes são derivadas do mesmo registro;
- paths ausentes são estado normal, não erro nem diagnostic por padrão.

O conjunto inicial de clientes e paths será fechado no PR de implementação
usando documentação upstream vigente. Este ADR aprova o modelo do registro, não
congela nomes ou layouts de terceiros que podem mudar.

## 4. Roots explícitos e limites

`--root` é consentimento apenas para o path informado naquela invocação. Roots
não podem vir de `.agentshield.toml`, de um repositório analisado, de um arquivo
descoberto ou de variável interpretada dentro de configuração de cliente.

No v1, cada `--root`:

- deve apontar para um diretório existente;
- não pode ser symlink nem filesystem/volume root;
- pode ser absoluto ou relativo ao cwd da invocation;
- rejeita componentes `..` antes de resolver o path;
- é aberto componente a componente sem seguir links, e o directory handle
  resultante define o boundary;
- autoriza leitura somente de configs allowlisted dentro desse boundary.

Um root explícito pode estar fora do home do usuário. Essa autorização não
ignora permissões do sistema operacional nem autoriza qualquer path fora do
boundary. Paths padrão, por outro lado, são resolvidos somente para o profile
do usuário efetivo; discovery nunca enumera homes de outros usuários.

Cada root explícito usa os mesmos parsers, identidade, ordenação e diagnostics
dos paths padrão, com limites determinísticos v1:

- profundidade máxima: 4 diretórios abaixo de cada root;
- diretórios visitados: 256 por root e 512 por invocation;
- arquivos candidatos encontrados: 1.024 por root e 2.048 por invocation;
- arquivos de configuração abertos: 128 por root e 256 por invocation;
- tamanho máximo: 1 MiB por arquivo;
- bytes agregados lidos: 8 MiB por invocation;
- entradas configuradas aceitas: 1.024 por invocation.

O v1 não usa wall-clock timeout para decidir quais resultados existem, porque
isso tornaria a cardinalidade dependente da máquina. Cancelamento explícito
pode interromper a invocation sem representar resultado completo.

Atingir um limite preserva resultados válidos anteriores e produz diagnostic
estruturado `limit_reached`; nunca amplia o limite silenciosamente.

Somente filenames/layouts allowlisted são abertos. A traversal não interpreta
globs vindos de arquivos locais.

## 5. Boundary de filesystem

Discovery:

- considera apenas arquivos regulares;
- usa metadata de symlink e não segue symlinks;
- rejeita FIFO, socket, device e outros arquivos especiais;
- abre diretórios e arquivos por handle relativo com no-follow/reparse-point
  semantics da plataforma;
- valida tipo e identidade pelo handle aberto, não apenas pelo pathname;
- verifica containment no boundary absoluto antes e depois de abrir;
- não eleva privilégios;
- trata `permission_denied`, mudança detectada durante a leitura, arquivo
  removido e arquivo oversized como falhas isoladas daquela source.

V1 não promete detectar toda escrita concorrente. Compara metadata e identidade
do handle antes/depois da leitura e emite `change_detected_during_read` quando
observar diferença. Testes adversariais cobrem rename e symlink swap.

O PR D.0 deve documentar e testar o primitive usado em cada plataforma
suportada. Se a plataforma/filesystem não oferecer abertura atômica que impeça
seguir symlink/reparse point, discovery não abre a source e emite
`unsupported_filesystem_safety`. Não existe fallback check-then-open.

Não há restrição portável de mount ou owner dentro de um root explícito: o root
é o boundary autorizado. Em paths padrão, somente o profile efetivo é elegível.
Esse limite é documentado para não alegar isolamento que a plataforma não pode
provar.

Se suporte futuro a symlink for necessário, ele exige novo ADR com semântica de
containment e portabilidade explícita.

## 6. Parsing sem execução

Parsers de discovery são estruturais e fail-closed. Eles não:

- iniciam subprocessos;
- executam command, args, hooks ou scripts;
- invocam package managers, containers ou wrappers;
- fazem shell parsing, command substitution ou glob expansion;
- expandem variáveis de ambiente presentes no arquivo;
- resolvem includes;
- fazem DNS, HTTP ou qualquer outra operação de rede;
- verificam se um endpoint remoto está ativo;
- inferem um repositório local a partir de `npx`, `uvx`, `docker`, URL ou nome
  de pacote;
- carregam plugins do cliente.

Uma entrada só recebe `local_reference` quando o formato suportado contém um
path local explícito em posição estrutural allowlisted. Paths relativos são
resolvidos contra a base documentada daquele client format. Discovery não abre,
faz stat ou analisa esse target; a referência pode apontar para fora do config
boundary e não concede autorização de scan. Caso contrário, ela permanece
`configured_entry` ou `unresolved_entry`; não há heurística.

Arquivos malformados, ambíguos ou parcialmente suportados não produzem
`local_reference`. Falha em uma source não invalida sources independentes.

## 7. Privacidade e redaction

O processo usa allowlist de campos retidos, não heurística de secrets. Somente
client, source, chave declarada, estado, scope e referência local estrutural
podem entrar no resultado. Todo campo não allowlisted é descartado.

Ele nunca retém, registra, serializa, inclui em fingerprint ou mostra:

- valor de variável de ambiente;
- token, API key, password, cookie ou header;
- conteúdo bruto do arquivo;
- command, args ou argumento opaco;
- URL contendo credentials;
- snippet da configuração.

Nomes e valores de variáveis podem ser representados somente como presença ou
contagem agregada quando necessário, nunca individualmente. Um parser só pode
extrair path local de uma posição explicitamente definida pelo schema daquele
client; ele não procura paths em command ou args desconhecidos.

Diagnostics usam códigos fechados e mensagens bounded. Erros de parser não
incluem slices do input. Console e JSON usam somente path refs redigidos:

- paths padrão sob o profile usam `~/...`;
- roots explícitos usam `$ROOT[n]/...`;
- referências relativas ao diretório da source usam `@SOURCE/...`;
- nenhum output padrão inclui path absoluto, username ou prefixo do home.

Uma referência absoluta fora do profile e dos roots explícitos permanece
`unresolved` com reason code `absolute_path_redacted`; seu valor não é emitido.

Um futuro modo de emitir paths absolutos exige opt-in e revisão de privacidade
própria.

O help e `--explain` deixam claro que o comando abre configurações locais. A
opção `--no-default-paths` é parte obrigatória do contrato v1, não conveniência.

## 8. Modelo de resultado v1

Discovery não retorna `ScanTarget` e não reutiliza `ScanReport`. O JSON usa um
envelope próprio:

```text
schema: "agentshield.discovery/v1"
registry_version
sources[]
entries[]
diagnostics[]
summary
```

Uma source contém:

- `source_id` determinístico;
- `client_id`;
- path ref redigido;
- scope;
- status: `inspected`, `unsupported`, `malformed`, `permission_denied`,
  `limit_reached`, `unsupported_filesystem_safety` ou
  `change_detected_during_read`;
- lista ordenada de provenance observations, cada uma com
  `discovery_method`: `known_path` ou `explicit_root`.

Uma entry contém:

- `entry_id` determinístico;
- `source_id`;
- chave/nome declarado;
- estado: `configured`, `disabled`, `unresolved` ou `local_reference`;
- path ref local somente quando provado estruturalmente;
- support status;
- nenhuma cópia de command, args ou env.

O envelope não inclui findings, verdict, severity, rule catalog, policy ou
fingerprints de scan.

Alterações aditivas opcionais podem permanecer em v1. Renomear, remover ou mudar
semântica de campo exige nova versão. Alterar apenas o registro incrementa
`registry_version`, não o schema.

## 9. Identidade, deduplicação e precedência

Identidade de source deriva de:

```text
client_id + primary redacted path ref + scope
```

`discovery_method` é provenance, não identidade. A primary observation é
escolhida deterministicamente: `known_path` antes de `explicit_root`, depois
índice do descritor/root e path ref. `source_id` é o digest desse material
redigido.

Separadamente, a chave interna de deduplicação usa path absoluto normalizado e,
quando disponível, file ID do handle. Essa chave nunca é serializada, incluída
no `source_id` ou registrada.

Identidade de entry deriva de:

```text
source_id + chave declarada
```

Entradas com o mesmo nome em sources diferentes não são mescladas. Global e
workspace, enabled e disabled, profiles e overrides permanecem instâncias
separadas.

Somente observações que resolvem para o mesmo arquivo regular canônico podem
ser deduplicadas em uma source, preservando todas as provenances ordenadas.
Hard links com file ID igual podem convergir; sem file ID portável permanecem
sources separadas. Discovery não
calcula precedência efetiva do cliente a menos que a regra esteja documentada
e comprovada pelo parser daquele cliente. Ausência dessa prova produz entradas
separadas, não uma escolha.

Ordenação é estável por:

```text
client_id, source path ref, scope, chave declarada, entry_id
```

Concorrência não pode alterar cardinalidade ou ordem.

## 10. Diagnostics e exit codes

Diagnostics são dados, não logs livres. Cada um contém código, source opcional
e contagem bounded; nunca contém input bruto.

Semântica de exit:

- `0`: discovery concluiu, inclusive com zero entradas ou diagnostics parciais;
- `2`: invocação inválida, como root inexistente ou formato desconhecido;
- erro interno não recuperável usa o contrato de erro CLI existente.

Uma source inválida não remove resultados de sources válidas. JSON e console
representam a mesma truth; o console é apenas uma projeção.

## 11. Compatibilidade e isolamento

O primeiro PR de implementação não altera:

- `scan()` ou `ScanOptions`;
- `ScanTarget`, `ScanReport` ou adapters existentes;
- JSON/SARIF/HTML de scan;
- findings, fingerprints, baselines ou suppressions;
- certification e attestation;
- `.agentshield.toml`;
- rule registry ou policy evaluation.

Discovery não alimenta scan implicitamente. Um workflow futuro
discover-then-scan exige consentimento explícito e decisão própria sobre
multi-target reporting.

Não há cache global ou thread-local. Uma invocation possui todo seu registry,
budgets, diagnostics e resultados.

## 12. Alternativas consideradas

### Somente paths conhecidos

Mais simples e com menor superfície, mas não cobre layouts portáteis, clientes
novos ou ambientes corporativos sem novo release. Permanece fallback se os
limites de roots explícitos não puderem ser implementados com segurança.

### Busca recursiva por padrão

Rejeitada. Uma busca implícita em home ou filesystem cria surpresa de
privacidade, custo não determinístico, risco de symlink/permission boundary e
falsa atribuição.

### Reusar `scan()` ou `ScanTarget`

Rejeitada. Discovery descreve configuração e provenance; scan descreve IR e
findings de um target escolhido. Misturar os contratos altera APIs e
serialização e sugere análise automática não autorizada.

### Executar comandos para resolver targets

Rejeitada. Mesmo `--version`, package-manager lookup ou container inspection
viola o contrato read-only/offline e pode executar código controlado por
configuração.

### Adiar discovery

Rejeitada enquanto os gates deste ADR forem implementáveis. Se redaction,
boundary checks, budgets ou disclosure não puderem ser garantidos, deferir é
preferível a enfraquecer o contrato.

## 13. Consequências

Positivas:

- experiência útil sem crawling implícito;
- boundary de privacidade visível e desativável;
- cobertura extensível sem acoplar discovery ao IR;
- resultados determinísticos, auditáveis e testáveis;
- falhas parciais preservam trabalho válido.

Negativas:

- manutenção contínua do registro de paths e formatos;
- cobertura conservadora produz falsos negativos;
- explicit roots exigem traversal e testes adversariais;
- discovery não resolve automaticamente wrappers ou targets remotos;
- um workflow completo pode exigir um segundo comando explícito.

## 14. Reversal triggers

Reconsiderar esta decisão se:

- pesquisa com usuários mostrar que qualquer leitura implícita fora do cwd é
  inaceitável; nesse caso paths padrão tornam-se opt-in;
- não for possível implementar budgets e boundary checks portáveis; nesse caso
  o v1 usa somente paths exatos;
- o resultado precisar expor secrets ou executar resolução para ser útil; nesse
  caso discovery é adiado;
- symlink, remote discovery ou auto-scan se tornarem requisito; cada um exige
  nova decisão;
- o modelo CLI-only impedir um caso real comprovado; uma API pública exige
  revisão de ownership, semver e serialization.

## 15. Sequência de implementação

Separar review gates:

1. **D.0 — registry e tipos crate-private**
   - fechar clientes/paths iniciais com documentação upstream;
   - implementar registry, budgets, tipos e parsers sem comando público;
   - fixtures para cada formato e testes de integridade/redaction;
   - permitir um único `#![allow(dead_code)]` no módulo D.0, justificado pela
     separação do review gate e removido obrigatoriamente em D.1;
   - provar zero mudança em scan e outputs existentes.
2. **D.1 — CLI discovery**
   - adicionar `discover`, `--no-default-paths`, `--root`, `--format` e
     `--explain`;
   - emitir console e envelope JSON v1;
   - manter auto-scan fora do escopo.
3. **D.2 — cobertura adicional**
   - adicionar clientes e layouts somente com documentação, fixtures e
     atualização de `registry_version`;
   - avaliar API pública em ADR separado se houver demanda comprovada.

## 16. Critérios de aceite

- [ ] somente paths exatos documentados são inspecionados por padrão;
- [ ] `--no-default-paths` resulta em zero leitura de paths padrão;
- [ ] roots adicionais vêm apenas da invocation atual;
- [ ] roots rejeitam symlink, filesystem root e componentes `..`;
- [ ] todo ancestor component é aberto sem seguir symlink/reparse point;
- [ ] paths padrão nunca enumeram profiles de outros usuários;
- [ ] traversal respeita depth/file/byte/entry budgets determinísticos;
- [ ] symlinks e arquivos especiais não são seguidos ou lidos; plataformas sem
      primitive atômico falham com `unsupported_filesystem_safety`;
- [ ] testes adversariais cobrem rename e symlink swap entre check e open;
- [ ] zero network, subprocess, shell/env expansion ou include resolution;
- [ ] conteúdo bruto e valores sensíveis não aparecem em output, logs, errors
      ou fingerprints;
- [ ] command, args, env e campos desconhecidos são descartados por allowlist,
      não por heurística de secret;
- [ ] console e JSON não serializam path absoluto, username ou home prefix;
- [ ] malformed/denied/oversized/changed sources falham isoladamente;
- [ ] nenhuma entry ambígua vira `local_reference`;
- [ ] identidade, deduplicação e ordenação são determinísticas;
- [ ] o mesmo arquivo encontrado por known path e explicit root produz uma
      source com duas provenance observations;
- [ ] known paths e explicit roots compartilham parsers e modelo;
- [ ] registro é fonte única para help, discovery e testes;
- [ ] JSON declara schema e registry versions separados;
- [ ] default e `--no-default-features` produzem discovery equivalente;
- [ ] scan, outputs, findings, fingerprints e attestation permanecem
      byte-for-byte equivalentes;
- [ ] testes nunca leem configurações reais do usuário ou do runner;
- [ ] docs explicam consentimento, limites e estados sem chamar entradas de
      "instaladas", "ativas" ou "seguras" sem prova.

## 17. Council review

O council full Level 1 recomendou a opção híbrida com confiança alta. O
consenso depende de todos os limites deste ADR.

Dissent preservado: paths padrão ainda são leitura implícita de configuração
pessoal. `--no-default-paths`, disclosure visível e zero crawling são gates. Se
esses gates não puderem ser mantidos, paths padrão devem virar opt-in ou o
feature deve ser adiado.

O veto adversarial de privacidade/security concordou com a decisão condicionada
aos mesmos limites.
