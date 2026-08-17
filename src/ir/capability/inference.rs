use super::projection::sort_and_dedup_declarations;
use super::types::{DESCRIPTION_PHRASES, DescriptionCapability, DescriptionToken};
use crate::ir::tool_surface::{CapabilityDeclaration, CapabilityDeclarationSource, ToolSurface};

pub(crate) fn project_declared_description(tool: &mut ToolSurface) {
    let Some(description) = tool.description.as_deref() else {
        return;
    };

    for matched in description_capabilities(description) {
        tool.declared_capabilities.insert(matched.capability);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability: matched.capability,
            source: CapabilityDeclarationSource::Description,
            phrase_or_field: matched.phrase,
        });
    }
    sort_and_dedup_declarations(&mut tool.capability_declarations);
}

pub(crate) fn description_capabilities(description: &str) -> Vec<DescriptionCapability> {
    let tokens = tokenize_description(description);
    let mut matches = Vec::new();

    for pattern in DESCRIPTION_PHRASES {
        for (start, candidate) in tokens.windows(pattern.tokens.len()).enumerate() {
            if pattern_matches(candidate, pattern.tokens) && !is_negated(&tokens, start) {
                matches.push(DescriptionCapability {
                    capability: pattern.capability,
                    phrase: pattern.tokens.join(" "),
                });
            }
        }
    }

    matches.sort_by(|left, right| {
        (left.capability, &left.phrase).cmp(&(right.capability, &right.phrase))
    });
    matches.dedup();
    matches
}

fn pattern_matches(candidate: &[DescriptionToken], pattern: &[&str]) -> bool {
    candidate
        .iter()
        .zip(pattern)
        .all(|(token, expected)| matches!(token, DescriptionToken::Word(word) if word == expected))
}

fn tokenize_description(description: &str) -> Vec<DescriptionToken> {
    let normalized = description.to_lowercase().replace('’', "'");
    let mut tokens = Vec::new();
    let mut word = String::new();

    for character in normalized.chars() {
        if character.is_alphanumeric() || character == '\'' {
            word.push(character);
            continue;
        }

        push_description_word(&mut tokens, &mut word);
        if matches!(character, '.' | ';' | ':' | '!' | '?')
            && !matches!(tokens.last(), Some(DescriptionToken::Boundary))
        {
            tokens.push(DescriptionToken::Boundary);
        }
    }
    push_description_word(&mut tokens, &mut word);
    tokens
}

fn push_description_word(tokens: &mut Vec<DescriptionToken>, word: &mut String) {
    if word.is_empty() {
        return;
    }

    let normalized = normalize_description_word(word);
    if !matches!(normalized, "a" | "an" | "the") {
        tokens.push(DescriptionToken::Word(normalized.to_string()));
    }
    word.clear();
}

fn normalize_description_word(word: &str) -> &str {
    match word {
        "reads" => "read",
        "writes" => "write",
        "creates" => "create",
        "deletes" => "delete",
        "modifies" => "modify",
        "lists" => "list",
        "inspects" => "inspect",
        "fetches" => "fetch",
        "calls" => "call",
        "downloads" => "download",
        "runs" => "run",
        "executes" => "execute",
        "loads" => "load",
        "accesses" => "access",
        "evaluates" => "evaluate",
        "installs" => "install",
        "adds" => "add",
        "queries" => "query",
        "searches" => "search",
        "updates" => "update",
        _ => word,
    }
}

fn is_negated(tokens: &[DescriptionToken], phrase_start: usize) -> bool {
    let mut preceding_words = 0;
    for token in tokens[..phrase_start].iter().rev() {
        let DescriptionToken::Word(word) = token else {
            break;
        };
        if matches!(word.as_str(), "but" | "however" | "yet") {
            break;
        }
        preceding_words += 1;
        if matches!(
            word.as_str(),
            "no" | "not" | "never" | "without" | "doesn't"
        ) {
            return true;
        }
        if preceding_words == 4 {
            break;
        }
    }
    false
}
