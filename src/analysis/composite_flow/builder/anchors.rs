use tree_sitter::Node;

use super::super::ast::normalized_subtree_hash;
use super::super::types::SemanticAnchor;
use super::types::{AnchorKey, AnchorSeed, Analyzer};

impl Analyzer<'_> {
    pub(crate) fn anchor(
        &mut self,
        unit_index: usize,
        owner: &str,
        operation: &'static str,
        api: &'static str,
        node: Node<'_>,
    ) -> SemanticAnchor {
        let unit = &self.units[unit_index];
        let hash = normalized_subtree_hash(node, unit.content);
        let key = AnchorKey {
            file: unit.path.to_path_buf(),
            owner: owner.to_string(),
            operation,
            api,
            hash: hash.clone(),
        };
        let ordinal = self.anchor_ordinals.entry(key).or_default();
        let current = *ordinal;
        *ordinal += 1;
        SemanticAnchor {
            relative_file: unit.path.to_path_buf(),
            lexical_owner: owner.to_string(),
            operation_kind: operation,
            resolved_api: api,
            normalized_subtree_hash: hash,
            identical_ordinal: current,
        }
    }

    pub(crate) fn anchor_from_key(&mut self, seed: AnchorSeed) -> SemanticAnchor {
        let current = if let Some(ordinal) = self.anchor_instances.get(&seed) {
            *ordinal
        } else {
            let ordinal = self.anchor_ordinals.entry(seed.key.clone()).or_default();
            let current = *ordinal;
            *ordinal += 1;
            self.anchor_instances.insert(seed.clone(), current);
            current
        };
        let key = seed.key;
        SemanticAnchor {
            relative_file: key.file,
            lexical_owner: key.owner,
            operation_kind: key.operation,
            resolved_api: key.api,
            normalized_subtree_hash: key.hash,
            identical_ordinal: current,
        }
    }
}
