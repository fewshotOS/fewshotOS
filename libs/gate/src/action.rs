//! The action registry (docs/ARCHITECTURE.md §4.4).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use fewshot_labels::{Integrity, Secrecy};

/// Identifies a registered action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(pub u32);

/// What running an action does to the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Reads only.
    Read,
    /// Local change that can be undone.
    LocalReversible,
    /// Local change that cannot be undone.
    LocalIrreversible,
    /// Leaves the device: sends, pays, posts.
    External,
}

impl Effect {
    /// Runs at once; otherwise the effect waits in the outbox until commit.
    pub fn is_immediate(self) -> bool {
        matches!(self, Effect::Read | Effect::LocalReversible)
    }
}

/// How a parameter may be filled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamKind {
    /// Any value.
    Open,
    /// One of a user-approved set. `Bounded`-integrity values may fill it
    /// without approval when they pick one of these options.
    Choice(Vec<Vec<u8>>),
}

/// A declared parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// Name shown in approvals.
    pub name: String,
    /// How it may be filled.
    pub kind: ParamKind,
}

impl Param {
    /// An open parameter.
    pub fn open(name: impl Into<String>) -> Self {
        Param { name: name.into(), kind: ParamKind::Open }
    }

    /// A choice parameter.
    pub fn choice(name: impl Into<String>, options: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Param { name: name.into(), kind: ParamKind::Choice(options.into_iter().collect()) }
    }
}

/// An action's declared metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionSpec {
    /// Identifier.
    pub id: ActionId,
    /// Name, e.g. `"mail.send"`.
    pub name: String,
    /// Effect class.
    pub effect: Effect,
    /// Minimum argument integrity that needs no approval.
    pub integrity_floor: Integrity,
    /// Secrecy tags allowed to leave the device through this action
    /// (its egress tags intersected with the destination's clearance).
    pub egress_clearance: Secrecy,
    /// Declared parameters, in order.
    pub params: Vec<Param>,
    /// This action creates a local draft of the named external action (`$draftFor`).
    pub draft_for: Option<ActionId>,
    /// Action that undoes this one; called with the same arguments.
    pub compensation: Option<ActionId>,
}

/// Two actions registered with the same id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateAction(pub ActionId);

/// Why [`Registry::validate`] rejected the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// `action` names `target` as its draft or compensation, but `target` is not registered.
    UnknownTarget {
        /// The action declaring the reference.
        action: ActionId,
        /// The missing action.
        target: ActionId,
    },
    /// `action` drafts `target`, but `target` is not external.
    DraftTargetNotExternal {
        /// The draft action.
        action: ActionId,
        /// The action it drafts.
        target: ActionId,
    },
    /// A draft action must itself be a read or local-reversible effect.
    DraftNotReversible(ActionId),
    /// Two actions draft the same external action.
    DuplicateDraft {
        /// The external action.
        target: ActionId,
        /// The first draft action.
        first: ActionId,
        /// The second draft action.
        second: ActionId,
    },
    /// An action names itself as its compensation.
    SelfCompensation(ActionId),
    /// A compensation takes a different number of parameters than the action it undoes.
    CompensationArity {
        /// The action being undone.
        action: ActionId,
        /// Its compensation.
        compensation: ActionId,
    },
}

/// Registered actions.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    actions: BTreeMap<ActionId, ActionSpec>,
}

impl Registry {
    /// Empty registry.
    pub fn new() -> Self {
        Registry::default()
    }

    /// Registers an action.
    pub fn register(&mut self, spec: ActionSpec) -> Result<(), DuplicateAction> {
        if self.actions.contains_key(&spec.id) {
            return Err(DuplicateAction(spec.id));
        }
        self.actions.insert(spec.id, spec);
        Ok(())
    }

    /// Looks up an action.
    pub fn get(&self, id: ActionId) -> Option<&ActionSpec> {
        self.actions.get(&id)
    }

    /// Every action, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &ActionSpec> {
        self.actions.values()
    }

    /// The action that drafts `external`, if one is registered.
    pub fn draft_of(&self, external: ActionId) -> Option<&ActionSpec> {
        self.iter().find(|a| a.draft_for == Some(external))
    }

    /// Checks draft and compensation references. Call after registering everything.
    pub fn validate(&self) -> Result<(), RegistryError> {
        let mut drafts: BTreeMap<ActionId, ActionId> = BTreeMap::new();
        for a in self.iter() {
            if let Some(target) = a.draft_for {
                let t = self.get(target).ok_or(RegistryError::UnknownTarget { action: a.id, target })?;
                if t.effect != Effect::External {
                    return Err(RegistryError::DraftTargetNotExternal { action: a.id, target });
                }
                if !a.effect.is_immediate() {
                    return Err(RegistryError::DraftNotReversible(a.id));
                }
                if let Some(&first) = drafts.get(&target) {
                    return Err(RegistryError::DuplicateDraft { target, first, second: a.id });
                }
                drafts.insert(target, a.id);
            }
            if let Some(c) = a.compensation {
                if c == a.id {
                    return Err(RegistryError::SelfCompensation(a.id));
                }
                let comp = self.get(c).ok_or(RegistryError::UnknownTarget { action: a.id, target: c })?;
                if comp.params.len() != a.params.len() {
                    return Err(RegistryError::CompensationArity { action: a.id, compensation: c });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const SEND: ActionId = ActionId(1);
    const DRAFT: ActionId = ActionId(2);
    const UNSEND: ActionId = ActionId(3);
    const NOTE: ActionId = ActionId(4);

    fn spec(id: ActionId, effect: Effect, params: usize) -> ActionSpec {
        ActionSpec {
            id,
            name: "a".into(),
            effect,
            integrity_floor: Integrity::User,
            egress_clearance: Secrecy::EMPTY,
            params: (0..params).map(|_| Param::open("p")).collect(),
            draft_for: None,
            compensation: None,
        }
    }

    fn registry(specs: impl IntoIterator<Item = ActionSpec>) -> Registry {
        let mut r = Registry::new();
        for s in specs {
            r.register(s).unwrap();
        }
        r
    }

    #[test]
    fn draft_of_an_external_action_is_valid() {
        let r = registry([
            spec(SEND, Effect::External, 2),
            ActionSpec { draft_for: Some(SEND), ..spec(DRAFT, Effect::LocalReversible, 2) },
        ]);
        assert_eq!(r.validate(), Ok(()));
        assert_eq!(r.draft_of(SEND).map(|a| a.id), Some(DRAFT));
        assert!(r.draft_of(DRAFT).is_none());
    }

    #[test]
    fn draft_target_must_exist() {
        let r = registry([ActionSpec { draft_for: Some(SEND), ..spec(DRAFT, Effect::LocalReversible, 2) }]);
        assert_eq!(r.validate(), Err(RegistryError::UnknownTarget { action: DRAFT, target: SEND }));
    }

    #[test]
    fn draft_target_must_be_external() {
        let r = registry([
            spec(NOTE, Effect::LocalIrreversible, 1),
            ActionSpec { draft_for: Some(NOTE), ..spec(DRAFT, Effect::LocalReversible, 1) },
        ]);
        assert_eq!(r.validate(), Err(RegistryError::DraftTargetNotExternal { action: DRAFT, target: NOTE }));
    }

    #[test]
    fn draft_must_be_reversible() {
        let r = registry([
            spec(SEND, Effect::External, 1),
            ActionSpec { draft_for: Some(SEND), ..spec(DRAFT, Effect::External, 1) },
        ]);
        assert_eq!(r.validate(), Err(RegistryError::DraftNotReversible(DRAFT)));
    }

    #[test]
    fn one_draft_per_external_action() {
        let r = registry([
            spec(SEND, Effect::External, 1),
            ActionSpec { draft_for: Some(SEND), ..spec(DRAFT, Effect::LocalReversible, 1) },
            ActionSpec { draft_for: Some(SEND), ..spec(NOTE, Effect::Read, 1) },
        ]);
        assert_eq!(r.validate(), Err(RegistryError::DuplicateDraft { target: SEND, first: DRAFT, second: NOTE }));
    }

    #[test]
    fn compensation_with_matching_arity_is_valid() {
        let r = registry([
            ActionSpec { compensation: Some(UNSEND), ..spec(SEND, Effect::External, 2) },
            spec(UNSEND, Effect::External, 2),
        ]);
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn compensation_must_exist() {
        let r = registry([ActionSpec { compensation: Some(UNSEND), ..spec(SEND, Effect::External, 2) }]);
        assert_eq!(r.validate(), Err(RegistryError::UnknownTarget { action: SEND, target: UNSEND }));
    }

    #[test]
    fn compensation_cannot_be_self() {
        let r = registry([ActionSpec { compensation: Some(SEND), ..spec(SEND, Effect::External, 2) }]);
        assert_eq!(r.validate(), Err(RegistryError::SelfCompensation(SEND)));
    }

    #[test]
    fn compensation_arity_must_match() {
        let r = registry([
            ActionSpec { compensation: Some(UNSEND), ..spec(SEND, Effect::External, 2) },
            spec(UNSEND, Effect::External, 1),
        ]);
        assert_eq!(r.validate(), Err(RegistryError::CompensationArity { action: SEND, compensation: UNSEND }));
    }

    #[test]
    fn iter_is_in_id_order() {
        let r = registry([spec(NOTE, Effect::Read, 0), spec(SEND, Effect::External, 0)]);
        assert_eq!(r.iter().map(|a| a.id).collect::<Vec<_>>(), vec![SEND, NOTE]);
    }
}
