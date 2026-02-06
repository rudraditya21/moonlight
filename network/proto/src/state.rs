use corelib::error::{CoreError, CoreResult};
use std::collections::HashMap;
use std::hash::Hash;

pub trait StateMachine {
    type State: Copy + Eq + Hash;
    type Event: Copy + Eq + Hash;

    fn state(&self) -> Self::State;
    fn on_event(&mut self, event: Self::Event) -> CoreResult<()>;
}

#[derive(Debug, Clone)]
pub struct StateTransition<S: Copy + Eq + Hash, E: Copy + Eq + Hash> {
    transitions: HashMap<(S, E), S>,
}

impl<S: Copy + Eq + Hash, E: Copy + Eq + Hash> StateTransition<S, E> {
    pub fn new() -> Self {
        Self {
            transitions: HashMap::new(),
        }
    }

    pub fn allow(mut self, from: S, event: E, to: S) -> Self {
        self.transitions.insert((from, event), to);
        self
    }

    pub fn next(&self, from: S, event: E) -> CoreResult<S> {
        self.transitions
            .get(&(from, event))
            .copied()
            .ok_or_else(|| CoreError::Message("invalid state transition".to_string()))
    }
}
