//! Presentational + stateful components for the GritShield console.
//!
//! Each is annotated with `#[component]`, which synthesises a `<Name>Props`
//! struct per parameter. Shared state is never threaded as props — components
//! pull the single `AppState` out of context with `use_context`.

pub mod control_panel;
pub mod drop_zone;
pub mod log_terminal;
pub mod metrics_bar;
pub mod threat_panel;
pub mod top_bar;

// Glob re-export: `view!` references both the component function and its
// generated `<Name>Props` struct, so a single `use crate::components::*;`
// brings everything into scope.
pub use control_panel::*;
pub use drop_zone::*;
pub use log_terminal::*;
pub use metrics_bar::*;
pub use threat_panel::*;
pub use top_bar::*;
