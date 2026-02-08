/// Feature-gated logging macros.
///
/// When the `tracing` feature is enabled, these re-export the corresponding
/// macros from the `tracing` crate. When disabled, they compile to no-ops.

#[cfg(feature = "tracing")]
pub use tracing::{trace, debug, info, warn, error, info_span, debug_span, trace_span};

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! info_span {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! debug_span {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! trace_span {
    ($($t:tt)*) => {()};
}

#[cfg(not(feature = "tracing"))]
pub use crate::{trace, debug, info, warn, error, info_span, debug_span, trace_span};
