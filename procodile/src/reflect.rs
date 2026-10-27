//! Compile-time reflection via [`facet`], for registering procodile's types with
//! an external consumer such as a scripting runtime or inspector. Enabled by the
//! `reflect` feature.
//!
//! Every public data type derives [`facet::Facet`], so a consumer never registers
//! them one by one: it starts from the shapes in [`roots`] and walks each shape's
//! fields and variants (which reference other shapes) to reach every reflected type
//! transitively.
//!
//! One type is deliberately [opaque](facet::Opaque) — it appears in the graph as a
//! sized black box rather than exposing its contents:
//!
//! - [`Protection`](crate::Protection): its semantics are carried by `const` flag
//!   values (`READ`, `WRITE`, …) that no derive macro can surface. Inspect them via
//!   [`Protection::contains`] or the named constants directly.
//!
//! [`ProcessHandle`](crate::ProcessHandle) and [`Process`](crate::Process) are not
//! reflected: they wrap platform-specific handle types whose layouts differ per OS.

use facet::{Facet, Shape};

use crate::{Module, Region, LoadMethod, scan::ValueType};

/// The shapes of procodile's entry-point types. Walk each shape's fields and
/// variants to reach every reflected type in the crate.
pub fn roots() -> &'static [&'static Shape] {
    &[
        <Region as Facet>::SHAPE,
        <Module as Facet>::SHAPE,
        <ValueType as Facet>::SHAPE,
        <LoadMethod as Facet>::SHAPE,
    ]
}
