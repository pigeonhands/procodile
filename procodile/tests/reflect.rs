#![cfg(feature = "reflect")]
//! Confirms the `reflect` feature derives `facet::Facet` across every category
//! of public type, and that the roots() entry point covers the expected types.

use facet::Facet;
use procodile::{
    Address, LoadMethod, Module, Protection, Region, RegionKind,
    scan::{Value, ValueType},
};

fn assert_facet<'a, T: Facet<'a>>() {}

#[test]
fn every_category_is_reflected() {
    // repr(transparent) newtype over usize.
    assert_facet::<Address>();

    // Bitflags-like type: opaque, but impls Facet.
    assert_facet::<Protection>();

    // Plain C-like enum.
    assert_facet::<RegionKind>();

    // Struct with non-Facet fields (opaque).
    assert_facet::<Region>();
    assert_facet::<Module>();

    // Scan value types.
    assert_facet::<ValueType>();
    assert_facet::<Value>();

    // Injection method enum.
    assert_facet::<LoadMethod>();
}

#[test]
fn roots_are_exposed() {
    let roots = procodile::reflect::roots();
    assert_eq!(roots.len(), 4);
    let names: Vec<&str> = roots.iter().map(|s| s.type_identifier).collect();
    assert!(names.contains(&"Region"),    "Region not in roots");
    assert!(names.contains(&"Module"),    "Module not in roots");
    assert!(names.contains(&"ValueType"), "ValueType not in roots");
    assert!(names.contains(&"LoadMethod"), "LoadMethod not in roots");
}

#[test]
fn protection_is_opaque() {
    // Protection is reflected but opaque — its flag semantics live in const values,
    // not derive-accessible variants.
    let shape = <Protection as Facet>::SHAPE;
    // Opaque types have a User kind in facet's type system.
    assert!(
        matches!(shape.ty, facet::Type::User(_)),
        "Protection should be reflected as opaque (Type::User), got {:?}",
        shape.ty
    );
}
