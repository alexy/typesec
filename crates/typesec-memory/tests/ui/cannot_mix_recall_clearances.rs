// A Recall carries its clearance as a type parameter, so a Sensitive-clearance
// recall cannot be passed where a Public-clearance one is expected. This is the
// information-flow guarantee at the recall boundary.

use typesec_core::secure_value::{Public, Sensitive};
use typesec_memory::Recall;

fn only_public(_: Recall<Public>) {}

fn misuse(sensitive: Recall<Sensitive>) {
    // Passing a Sensitive recall where Public is required must not compile.
    only_public(sensitive);
}

fn main() {}
