use super::*;
use typesec_core::secure_value::{Internal, Secret, Sensitive};

#[test]
fn label_order_is_least_to_most_restrictive() {
    assert!(Label::Public < Label::Internal);
    assert!(Label::Internal < Label::Sensitive);
    assert!(Label::Sensitive < Label::Secret);
}

#[test]
fn join_takes_the_more_restrictive() {
    assert_eq!(Label::Public.join(Label::Sensitive), Label::Sensitive);
    assert_eq!(Label::Secret.join(Label::Public), Label::Secret);
    assert_eq!(Label::Internal.join(Label::Internal), Label::Internal);
}

#[test]
fn unknown_names_fail_closed_to_secret() {
    assert_eq!(Label::from_name("public"), Label::Public);
    assert_eq!(Label::from_name("nonsense"), Label::Secret);
    assert_eq!(Label::from_name(""), Label::Secret);
}

#[test]
fn clearance_maps_type_labels_to_runtime_ceilings() {
    assert_eq!(<Public as Clearance>::ceiling(), Label::Public);
    assert_eq!(<Internal as Clearance>::ceiling(), Label::Internal);
    assert_eq!(<Sensitive as Clearance>::ceiling(), Label::Sensitive);
    assert_eq!(<Secret as Clearance>::ceiling(), Label::Secret);
}
