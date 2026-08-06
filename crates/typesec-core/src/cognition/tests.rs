use super::CognitionEffect;

#[test]
fn effect_wire_values_are_explicit_and_closed() {
    assert_eq!(
        serde_json::to_string(&CognitionEffect::Mutated).unwrap(),
        r#""mutated""#
    );
    assert_eq!(
        serde_json::to_string(&CognitionEffect::NoChange).unwrap(),
        r#""no_change""#
    );
    assert!(serde_json::from_str::<CognitionEffect>(r#""unchanged""#).is_err());
}
