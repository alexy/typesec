use super::*;

#[test]
fn identity_limit_is_inclusive() {
    let setters: [fn(&mut CognitionCommitReceiptClaims, String); 6] = [
        |claims, value| claims.subject = value,
        |claims, value| claims.resource = value,
        |claims, value| claims.job_id = value,
        |claims, value| claims.backend_commit_id = value,
        |claims, value| claims.prior_version = value,
        |claims, value| claims.resulting_version = value,
    ];
    for setter in setters {
        let mut claims = complete_claims();
        setter(
            &mut claims,
            "x".repeat(cognition::validation::MAX_IDENTITY_BYTES),
        );
        CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap();
    }
}

#[test]
fn affected_id_count_limit_is_inclusive() {
    let mut exact = complete_claims();
    exact.affected_ids = (0..cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    CognitionCommitReceipt::new(exact, TimeDelta::minutes(5)).unwrap();

    let mut over = complete_claims();
    over.affected_ids = (0..=cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    assert_fixed_error(
        CognitionCommitReceipt::new(over, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt affected IDs",
    );
}

#[test]
fn receipt_bounds_aggregate_affected_id_bytes() {
    let exact_aggregate =
        cognition::validation::MAX_AFFECTED_ID_BYTES / cognition::validation::MAX_IDENTITY_BYTES;
    let mut exact = complete_claims();
    exact.affected_ids = large_sorted_ids(exact_aggregate);
    CognitionCommitReceipt::new(exact, TimeDelta::minutes(5)).unwrap();

    let mut over = complete_claims();
    over.affected_ids = large_sorted_ids(exact_aggregate + 1);
    assert_fixed_error(
        CognitionCommitReceipt::new(over, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt affected IDs",
    );
}

fn large_sorted_ids(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| {
            let prefix = format!("{index:04}:");
            format!(
                "{prefix}{}",
                "x".repeat(cognition::validation::MAX_IDENTITY_BYTES - prefix.len())
            )
        })
        .collect()
}
