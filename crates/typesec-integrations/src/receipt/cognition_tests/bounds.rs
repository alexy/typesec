use super::*;

#[test]
fn identity_limit_is_inclusive() {
    let setters: [fn(&mut CognitionCommitReceipt, String); 6] = [
        |receipt, value| receipt.subject = value,
        |receipt, value| receipt.resource = value,
        |receipt, value| receipt.job_id = value,
        |receipt, value| receipt.backend_commit_id = value,
        |receipt, value| receipt.prior_version = value,
        |receipt, value| receipt.resulting_version = value,
    ];
    for setter in setters {
        let mut receipt = claims();
        setter(
            &mut receipt,
            "x".repeat(cognition::validation::MAX_IDENTITY_BYTES),
        );
        receipt.validate().unwrap();
    }
}

#[test]
fn affected_id_count_limit_is_inclusive() {
    let mut receipt = claims();
    receipt.affected_ids = (0..cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    receipt.validate().unwrap();

    receipt.affected_ids = (0..=cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    assert_fixed_error(
        receipt.validate().unwrap_err(),
        "invalid cognition receipt affected IDs",
    );
}

#[test]
fn receipt_bounds_aggregate_affected_id_bytes() {
    let mut receipt = claims();
    let exact_aggregate =
        cognition::validation::MAX_AFFECTED_ID_BYTES / cognition::validation::MAX_IDENTITY_BYTES;
    receipt.affected_ids = large_sorted_ids(exact_aggregate);
    receipt.validate().unwrap();

    receipt.affected_ids = large_sorted_ids(exact_aggregate + 1);
    assert_fixed_error(
        receipt.validate().unwrap_err(),
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
