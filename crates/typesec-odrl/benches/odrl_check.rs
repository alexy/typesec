use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use typesec_odrl::OdrlEngine;
use typesec_odrl::constraint::ConstraintContext;

fn odrl_policy(policy_count: usize) -> String {
    let mut yaml = String::from("policies:\n");
    for idx in 0..policy_count {
        yaml.push_str(&format!(
            r#"  - uid: "policy-{idx}"
    type: Set
    rules:
      - type: permission
        assignee: "agent:bench"
        action: read
        target: "reports/{idx}/*"
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: analytics
"#
        ));
    }
    yaml
}

fn irrelevant_policy(policy_count: usize) -> String {
    let mut yaml = String::from("policies:\n");
    for idx in 0..policy_count {
        yaml.push_str(&format!(
            r#"  - uid: "irrelevant-{idx}"
    type: Set
    rules:
      - type: permission
        assignee: "agent:{idx}"
        action: read
        target: "reports/{idx}/*"
"#
        ));
    }
    yaml
}

fn bench_odrl_checks(c: &mut Criterion) {
    let context = ConstraintContext::default().with_purpose("analytics");
    let mut group = c.benchmark_group("odrl_check");
    group.throughput(Throughput::Elements(1));

    for policy_count in [1, 10, 100] {
        let yaml = odrl_policy(policy_count);
        let engine = OdrlEngine::from_yaml(&yaml).expect("policy");
        let resource = format!("reports/{}/q1", policy_count - 1);
        group.bench_with_input(
            BenchmarkId::new("constrained_last_target_hit", policy_count),
            &policy_count,
            |b, _| {
                b.iter(|| {
                    black_box(engine.check_with_context(
                        black_box("agent:bench"),
                        black_box("read"),
                        black_box(&resource),
                        black_box(&context),
                    ))
                })
            },
        );
    }

    let yaml = irrelevant_policy(1_000);
    let engine = OdrlEngine::from_yaml(&yaml).expect("policy");
    group.bench_function("indexed_miss_1000_irrelevant_rules", |b| {
        b.iter(|| {
            black_box(engine.check_with_context(
                black_box("agent:bench"),
                black_box("read"),
                black_box("reports/missing/q1"),
                black_box(&context),
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_odrl_checks);
criterion_main!(benches);
