use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use typesec_core::{PolicyEngine, ResourceId, SubjectId};
use typesec_rbac::RbacEngine;

const HIT_POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:bench"
    roles: [analyst]
"#;

fn miss_policy() -> String {
    let mut yaml = String::from("roles:\n");
    for idx in 0..50 {
        yaml.push_str(&format!(
            "  - name: role_{idx}\n    permissions: [read]\n    resources: [\"reports/{idx}/*\"]\n"
        ));
    }
    yaml.push_str("assignments:\n");
    yaml.push_str("  - subject: \"agent:other\"\n    roles: [role_0]\n");
    yaml
}

fn policy_with_permissions(count: usize) -> String {
    let permissions = (0..count)
        .map(|idx| format!("action_{idx}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
roles:
  - name: scaled
    permissions: [{permissions}]
    resources: ["reports/*"]
assignments:
  - subject: "agent:bench"
    roles: [scaled]
"#
    )
}

fn bench_rbac_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbac_check");
    group.throughput(Throughput::Elements(1));

    let engine = RbacEngine::from_yaml(HIT_POLICY).expect("policy");
    let subject = SubjectId::from("agent:bench");
    let resource = ResourceId::from("reports/q1");

    group.bench_function("exact_hit", |b| {
        b.iter(|| {
            black_box(engine.check(black_box(&subject), black_box("read"), black_box(&resource)))
        })
    });

    let yaml = miss_policy();
    let engine = RbacEngine::from_yaml(&yaml).expect("policy");

    group.bench_function("unassigned_subject_miss", |b| {
        b.iter(|| {
            black_box(engine.check(
                black_box(&subject),
                black_box("write"),
                black_box(&resource),
            ))
        })
    });

    for permission_count in [1, 16, 64] {
        let policy = policy_with_permissions(permission_count);
        let engine = RbacEngine::from_yaml(&policy).expect("scaled policy");
        let action = format!("action_{}", permission_count - 1);
        group.bench_with_input(
            BenchmarkId::new("last_permission_hit", permission_count),
            &permission_count,
            |b, _| {
                b.iter(|| {
                    black_box(engine.check(
                        black_box(&subject),
                        black_box(&action),
                        black_box(&resource),
                    ))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_rbac_checks);
criterion_main!(benches);
