use criterion::{criterion_group, criterion_main, Criterion};
use sl_compute::mpc::common_randomness::test_run_get_serverstate;
use sl_compute::types::{ArithmeticShare, FieldElement};

fn bench_a_to_b(c: &mut Criterion) {
    let share_p1 = ArithmeticShare::new(FieldElement::from(38829u64), FieldElement::from(12123u64));
    let share_p2 = ArithmeticShare::new(FieldElement::from(38830u64), FieldElement::from(26707u64));
    let share_p3 = ArithmeticShare::new(FieldElement::from(53413u64), FieldElement::from(26706u64));

    let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) = test_run_get_serverstate();

    c.bench_function("test_run_a_to_b", |b| {
        b.iter(|| {});
    });
}

criterion_group!(a_to_b, bench_a_to_b);

criterion_main!(a_to_b,);
