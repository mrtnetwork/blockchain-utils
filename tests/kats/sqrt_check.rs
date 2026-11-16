use blockchain_utils::curve::pallas::Fe;
use blockchain_utils::curve::traits::FieldElement;
#[test]
fn sqrt_basic() {
    let four = Fe::one().add(&Fe::one()).add(&Fe::one()).add(&Fe::one());
    let r = four.sqrt().expect("sqrt(4)");
    assert!(r.mul(&r).ct_eq(&four) == 1, "sqrt(4)^2==4");
    // Nonsquare: -1? For pallas (p = 3 mod 4?), -1 may be square. Try 2? Just check determinism.
    // Known nonsquare test via legendre would need API; check sqrt(4) + sqrt(9).
    let nine = four.add(&four).add(&Fe::one());
    let r9 = nine.sqrt().expect("sqrt(9)");
    assert!(r9.mul(&r9).ct_eq(&nine) == 1, "sqrt(9)^2==9");
    eprintln!("sqrt works");
}
