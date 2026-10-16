// SPDX-License-Identifier: Apache-2.0

use super::*;

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz_012345";
const THUMBPRINT: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

fn host(dns_name: &str) -> ManagedHost {
    ManagedHost {
        xmpp_domain: dns_name.into(),
        dns_name: dns_name.into(),
    }
}

fn registry() -> Challenges {
    Challenges::new(&[host("one.example"), host("two.example")]).unwrap()
}

#[test]
fn lease_owns_exact_host_and_token() {
    let challenges = registry();
    let authorization = format!("{TOKEN}.{THUMBPRINT}");
    let lease = challenges
        .publish("one.example", TOKEN, &authorization)
        .unwrap();
    assert_eq!(
        challenges.lookup("ONE.EXAMPLE", TOKEN).unwrap(),
        authorization
    );
    assert!(challenges.lookup("two.example", TOKEN).is_none());
    assert!(challenges.lookup("one.example", "unknown").is_none());
    assert!(matches!(
        challenges.publish("one.example", TOKEN, &authorization),
        Err(ChallengeError::AlreadyPublished)
    ));
    assert!(matches!(
        challenges.publish("other.example", TOKEN, &authorization),
        Err(ChallengeError::UnconfiguredHost)
    ));
    drop(lease);
    assert!(challenges.lookup("one.example", TOKEN).is_none());
}

#[test]
fn clear_preserves_new_generation_when_old_lease_drops() {
    let challenges = registry();
    let authorization = format!("{TOKEN}.{THUMBPRINT}");
    let old = challenges
        .publish("one.example", TOKEN, &authorization)
        .unwrap();
    challenges.clear();
    let current = challenges
        .publish("one.example", TOKEN, &authorization)
        .unwrap();
    drop(old);
    assert!(challenges.lookup("one.example", TOKEN).is_some());
    assert_eq!(challenges.inner.lock().active, 1);
    drop(current);
    assert_eq!(challenges.inner.lock().active, 0);
}

#[test]
fn cancellation_removes_lease() {
    let challenges = registry();
    let authorization = format!("{TOKEN}.{THUMBPRINT}");
    let lease = challenges
        .publish("one.example", TOKEN, &authorization)
        .unwrap();
    let cancelled = async move {
        let _lease = lease;
        std::future::pending::<()>().await;
    };
    drop(cancelled);
    assert!(challenges.lookup("one.example", TOKEN).is_none());
}

#[test]
fn active_entries_are_globally_bounded() {
    let hosts: Vec<_> = (0..65)
        .map(|index| host(&format!("h{index}.example")))
        .collect();
    let challenges = Challenges::new(&hosts).unwrap();
    let authorization = format!("{TOKEN}.{THUMBPRINT}");
    let mut leases = Vec::new();
    for host in &hosts[..64] {
        leases.push(
            challenges
                .publish(&host.dns_name, TOKEN, &authorization)
                .unwrap(),
        );
    }
    assert!(matches!(
        challenges.publish(&hosts[64].dns_name, TOKEN, &authorization),
        Err(ChallengeError::Capacity)
    ));
    leases.pop();
    assert!(
        challenges
            .publish(&hosts[64].dns_name, TOKEN, &authorization)
            .is_ok()
    );
}

#[test]
fn tokens_and_authorizations_are_strictly_bounded() {
    let challenges = registry();
    for token in [
        "a".repeat(21),
        "a".repeat(257),
        "a".repeat(21) + "/",
        "a".repeat(21) + "=",
        "a".repeat(21) + "é",
        "a".repeat(21) + "\n",
    ] {
        assert!(matches!(
            challenges.publish("one.example", &token, &format!("{token}.{THUMBPRINT}")),
            Err(ChallengeError::InvalidToken)
        ));
    }
    for authorization in [
        format!("{TOKEN}.{}", "a".repeat(42)),
        format!("{TOKEN}.{}", "a".repeat(44)),
        format!("{TOKEN}.{THUMBPRINT}\n"),
        format!("wrong.{THUMBPRINT}"),
        format!("{TOKEN}.{}=", "a".repeat(42)),
    ] {
        assert!(matches!(
            challenges.publish("one.example", TOKEN, &authorization),
            Err(ChallengeError::InvalidAuthorization)
        ));
    }
    for length in [22, 256] {
        let token = "_".repeat(length);
        let lease = challenges
            .publish("one.example", &token, &format!("{token}.{THUMBPRINT}"))
            .unwrap();
        drop(lease);
    }
}

#[test]
fn configured_names_must_be_canonical_and_unique() {
    for name in [
        "ONE.EXAMPLE",
        "127.0.0.1",
        "one.example.",
        "one_thing.example",
        "é.example",
    ] {
        assert!(matches!(
            Challenges::new(&[host(name)]),
            Err(ChallengeError::InvalidHost)
        ));
    }
    assert!(Challenges::new(&[host("one.example"), host("one.example")]).is_err());
}
