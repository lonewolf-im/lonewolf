// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn phase_completion_and_task_drop_balance_connections_once() {
    let capacity = Arc::new(Capacity::new());
    let mut connection = ConnectionCapacity::new(Arc::clone(&capacity));
    assert_eq!(capacity.gauge(Gauge::ConnectionsActive), 1);
    assert_eq!(capacity.gauge(Gauge::ConnectionsEstablishing), 1);
    connection.transition(
        Gauge::ConnectionsAuthenticating,
        Histogram::ConnectionAuthentication,
    );
    assert_eq!(
        capacity.histogram(Histogram::ConnectionEstablishment).count,
        1
    );
    assert_eq!(capacity.gauge(Gauge::ConnectionsEstablishing), 0);
    connection.transition(Gauge::ConnectionsBinding, Histogram::ConnectionBinding);
    connection.transition(Gauge::ConnectionsBound, Histogram::ConnectionBound);
    connection.finish();
    connection.finish();
    drop(connection);
    for histogram in [
        Histogram::ConnectionEstablishment,
        Histogram::ConnectionAuthentication,
        Histogram::ConnectionBinding,
        Histogram::ConnectionBound,
    ] {
        assert_eq!(capacity.histogram(histogram).count, 1);
        assert_eq!(capacity.histogram(histogram).abandoned_total, 0);
        assert_eq!(capacity.histogram(histogram).in_flight, 0);
    }
    let connection = ConnectionCapacity::new(Arc::clone(&capacity));
    drop(connection);
    assert_eq!(
        capacity
            .histogram(Histogram::ConnectionEstablishment)
            .abandoned_total,
        1
    );
    assert_eq!(capacity.counter(Counter::ConnectionsAccepted), 2);
    assert_eq!(capacity.counter(Counter::ConnectionsClosed), 2);
    for gauge in Gauge::ALL {
        assert_eq!(capacity.gauge(*gauge), 0);
    }
}
