// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::RejectionReport;

#[test]
fn first_rejection_reports_immediately_and_intervals_include_the_boundary() {
    let mut report = RejectionReport::default();
    let now = Instant::now();

    assert_eq!(report.record(now), Some(1));
    assert_eq!(report.record(now), None);
    assert_eq!(report.record(now + Duration::from_nanos(999_999_999)), None);
    assert_eq!(report.record(now + Duration::from_secs(1)), Some(3));
    assert_eq!(report.record(now + Duration::from_secs(2)), Some(1));
}

#[test]
fn earlier_timestamp_does_not_move_the_reporting_deadline() {
    let mut report = RejectionReport::default();
    let earlier = Instant::now();
    let now = earlier + Duration::from_secs(1);

    assert_eq!(report.record(now), Some(1));
    assert_eq!(report.record(earlier), None);
    assert_eq!(report.record(now + Duration::from_nanos(999_999_999)), None);
    assert_eq!(report.record(now + Duration::from_secs(1)), Some(3));
}

#[test]
fn rejection_count_saturates_and_resets_after_reporting() {
    let now = Instant::now();
    let mut report = RejectionReport {
        last_report_at: Some(now),
        unreported_rejections: u64::MAX - 1,
    };

    assert_eq!(report.record(now), None);
    assert_eq!(report.record(now), None);
    assert_eq!(report.record(now + Duration::from_secs(1)), Some(u64::MAX));
    assert_eq!(report.record(now + Duration::from_secs(2)), Some(1));
}
