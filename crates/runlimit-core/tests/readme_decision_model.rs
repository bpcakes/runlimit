//! Compile and behavior check for the README decision-model example.

use std::time::Duration;

use runlimit_core::{Decision, DecisionView, Denial, QuotaDenial};

fn describe(decision: &Decision) -> String {
    match decision.view() {
        DecisionView::Allowed {
            capacity,
            available,
            ..
        } => {
            format!("admitted; {available} of {capacity} left")
        }
        DecisionView::ShadowDenied { denial } => format!(
            "admitted; quota of {} would have denied for {:?}",
            denial.capacity(),
            denial.retry_after(),
        ),
        DecisionView::Denied { denial } => match denial.quota() {
            Some(quota) => format!("rejected; retry after {:?}", quota.retry_after()),
            None => "rejected; backend capacity".to_owned(),
        },
    }
}

#[test]
fn every_outcome_is_described_without_a_catch_all_on_the_view() {
    let quota = QuotaDenial::try_new(8, Duration::from_secs(30)).unwrap();
    assert_eq!(
        describe(&Decision::try_allowed(8, 7, Duration::from_secs(60)).unwrap()),
        "admitted; 7 of 8 left"
    );
    assert_eq!(
        describe(&Decision::shadow_denied(quota)),
        "admitted; quota of 8 would have denied for 30s"
    );
    assert_eq!(
        describe(&Decision::denied(quota)),
        "rejected; retry after 30s"
    );
    assert_eq!(
        describe(&Decision::denied(Denial::storage_capacity(None))),
        "rejected; backend capacity"
    );
}
