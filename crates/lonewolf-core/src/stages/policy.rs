// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::policy::{Direction, PolicyRequest, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, Storage};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::StanzaType;

use super::{Stage, StageFailure};
use crate::delivery::{report_failure, report_handler_failure, storage_failure};
use crate::router::RouterHandle;

pub(crate) struct Check<'a> {
    pub(crate) account: &'a AccountKey,
    pub(crate) direction: Direction,
    pub(crate) peer: JidRef<'a>,
}

pub(crate) async fn evaluate<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    if checks
        .iter()
        .all(|check| stage.router.policies(check.account.domain()).is_empty())
    {
        return Ok(Verdict::Allow);
    }
    let transaction = stage.storage.begin_read().await.map_err(|error| {
        report_failure(
            storage_failure(error, "policy_begin_read"),
            checks[0].account,
        );
        StageFailure
    })?;
    evaluate_in(stage.router, &transaction, kind, checks).await
}

pub(crate) async fn evaluate_in<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    transaction: &RedbRead,
    kind: StanzaType,
    checks: &[Check<'_>],
) -> Result<Verdict, StageFailure> {
    let mut verdict = Verdict::Allow;
    let mut decided_by = None;
    'checks: for check in checks {
        for (name, handler) in router.policies(check.account.domain()) {
            let next = match handler
                .check(
                    PolicyRequest {
                        account: check.account,
                        direction: check.direction,
                        peer: check.peer,
                        kind,
                    },
                    transaction,
                )
                .await
            {
                Ok(verdict) => verdict,
                Err(error) => {
                    report_handler_failure(&error, check.account);
                    Verdict::Reject {
                        condition: error.condition(),
                        application: None,
                    }
                }
            };
            let strictest = verdict.strictest(next);
            if strictest != verdict {
                decided_by = Some((check, name));
            }
            verdict = strictest;
            if verdict == Verdict::Drop {
                break 'checks;
            }
        }
    }
    let verdict = verdict.for_stanza(kind);
    if let Some((check, name)) = decided_by {
        tracing::debug!(
            account_jid = ?check.account.as_str(),
            direction = ?check.direction,
            stanza_kind = kind.kind().as_str(),
            extension = name,
            outcome = if verdict == Verdict::Drop { "dropped" } else { "rejected" },
            "policy decided"
        );
    }
    Ok(verdict)
}
