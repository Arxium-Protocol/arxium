// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Fixed-menu account authorization, enforced against the block overlay.
use xc_primitives::*;

fn invalid(message: &'static str) -> SignatureError {
    SignatureError::BadMultisig(message)
}

pub fn apply_policy_action(
    account: &mut AccountEntry,
    action: &AccountPolicyAction,
    auth: PolicyAuthorization,
    height: u64,
) -> Result<(), SignatureError> {
    use AccountPolicyAction::*;
    use PolicyAuthorization::*;
    // Guardians can only propose or finalize recovery, never spend/administer.
    if auth != Owner
        && !(auth == Guardian && matches!(action, StartRecovery { .. } | ExecuteRecovery))
    {
        return Err(invalid("capability cannot manage account policy"));
    }
    if let SetPolicy { policy } = action {
        if auth != Owner {
            return Err(invalid("only owners may set policy"));
        }
        policy.validate()?;
        // Existing policy spending windows cannot be reset by re-submission.
        // An owner deliberately replacing the menu may change its limits.
        let counters = account
            .programmable
            .as_ref()
            .map(|a| a.counters.clone())
            .unwrap_or_default();
        let counters = counters
            .into_iter()
            .filter(|c| {
                account.programmable.as_ref().is_some_and(|old| {
                    old.policy
                        .limits
                        .iter()
                        .any(|l| l.asset == c.asset && policy.limits.iter().any(|new| new == l))
                })
            })
            .collect();
        account.programmable = Some(ProgrammableAccount {
            policy: policy.clone(),
            counters,
            pending_recovery: None,
        });
        return Ok(());
    }
    let state = account
        .programmable
        .as_mut()
        .ok_or(invalid("account has no policy"))?;
    match action {
        RotateMembers { owners } => {
            owners.validate()?;
            state.policy.owners = owners.clone();
            state.policy.sessions.clear();
            state.pending_recovery = None;
        }
        AddSession { session } => {
            if session.expires_at <= height {
                return Err(invalid("session already expired"));
            }
            if state
                .policy
                .sessions
                .iter()
                .any(|s| s.public_key == session.public_key)
            {
                return Err(invalid("session already exists; revoke before replacing"));
            }
            state.policy.sessions.push(session.clone());
            state.policy.validate()?;
        }
        RevokeSession { public_key } => {
            state
                .policy
                .sessions
                .retain(|s| &s.public_key != public_key);
        }
        StartRecovery { owners } => {
            if auth != Guardian {
                return Err(invalid("recovery requires guardians"));
            }
            owners.validate()?;
            if state.pending_recovery.is_some() {
                return Err(invalid("recovery already pending"));
            }
            let recovery = state
                .policy
                .recovery
                .as_ref()
                .ok_or(invalid("recovery disabled"))?;
            let execute_after = height
                .checked_add(recovery.delay_blocks)
                .ok_or(invalid("recovery height overflow"))?;
            state.pending_recovery = Some(PendingRecovery {
                owners: owners.clone(),
                execute_after,
            });
        }
        CancelRecovery => {
            state.pending_recovery = None;
        }
        ExecuteRecovery => {
            if auth != Guardian {
                return Err(invalid("recovery requires guardians"));
            }
            let pending = state
                .pending_recovery
                .as_ref()
                .ok_or(invalid("no pending recovery"))?;
            if height < pending.execute_after {
                return Err(invalid("recovery timelock has not elapsed"));
            }
            state.policy.owners = pending.owners.clone();
            state.policy.sessions.clear();
            state.pending_recovery = None;
        }
        SetPolicy { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// Debit totals and recipients are derived from the actual proposed updates,
/// not caller-supplied witness claims. Limits use consensus height / period.
pub fn enforce_spending(
    state: &mut ProgrammableAccount,
    auth: PolicyAuthorization,
    height: u64,
    spends: &[(SpendAsset, u128)],
    recipients: &[Address],
    session_transfer: Option<(&SpendAsset, &Address, u128)>,
) -> Result<(), SignatureError> {
    if auth == PolicyAuthorization::Guardian {
        return Err(invalid("guardians cannot authorize spending"));
    }
    if let Some(allowlist) = &state.policy.recipients
        && recipients.iter().any(|to| !allowlist.contains(to))
    {
        return Err(invalid("recipient is not allowed by account policy"));
    }
    for limit in &state.policy.limits {
        let amount = spends
            .iter()
            .filter(|(asset, _)| asset == &limit.asset)
            .try_fold(0u128, |total, (_, amount)| total.checked_add(*amount))
            .ok_or(invalid("spending amount overflow"))?;
        let window = height / limit.period_blocks;
        let i = match state.counters.iter().position(|c| c.asset == limit.asset) {
            Some(i) => i,
            None => {
                state.counters.push(SpendCounter {
                    asset: limit.asset.clone(),
                    window,
                    spent: 0,
                });
                state.counters.len() - 1
            }
        };
        let counter = &mut state.counters[i];
        if window < counter.window {
            return Err(invalid("spending clock moved backwards"));
        }
        if counter.window != window {
            counter.window = window;
            counter.spent = 0;
        }
        counter.spent = counter
            .spent
            .checked_add(amount)
            .ok_or(invalid("spending counter overflow"))?;
        if counter.spent > limit.amount {
            return Err(invalid("period spending limit exceeded"));
        }
    }
    if let PolicyAuthorization::Session(i) = auth {
        let (asset, to, amount) = session_transfer.ok_or(invalid("sessions are transfer-only"))?;
        let session = state
            .policy
            .sessions
            .get_mut(i)
            .ok_or(invalid("session revoked"))?;
        if height >= session.expires_at
            || asset != &session.asset
            || !session.recipients.contains(to)
        {
            return Err(invalid("session expired or transfer outside scope"));
        }
        session.allowance = session
            .allowance
            .checked_sub(amount)
            .ok_or(invalid("session allowance exceeded"))?;
    }
    Ok(())
}
