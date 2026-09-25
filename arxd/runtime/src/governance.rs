// Copyright (c) 2026 Arxium Protocol AG
// SPDX-License-Identifier: Apache-2.0

//! Dispatch for the governance variants — see `circuit-governance` for the
//! rules. Nothing here is role-gated: who may propose and vote is a
//! function of the validator set, which the circuit reads itself.

use xc_circuit::KvRead;
use xc_executor::BlockUpdates;
use xc_primitives::GovernanceAction;
use xc_storage::StorageError;

use crate::ChainAction;

pub(crate) fn submit<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    proposed: &GovernanceAction,
    description: &str,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    crate::asset::check_reason(description, "a proposal")?;
    let (_, governance) = circuit_governance::apply_submit(
        view,
        &action.sender,
        proposed.clone(),
        description,
        current_height,
    )?;
    Ok(BlockUpdates {
        governance,
        ..Default::default()
    })
}

pub(crate) fn vote<V: KvRead<Error = StorageError>>(
    view: &V,
    action: &ChainAction,
    proposal: u64,
    approve: bool,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    Ok(BlockUpdates {
        governance: circuit_governance::apply_vote(
            view,
            &action.sender,
            proposal,
            approve,
            current_height,
        )?,
        ..Default::default()
    })
}

pub(crate) fn execute<V: KvRead<Error = StorageError>>(
    view: &V,
    proposal: u64,
    current_height: u64,
) -> anyhow::Result<BlockUpdates> {
    let (governance, accounts) = circuit_governance::apply_execute(view, proposal, current_height)?;
    Ok(BlockUpdates {
        governance,
        accounts,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use crate::ActionPayload;
    use crate::test_support::*;
    use std::collections::HashMap;
    use xc_circuit::{ChainParamsKey, KvRead, ProposalKey, ValidatorSetKey};
    use xc_primitives::{
        Action, Address, ChainParams, GovernanceAction, ProposalStatus, VotingPower,
        treasury_account,
    };
    use xc_storage::BlockView;

    fn run(
        view: &mut BlockView<'_>,
        action: Action<ActionPayload>,
        height: u64,
    ) -> anyhow::Result<()> {
        let updates = crate::dispatch(
            &action,
            view,
            &operator_lookup,
            &operator_validators_lookup,
            &[],
            height,
            &no_bls_owner,
            0,
        )?;
        view.apply_accounts(&updates.accounts)?;
        view.apply_governance(&updates.governance);
        Ok(())
    }

    /// The whole lifecycle through `dispatch`: a validator proposes a
    /// treasury grant, the set votes it through, anyone executes it, and
    /// the treasury row the block reward feeds is what pays.
    #[test]
    fn treasury_spend_lifecycle_through_dispatch() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let bob = Address::from_pubkey_bytes(&[2u8; 32]).unwrap();
        let grantee = Address::from_pubkey_bytes(&[3u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([
                (alice.clone(), funded(FEE_BUDGET * 4)),
                (bob.clone(), funded(FEE_BUDGET * 4)),
                (grantee.clone(), funded(FEE_BUDGET)),
                (treasury_account(), funded(1_000)),
            ]),
            HashMap::new(),
        );
        view.put(
            &ValidatorSetKey(0),
            &std::collections::BTreeMap::from([
                (alice.clone(), VotingPower(7_000)),
                (bob.clone(), VotingPower(3_000)),
            ]),
        )
        .unwrap();
        view.put(
            &ChainParamsKey,
            &ChainParams {
                voting_period_blocks: 5,
                ..Default::default()
            },
        )
        .unwrap();
        let act = |sender: &Address, nonce, payload| Action {
            sender: sender.clone(),
            nonce,
            signature: None,
            payload,
        };

        // A non-validator can't propose.
        let err = run(
            &mut view,
            act(
                &grantee,
                0,
                ActionPayload::SubmitProposal {
                    action: GovernanceAction::TreasurySpend {
                        to: grantee.clone(),
                        amount: 600,
                    },
                    description: "grant".into(),
                },
            ),
            1,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not in the active validator set"),
            "{err}"
        );

        run(
            &mut view,
            act(
                &alice,
                0,
                ActionPayload::SubmitProposal {
                    action: GovernanceAction::TreasurySpend {
                        to: grantee.clone(),
                        amount: 600,
                    },
                    description: "grant".into(),
                },
            ),
            1,
        )
        .unwrap();
        run(
            &mut view,
            act(
                &alice,
                1,
                ActionPayload::VoteProposal {
                    proposal: 0,
                    approve: true,
                },
            ),
            2,
        )
        .unwrap();
        run(
            &mut view,
            act(
                &bob,
                0,
                ActionPayload::VoteProposal {
                    proposal: 0,
                    approve: false,
                },
            ),
            2,
        )
        .unwrap();
        // Too early.
        assert!(
            run(
                &mut view,
                act(&grantee, 0, ActionPayload::ExecuteProposal { proposal: 0 }),
                5
            )
            .is_err()
        );
        run(
            &mut view,
            act(&grantee, 0, ActionPayload::ExecuteProposal { proposal: 0 }),
            6,
        )
        .unwrap();

        let proposal = view.get(&ProposalKey(0)).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
        assert_eq!(
            view.get(&xc_circuit::AccountKey(&treasury_account()))
                .unwrap()
                .unwrap()
                .balance,
            400
        );
        let grantee_entry = view
            .get(&xc_circuit::AccountKey(&grantee))
            .unwrap()
            .unwrap();
        // Rejected actions charge nothing; one execute fee paid, 600 received.
        assert_eq!(
            grantee_entry.balance,
            FEE_BUDGET + 600
                - fee_of(&act(
                    &grantee,
                    0,
                    ActionPayload::ExecuteProposal { proposal: 0 }
                ))
        );
    }

    /// A passed `SetChainParams` retunes the fee for the very next action —
    /// the D-20 point: no release, no restart.
    #[test]
    fn a_voted_fee_change_is_charged_on_the_next_action() {
        let alice = Address::from_pubkey_bytes(&[1u8; 32]).unwrap();
        let db = temp_db();
        let mut view = seeded_view(
            &db,
            HashMap::from([(alice.clone(), funded(FEE_BUDGET * 4))]),
            HashMap::new(),
        );
        view.put(
            &ValidatorSetKey(0),
            &std::collections::BTreeMap::from([(alice.clone(), VotingPower(10_000))]),
        )
        .unwrap();
        let mut params = ChainParams {
            voting_period_blocks: 1,
            ..Default::default()
        };
        view.put(&ChainParamsKey, &params).unwrap();
        let act = |nonce, payload| Action {
            sender: alice.clone(),
            nonce,
            signature: None,
            payload,
        };
        params.action_fee *= 10;
        run(
            &mut view,
            act(
                0,
                ActionPayload::SubmitProposal {
                    action: GovernanceAction::SetChainParams(params.clone()),
                    description: "10x fee".into(),
                },
            ),
            1,
        )
        .unwrap();
        run(
            &mut view,
            act(
                1,
                ActionPayload::VoteProposal {
                    proposal: 0,
                    approve: true,
                },
            ),
            1,
        )
        .unwrap();
        let balance = |view: &BlockView<'_>| {
            view.get(&xc_circuit::AccountKey(&alice))
                .unwrap()
                .unwrap()
                .balance
        };
        let old_fee = crate::metering::action_fee_for(
            &ChainParams::default(),
            crate::metering::action_weight(&act(0, ActionPayload::ExecuteProposal { proposal: 0 })),
        );
        let b0 = balance(&view);
        run(
            &mut view,
            act(2, ActionPayload::ExecuteProposal { proposal: 0 }),
            2,
        )
        .unwrap();
        assert_eq!(
            b0 - balance(&view),
            old_fee,
            "the execute itself pays the old fee"
        );
        assert_eq!(view.get(&ChainParamsKey).unwrap().unwrap(), params);

        // The very next action pays the new one.
        let next = ActionPayload::SubmitProposal {
            action: GovernanceAction::SetChainParams(params.clone()),
            description: "again".into(),
        };
        let new_fee = crate::metering::action_fee_for(
            &params,
            crate::metering::action_weight(&act(0, next.clone())),
        );
        let b1 = balance(&view);
        run(&mut view, act(3, next), 3).unwrap();
        assert_eq!(b1 - balance(&view), new_fee);
        assert!(new_fee > old_fee);
    }
}
