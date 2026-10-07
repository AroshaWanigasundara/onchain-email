//! Benchmarking setup for pallet-numail
//!
//! PHASE 9: Worst-case benchmarks for all 8 extrinsics.
//! - `create_mailbox`: max folders (worst case = many folder declarations)
//! - `send_mail`: max recipients + max attachments (heaviest extrinsic)
//! - `mark_read`: minimal variance, straightforward state transition
//! - `tombstone`: minimal variance, index removal
//! - `move_to_folder`: two index mutations + folder existence check
//! - `set_mailbox_policy`: simple storage update
//! - `block_sender`: worst case = blocklist nearly full (linear search on insert)
//! - `unblock_sender`: worst case = blocklist full (linear filter across all entries)
//! - `system_notice`: max recipients (like send_mail but bypasses policies)
//!
//! Run with: `cargo benchmark --package pallet-numail --features runtime-benchmarks`
//! Then update weights.rs with the output.

use super::*;
use crate::Pallet as NuMail;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
// use frame_support::BoundedVec;
use frame_system::RawOrigin;
use frame_support::traits::Get;

#[benchmarks]
mod benchmarks {
	use super::*;

	/// Worst case: max folders declared at creation time.
	#[benchmark]
	fn create_mailbox() {
		let caller: T::AccountId = whitelisted_caller();
		
		// Worst case: declare the maximum number of folders.
		let max_folders = T::MaxFoldersPerAccount::get() as usize;
		let mut folders = Vec::with_capacity(max_folders);
		for i in 0..max_folders {
			folders.push(format!("folder_{}", i).into_bytes());
		}

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), AcceptancePolicy::Open, None, folders);
	}

	/// Worst case: max recipients + max attachments, with a postage-gated recipient.
	/// Tests policy checking across many recipients and attachment validation.
	#[benchmark]
	fn send_mail() {
		let sender: T::AccountId = whitelisted_caller();
		
		let max_recipients = T::MaxRecipients::get() as usize;
		let mut recipients = Vec::with_capacity(max_recipients);
		for i in 0..max_recipients {
			let recipient: T::AccountId = account("recipient", i as u32, 0);
			NuMail::<T>::create_mailbox(
				RawOrigin::Signed(recipient.clone()).into(),
				AcceptancePolicy::PostageRequired(1_000u128.into()),
				None,
				vec![],
			)
			.expect("recipient mailbox creation should succeed");
			recipients.push(recipient);
		}

		// Simulate encrypted body (nonce + ciphertext + tag)
		let encrypted_body = vec![0u8; 1024]; // 1 KB encrypted body

		// Simulate encrypted keys for each recipient (RSA-encrypted)
		let encrypted_keys: Vec<(T::AccountId, Vec<u8>)> = recipients
			.iter()
			.map(|r| (r.clone(), vec![0u8; 256]))
			.collect();

		let max_attachments = T::MaxAttachments::get() as usize;
		let attachments: Vec<T::Hash> = (0..max_attachments)
			.map(|_i| T::Hash::default())
			.collect();

		#[extrinsic_call]
		_(
			RawOrigin::Signed(sender),
			recipients,
			T::Hash::default(),
			encrypted_body,
			encrypted_keys,
			attachments,
			None,
		);
	}

	/// Simple state transition: Delivered → Read.
	/// Minimal variance; postage release is checked if escrow exists.
	#[benchmark]
	fn mark_read() {
		let sender: T::AccountId = whitelisted_caller();
		let recipient: T::AccountId = account("recipient", 0, 0);

		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(recipient.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![],
		)
		.expect("mailbox creation should succeed in setup");
		
		NuMail::<T>::send_mail(
			RawOrigin::Signed(sender).into(),
			vec![recipient.clone()],
			T::Hash::default(),
			T::Hash::default(),
			vec![],
			None,
		)
		.expect("send_mail should succeed in setup");

		#[extrinsic_call]
		_(RawOrigin::Signed(recipient), 0u64);
	}

	/// Remove from index + state transition.
	/// Minimal variance; defensive fallback in tombstone is rarely triggered.
	#[benchmark]
	fn tombstone() {
		let sender: T::AccountId = whitelisted_caller();
		let recipient: T::AccountId = account("recipient", 0, 0);

		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(recipient.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![],
		)
		.expect("mailbox creation should succeed in setup");
		
		NuMail::<T>::send_mail(
			RawOrigin::Signed(sender).into(),
			vec![recipient.clone()],
			T::Hash::default(),
			T::Hash::default(),
			vec![],
			None,
		)
		.expect("send_mail should succeed in setup");

		#[extrinsic_call]
		_(RawOrigin::Signed(recipient), 0u64);
	}

	/// Move mail between folders: remove from old index, add to new.
	/// Variant: folder existence is not pre-checked (BoundedVec.try_push handles capacity).
	#[benchmark]
	fn move_to_folder() {
		let sender: T::AccountId = whitelisted_caller();
		let recipient: T::AccountId = account("recipient", 0, 0);

		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(recipient.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![b"inbox".to_vec(), b"archive".to_vec()],
		)
		.expect("mailbox creation should succeed in setup");
		
		NuMail::<T>::send_mail(
			RawOrigin::Signed(sender).into(),
			vec![recipient.clone()],
			T::Hash::default(),
			T::Hash::default(),
			vec![],
			None,
		)
		.expect("send_mail should succeed in setup");

		#[extrinsic_call]
		_(RawOrigin::Signed(recipient), 0u64, b"archive".to_vec());
	}

	/// Simple storage update: policy and retention.
	/// Minimal variance.
	#[benchmark]
	fn set_mailbox_policy() {
		let caller: T::AccountId = whitelisted_caller();
		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(caller.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![],
		)
		.expect("mailbox creation should succeed in setup");

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), AcceptancePolicy::MinTrustScore(10), None);
	}

	/// Worst case: blocklist nearly full (linear search on `contains` check).
	#[benchmark]
	fn block_sender() {
		let caller: T::AccountId = whitelisted_caller();
		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(caller.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![],
		)
		.expect("mailbox creation should succeed in setup");

		// Worst case: fill blocklist to near-capacity, then add one more.
		let max_blocklist = T::MaxBlocklistSize::get() as usize;
		for i in 0..max_blocklist.saturating_sub(1) {
			let blocked: T::AccountId = account("blocked", i as u32, 0);
			NuMail::<T>::block_sender(RawOrigin::Signed(caller.clone()).into(), blocked)
				.expect("block_sender setup should succeed");
		}

		let target: T::AccountId = account("target", 999, 0);

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), target);
	}

	/// Worst case: blocklist full, filter across all entries.
	/// `retain` is O(n), so this is the heaviest unblock scenario.
	#[benchmark]
	fn unblock_sender() {
		let caller: T::AccountId = whitelisted_caller();
		NuMail::<T>::create_mailbox(
			RawOrigin::Signed(caller.clone()).into(),
			AcceptancePolicy::Open,
			None,
			vec![],
		)
		.expect("mailbox creation should succeed in setup");

		// Worst case: fill blocklist to capacity.
		let max_blocklist = T::MaxBlocklistSize::get() as usize;
		let mut targets = Vec::with_capacity(max_blocklist);
		for i in 0..max_blocklist {
			let blocked: T::AccountId = account("blocked", i as u32, 0);
			targets.push(blocked.clone());
			NuMail::<T>::block_sender(RawOrigin::Signed(caller.clone()).into(), blocked)
				.expect("block_sender setup should succeed");
		}

		// Unblock the first one (forces filter to scan the entire list).
		let target_to_unblock = targets[0].clone();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), target_to_unblock);
	}

	/// Worst case: max recipients (like send_mail, but skips acceptance policy checks).
	/// Tests delivery indexing across many recipients without policy variance.
	#[benchmark]
	fn system_notice() {
		let notice_sender: T::AccountId = account("notice_sender", 0, 0);
		
		// Worst case: max recipients, all requiring mailboxes.
		let max_recipients = T::MaxRecipients::get() as usize;
		let mut recipients = Vec::with_capacity(max_recipients);
		for i in 0..max_recipients {
			let recipient: T::AccountId = account("recipient", i as u32, 0);
			NuMail::<T>::create_mailbox(
				RawOrigin::Signed(recipient.clone()).into(),
				AcceptancePolicy::Open,
				None,
				vec![],
			)
			.expect("recipient mailbox creation should succeed");
			recipients.push(recipient);
		}

		#[extrinsic_call]
		_(
			RawOrigin::Root,
			notice_sender,
			recipients,
			T::Hash::default(),
			T::Hash::default(),
		);
	}

	impl_benchmark_test_suite!(NuMail, crate::mock::new_test_ext(), crate::mock::Test);
}