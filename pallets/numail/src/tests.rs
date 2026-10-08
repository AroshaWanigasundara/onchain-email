use crate::{
	mock::*, AcceptancePolicy, Blocklists, DeliveryState, DeliveryStatus, Error, Event, FolderId,
	MailEnvelope, MailItems, MailboxConfig, MailboxIndex, Mailboxes, NextMailId, PostageEscrow,
	Threads, MailEncryptedKeys,PublicKeys,
};
use frame_support::{assert_noop, assert_ok, BoundedVec};

// ---------------------------------------------------------------------------------------------
// Phase 2 carry-overs: direct storage round-trips, proving the data model's types/bounds/
// encoding are sound independent of any dispatchable.
// ---------------------------------------------------------------------------------------------

/// Helper: Create encrypted key for recipient (RSA-encrypted AES key)
fn mock_encrypted_key(size: usize) -> Vec<u8> {
	vec![0x42u8; size]
}

/// Helper: Create encrypted body (nonce 12 bytes + ciphertext)
fn mock_encrypted_body(size: usize) -> Vec<u8> {
	vec![0u8; size]
}

/// Mock RSA public key (256 bytes for testing)
fn mock_public_key(size: usize) -> Vec<u8> {
    vec![0xAB; size]  // Use different byte pattern (0xAB) to distinguish from other mocks
}

#[test]
fn mock_runtime_builds_and_executes() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_eq!(System::block_number(), 1);
	});
}

#[test]
fn mailbox_config_can_be_stored_and_read() {
	new_test_ext().execute_with(|| {
		let folder: FolderId<Test> = BoundedVec::try_from(b"inbox".to_vec()).unwrap();
		let config = MailboxConfig::<Test> {
			policy: AcceptancePolicy::Open,
			retention_blocks: None,
			folders: BoundedVec::try_from(vec![folder]).unwrap(),
		};

		Mailboxes::<Test>::insert(1, config.clone());
		assert_eq!(Mailboxes::<Test>::get(1), Some(config));
	});
}

#[test]
fn mail_item_can_be_stored_indexed_and_delivered() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mail_id = NextMailId::<Test>::get();
		let envelope = MailEnvelope::<Test> {
			sender: 1,
			recipients: BoundedVec::try_from(vec![2]).unwrap(),
			subject_hash: Default::default(),
			encrypted_subject: BoundedVec::default(),
			body_ref: Default::default(),
			encrypted_body: BoundedVec::default(),
			attachments: BoundedVec::default(),
			thread_parent: None,
			thread_id: None,
			created_at: System::block_number(),
		};

		MailItems::<Test>::insert(mail_id, envelope.clone());
		NextMailId::<Test>::put(mail_id + 1);

		let inbox: FolderId<Test> = BoundedVec::try_from(b"inbox".to_vec()).unwrap();
		MailboxIndex::<Test>::mutate(2, &inbox, |ids| {
			ids.try_push(mail_id).unwrap();
		});
		DeliveryState::<Test>::insert(mail_id, 2, DeliveryStatus::Delivered);

		assert_eq!(MailItems::<Test>::get(mail_id), Some(envelope));
		assert_eq!(MailboxIndex::<Test>::get(2, &inbox).into_inner(), vec![mail_id]);
		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Delivered));
		assert_eq!(NextMailId::<Test>::get(), mail_id + 1);
	});
}

#[test]
fn thread_blocklist_and_postage_storage_round_trip() {
	new_test_ext().execute_with(|| {
		Threads::<Test>::mutate(7u64, |ids| ids.try_push(1u64).unwrap());
		assert_eq!(Threads::<Test>::get(7u64).into_inner(), vec![1u64]);

		Blocklists::<Test>::mutate(1, |list| list.try_push(99).unwrap());
		assert_eq!(Blocklists::<Test>::get(1).into_inner(), vec![99]);

		PostageEscrow::<Test>::insert(1u64, 500u128);
		assert_eq!(PostageEscrow::<Test>::get(1u64), Some(500u128));
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 3: create_mailbox
// ---------------------------------------------------------------------------------------------

fn open_mailbox(who: u64) {
	assert_ok!(NuMail::create_mailbox(RuntimeOrigin::signed(who), AcceptancePolicy::Open, None, vec![], mock_public_key(256)));
}

#[test]
fn create_mailbox_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(1),
			AcceptancePolicy::Open,
			None,
			vec![b"inbox".to_vec(), b"sent".to_vec()],
			mock_public_key(256),
		));

		let stored = Mailboxes::<Test>::get(1).expect("mailbox should exist");
		assert_eq!(stored.policy, AcceptancePolicy::Open);
		assert_eq!(stored.folders.len(), 2);
		System::assert_last_event(Event::<Test>::MailboxCreated { who: 1 }.into());
	});
}

#[test]
fn create_mailbox_fails_if_already_exists() {
	new_test_ext().execute_with(|| {
		open_mailbox(1);
		assert_noop!(
			NuMail::create_mailbox(RuntimeOrigin::signed(1), AcceptancePolicy::Open, None, vec![], mock_public_key(256)),
			Error::<Test>::MailboxAlreadyExists
		);
	});
}

#[test]
fn create_mailbox_fails_for_folder_name_too_long() {
	new_test_ext().execute_with(|| {
		// MaxFolderNameLen is 32 in the mock.
		let too_long = vec![0u8; 33];
		assert_noop!(
			NuMail::create_mailbox(RuntimeOrigin::signed(1), AcceptancePolicy::Open, None, vec![too_long], mock_public_key(256)),
			Error::<Test>::FolderNameTooLong
		);
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 3: send_mail
// ---------------------------------------------------------------------------------------------

#[test]
fn send_mail_happy_path_open_policy() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		open_mailbox(2);

		let encrypted_key = mock_encrypted_key(256);

		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));

		let mail_id = 0u64;
		assert!(MailItems::<Test>::get(mail_id).is_some());
		let inbox: FolderId<Test> = BoundedVec::try_from(b"inbox".to_vec()).unwrap();
		assert_eq!(MailboxIndex::<Test>::get(2, &inbox).into_inner(), vec![mail_id]);
		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Delivered));
		assert_eq!(NextMailId::<Test>::get(), 1);
		System::assert_last_event(
			Event::<Test>::MailSent { mail_id, sender: 1, recipient_count: 1 }.into(),
		);
	});
}

#[test]
fn send_mail_fails_without_recipient_mailbox() {
	new_test_ext().execute_with(|| {

		let encrypted_key = mock_encrypted_key(256);
		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::MailboxNotFound
		);
	});
}

#[test]
fn send_mail_fails_when_sender_blocked() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		Blocklists::<Test>::mutate(2, |list| list.try_push(1).unwrap());

		let encrypted_key = mock_encrypted_key(256);

		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::SenderBlocked
		);
	});
}

#[test]
fn send_mail_min_trust_score_refuses_then_allows() {
	new_test_ext().execute_with(|| {
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::MinTrustScore(50),
			None,
			vec![],
			mock_public_key(256),
		));

		let encrypted_key = mock_encrypted_key(256);

		// Mock's RecipientPolicy defaults to trust_score() == 0 — below the threshold.
		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::RecipientPolicyRefused
		);

		let encrypted_key = mock_encrypted_key(256);

		set_trust_score(50);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));
	});
}

#[test]
fn send_mail_contacts_only_refuses_then_allows() {
	new_test_ext().execute_with(|| {
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::ContactsOnly,
			None,
			vec![],
			mock_public_key(256),
		));

		let encrypted_key = mock_encrypted_key(256);

		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::RecipientPolicyRefused
		);

		let encrypted_key = mock_encrypted_key(256);

		set_is_contact(true);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));
	});
}

#[test]
fn send_mail_lodges_postage_for_postage_required_policy() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		set_balance(1, 5_000);
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::PostageRequired(1_000),
			None,
			vec![],
			mock_public_key(256),
		));

		let encrypted_key = mock_encrypted_key(256);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));

		let mail_id = 0u64;
		assert_eq!(PostageEscrow::<Test>::get(mail_id), Some(1_000u128));
		assert_eq!(balance_of(1), 4_000); // 5_000 - 1_000 reserved
		System::assert_has_event(Event::<Test>::PostageLodged { mail_id, amount: 1_000 }.into());
	});
}

#[test]
fn send_mail_fails_for_insufficient_postage() {
	new_test_ext().execute_with(|| {
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::PostageRequired(1_000),
			None,
			vec![],
			mock_public_key(256),
		));
		set_balance(1, 500); // not enough to cover the 1_000 required
		let encrypted_key = mock_encrypted_key(256);

		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::PostageRequired
		);
		// Nothing should have been reserved on a failed send.
		assert_eq!(balance_of(1), 500);
	});
}

#[test]
fn send_mail_threads_replies_together() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		open_mailbox(1);
		open_mailbox(2);

		// Send root mail
		let encrypted_key_1 = mock_encrypted_key(256);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			mock_encrypted_body(50),  // Use actual encrypted body
			vec![(2, encrypted_key_1)],
			vec![],
			None,
		));
		let root_id = 0u64;

		// Send reply to root
		let encrypted_key_2 = mock_encrypted_key(256);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(2),
			vec![1],
			Default::default(),
			mock_encrypted_body(50),  // Use actual encrypted body
			vec![(1, encrypted_key_2)],
			vec![],
			Some(root_id),
		));
		let reply_id = 1u64;

		// Verify reply has correct thread linkage
		let reply = MailItems::<Test>::get(reply_id).unwrap();
		assert_eq!(reply.thread_parent, Some(root_id));
		assert_eq!(reply.thread_id, Some(root_id));

		// Verify thread contains the reply
		let thread_items = Threads::<Test>::get(root_id);
		assert_eq!(thread_items.len(), 1);
		assert_eq!(thread_items[0], reply_id);
	});
}

#[test]
fn send_mail_fails_for_unknown_thread_parent() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		let encrypted_key = mock_encrypted_key(256);
		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				Some(999u64),
			),
			Error::<Test>::ThreadNotFound
		);
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 4: mark_read
// ---------------------------------------------------------------------------------------------

fn send_open_mail(sender: u64, recipient: u64) -> u64 {
	open_mailbox(recipient);
	let encrypted_key = mock_encrypted_key(256);
	assert_ok!(NuMail::send_mail(
		RuntimeOrigin::signed(sender),
		vec![recipient],
		Default::default(),
		Default::default(),
		vec![(2, encrypted_key)],
		vec![],
		None,
	));
	NextMailId::<Test>::get() - 1
}

#[test]
fn mark_read_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		let mail_id = send_open_mail(1, 2);

		System::set_block_number(2);
		assert_ok!(NuMail::mark_read(RuntimeOrigin::signed(2), mail_id));

		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Read));
		System::assert_last_event(
			Event::<Test>::MailRead { mail_id, recipient: 2, at_block: 2 }.into(),
		);
	});
}

#[test]
fn mark_read_fails_for_non_recipient() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_noop!(
			NuMail::mark_read(RuntimeOrigin::signed(3), mail_id),
			Error::<Test>::NotRecipient
		);
	});
}

#[test]
fn mark_read_fails_if_already_read() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_ok!(NuMail::mark_read(RuntimeOrigin::signed(2), mail_id));
		assert_noop!(
			NuMail::mark_read(RuntimeOrigin::signed(2), mail_id),
			Error::<Test>::AlreadyRead
		);
	});
}

#[test]
fn mark_read_releases_postage() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		set_balance(1, 5_000);
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::PostageRequired(1_000),
			None,
			vec![],
			mock_public_key(256),
		));

		let encrypted_key = mock_encrypted_key(256);
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));
		let mail_id = 0u64;
		assert_eq!(PostageEscrow::<Test>::get(mail_id), Some(1_000u128));
		assert_eq!(balance_of(1), 4_000);

		assert_ok!(NuMail::mark_read(RuntimeOrigin::signed(2), mail_id));

		assert_eq!(PostageEscrow::<Test>::get(mail_id), None);
		assert_eq!(balance_of(1), 5_000); // released back to the original sender
		System::assert_has_event(Event::<Test>::PostageReleased { mail_id, amount: 1_000 }.into());
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 4: tombstone
// ---------------------------------------------------------------------------------------------

#[test]
fn tombstone_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		let mail_id = send_open_mail(1, 2);
		let inbox: FolderId<Test> = BoundedVec::try_from(b"inbox".to_vec()).unwrap();
		assert_eq!(MailboxIndex::<Test>::get(2, &inbox).into_inner(), vec![mail_id]);

		assert_ok!(NuMail::tombstone(RuntimeOrigin::signed(2), mail_id));

		assert!(MailboxIndex::<Test>::get(2, &inbox).is_empty());
		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Tombstoned));
		// Evidential record persists — tombstoning is not erasure.
		assert!(MailItems::<Test>::get(mail_id).is_some());
		System::assert_last_event(Event::<Test>::MailTombstoned { mail_id, recipient: 2 }.into());
	});
}

#[test]
fn tombstone_fails_for_non_recipient() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_noop!(
			NuMail::tombstone(RuntimeOrigin::signed(3), mail_id),
			Error::<Test>::NotRecipient
		);
	});
}

#[test]
fn tombstone_fails_if_already_tombstoned() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_ok!(NuMail::tombstone(RuntimeOrigin::signed(2), mail_id));
		assert_noop!(
			NuMail::tombstone(RuntimeOrigin::signed(2), mail_id),
			Error::<Test>::AlreadyTombstoned
		);
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 5: move_to_folder, set_mailbox_policy, block_sender / unblock_sender
// ---------------------------------------------------------------------------------------------

#[test]
fn move_to_folder_works() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		let inbox: FolderId<Test> = BoundedVec::try_from(b"inbox".to_vec()).unwrap();
		let archive: FolderId<Test> = BoundedVec::try_from(b"archive".to_vec()).unwrap();

		assert_ok!(NuMail::move_to_folder(RuntimeOrigin::signed(2), mail_id, b"archive".to_vec()));

		assert!(MailboxIndex::<Test>::get(2, &inbox).is_empty());
		assert_eq!(MailboxIndex::<Test>::get(2, &archive).into_inner(), vec![mail_id]);
		assert_eq!(crate::MailFolderOf::<Test>::get(2, mail_id), Some(archive));
	});
}

#[test]
fn move_to_folder_fails_for_non_recipient() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_noop!(
			NuMail::move_to_folder(RuntimeOrigin::signed(3), mail_id, b"archive".to_vec()),
			Error::<Test>::NotRecipient
		);
	});
}

#[test]
fn move_to_folder_fails_after_tombstone() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_ok!(NuMail::tombstone(RuntimeOrigin::signed(2), mail_id));
		assert_noop!(
			NuMail::move_to_folder(RuntimeOrigin::signed(2), mail_id, b"archive".to_vec()),
			Error::<Test>::AlreadyTombstoned
		);
	});
}

#[test]
fn tombstone_after_move_removes_from_new_folder_not_inbox() {
	new_test_ext().execute_with(|| {
		let mail_id = send_open_mail(1, 2);
		assert_ok!(NuMail::move_to_folder(RuntimeOrigin::signed(2), mail_id, b"archive".to_vec()));
		assert_ok!(NuMail::tombstone(RuntimeOrigin::signed(2), mail_id));

		let archive: FolderId<Test> = BoundedVec::try_from(b"archive".to_vec()).unwrap();
		assert!(MailboxIndex::<Test>::get(2, &archive).is_empty());
		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Tombstoned));
	});
}

#[test]
fn set_mailbox_policy_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		open_mailbox(1);

		assert_ok!(NuMail::set_mailbox_policy(
			RuntimeOrigin::signed(1),
			AcceptancePolicy::MinTrustScore(10),
			None,
		));

		assert_eq!(Mailboxes::<Test>::get(1).unwrap().policy, AcceptancePolicy::MinTrustScore(10));
		System::assert_last_event(Event::<Test>::PolicyUpdated { who: 1 }.into());
	});
}

#[test]
fn set_mailbox_policy_fails_without_mailbox() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			NuMail::set_mailbox_policy(RuntimeOrigin::signed(1), AcceptancePolicy::Open, None),
			Error::<Test>::MailboxNotFound
		);
	});
}

#[test]
fn block_sender_prevents_future_mail_and_unblock_restores_it() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		open_mailbox(2);

		assert_ok!(NuMail::block_sender(RuntimeOrigin::signed(2), 1));
		System::assert_last_event(Event::<Test>::SenderBlocked { who: 2, blocked: 1 }.into());

		let encrypted_key = mock_encrypted_key(256);
		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![],
				None,
			),
			Error::<Test>::SenderBlocked
		);

		let encrypted_key = mock_encrypted_key(256);

		assert_ok!(NuMail::unblock_sender(RuntimeOrigin::signed(2), 1));
		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![],
			None,
		));
	});
}

#[test]
fn block_sender_fails_without_mailbox() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			NuMail::block_sender(RuntimeOrigin::signed(1), 2),
			Error::<Test>::MailboxNotFound
		);
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 6: system_notice
// ---------------------------------------------------------------------------------------------

#[test]
fn system_notice_works_via_root() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		open_mailbox(2);

		assert_ok!(NuMail::system_notice(
			RuntimeOrigin::root(),
			99, // notice sender, e.g. a pallet account
			vec![2],
			Default::default(),
			Default::default(),
		));

		let mail_id = 0u64;
		assert!(MailItems::<Test>::get(mail_id).is_some());
		assert_eq!(DeliveryState::<Test>::get(mail_id, 2), Some(DeliveryStatus::Delivered));
		System::assert_has_event(
			Event::<Test>::MailSent { mail_id, sender: 99, recipient_count: 1 }.into(),
		);
	});
}

#[test]
fn system_notice_fails_for_signed_origin() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		assert_noop!(
			NuMail::system_notice(
				RuntimeOrigin::signed(1),
				99,
				vec![2],
				Default::default(),
				Default::default(),
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn system_notice_fails_without_recipient_mailbox() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			NuMail::system_notice(
				RuntimeOrigin::root(),
				99,
				vec![2],
				Default::default(),
				Default::default(),
			),
			Error::<Test>::MailboxNotFound
		);
	});
}

#[test]
fn system_notice_bypasses_acceptance_policy() {
	new_test_ext().execute_with(|| {
		// A restrictive policy that would refuse ordinary mail from an unqualified sender...
		assert_ok!(NuMail::create_mailbox(
			RuntimeOrigin::signed(2),
			AcceptancePolicy::MinTrustScore(100),
			None,
			vec![],
			mock_public_key(256),
		));

		// ...still gets through via the privileged system_notice pathway.
		assert_ok!(NuMail::system_notice(
			RuntimeOrigin::root(),
			99,
			vec![2],
			Default::default(),
			Default::default(),
		));
	});
}

#[test]
fn deliver_system_notice_can_be_called_directly() {
	// Proves the pallet-internal pathway works without going through extrinsic dispatch at
	// all — the "pallet-internal" half of the spec's "Root / pallet-internal" origin.
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		assert_ok!(NuMail::deliver_system_notice(99, vec![2], Default::default(), Default::default()));
		assert_eq!(DeliveryState::<Test>::get(0u64, 2), Some(DeliveryStatus::Delivered));
	});
}

// ---------------------------------------------------------------------------------------------
// Phase 8: attachment anchoring (AttachmentAnchor / DNC integration point)
// ---------------------------------------------------------------------------------------------

#[test]
fn send_mail_fails_for_unanchored_attachment() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		let attachment = sp_core::H256::repeat_byte(0xAB);
		let encrypted_key = mock_encrypted_key(256);

		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![attachment],
				None,
			),
			Error::<Test>::AttachmentNotAnchored
		);
	});
}

#[test]
fn send_mail_succeeds_with_anchored_attachment() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		let attachment = sp_core::H256::repeat_byte(0xAB);
		mark_anchored(attachment);
		let encrypted_key = mock_encrypted_key(256);

		assert_ok!(NuMail::send_mail(
			RuntimeOrigin::signed(1),
			vec![2],
			Default::default(),
			Default::default(),
			vec![(2, encrypted_key)],
			vec![attachment],
			None,
		));

		let envelope = MailItems::<Test>::get(0u64).unwrap();
		assert_eq!(envelope.attachments.into_inner(), vec![attachment]);
	});
}

#[test]
fn send_mail_fails_if_any_one_attachment_is_unanchored() {
	new_test_ext().execute_with(|| {
		open_mailbox(2);
		let anchored = sp_core::H256::repeat_byte(0x01);
		let not_anchored = sp_core::H256::repeat_byte(0x02);
		let encrypted_key = mock_encrypted_key(256);
		mark_anchored(anchored);

		assert_noop!(
			NuMail::send_mail(
				RuntimeOrigin::signed(1),
				vec![2],
				Default::default(),
				Default::default(),
				vec![(2, encrypted_key)],
				vec![anchored, not_anchored],
				None,
			),
			Error::<Test>::AttachmentNotAnchored
		);
	});
}

#[test]
fn send_mail_stores_encrypted_body_and_keys() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        open_mailbox(2);

        // Simulate encrypted body (nonce 12 bytes + ciphertext + tag)
        let encrypted_body = vec![
            0u8; 50  // 12 bytes nonce + 32 bytes ciphertext + 16 bytes tag + padding
        ];
        let encrypted_key_for_recipient = vec![0x42u8; 256]; // Simulated encrypted RSA key

        assert_ok!(NuMail::send_mail(
            RuntimeOrigin::signed(1),
            vec![2],
            Default::default(),
            encrypted_body.clone(),
            vec![(2, encrypted_key_for_recipient.clone())],
            vec![],
            None,
        ));

        let mail_id = 0u64;
        
        // Verify encrypted body is stored in MailItems
        let envelope = MailItems::<Test>::get(mail_id).expect("envelope should exist");
        assert_eq!(envelope.encrypted_body.to_vec(), encrypted_body);

        // Verify encrypted key is stored in MailEncryptedKeys
        let stored_key = MailEncryptedKeys::<Test>::get(mail_id, 2)
            .expect("encrypted key should exist for recipient");
        assert_eq!(stored_key.to_vec(), encrypted_key_for_recipient);
    });
}

#[test]
fn send_mail_fails_for_encrypted_body_too_large() {
    new_test_ext().execute_with(|| {
        open_mailbox(2);
        let oversized_body = vec![0u8; 100000]; // Exceeds MaxEncryptedBodyLen (65536)
        let encrypted_key = vec![0u8; 256];

        assert_noop!(
            NuMail::send_mail(
                RuntimeOrigin::signed(1),
                vec![2],
                Default::default(),
                oversized_body,
                vec![(2, encrypted_key)],
                vec![],
                None,
            ),
            Error::<Test>::EncryptedBodyTooLarge
        );
    });
}

#[test]
fn send_mail_fails_for_encrypted_key_too_large() {
    new_test_ext().execute_with(|| {
        open_mailbox(2);
        let encrypted_body = vec![0u8; 50];
        let oversized_key = vec![0u8; 2050]; // Exceeds MaxEncryptedKeyLen (2048)

        assert_noop!(
            NuMail::send_mail(
                RuntimeOrigin::signed(1),
                vec![2],
                Default::default(),
                encrypted_body,
                vec![(2, oversized_key)],
                vec![],
                None,
            ),
            Error::<Test>::EncryptedKeyTooLarge
        );
    });
}

#[test]
fn send_mail_fails_for_key_count_mismatch() {
    new_test_ext().execute_with(|| {
        open_mailbox(2);
        open_mailbox(3);
        let encrypted_body = vec![0u8; 50];

        // 2 recipients but only 1 encrypted key
        assert_noop!(
            NuMail::send_mail(
                RuntimeOrigin::signed(1),
                vec![2, 3],
                Default::default(),
                encrypted_body,
                vec![(2, vec![0u8; 256])],  // Missing key for recipient 3
                vec![],
                None,
            ),
            Error::<Test>::EncryptedKeyCountMismatch
        );
    });
}

#[test]
fn create_mailbox_stores_public_key() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let public_key = mock_public_key(256);
        
        assert_ok!(NuMail::create_mailbox(
            RuntimeOrigin::signed(1),
            AcceptancePolicy::Open,
            None,
            vec![],
            public_key.clone(),
        ));

        // Verify public key is stored
        let stored_key = PublicKeys::<Test>::get(1).expect("public key should exist");
        assert_eq!(stored_key.to_vec(), public_key);
    });
}

#[test]
fn public_key_can_be_queried() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let public_key = mock_public_key(256);
        
        assert_ok!(NuMail::create_mailbox(
            RuntimeOrigin::signed(1),
            AcceptancePolicy::Open,
            None,
            vec![],
            public_key.clone(),
        ));

        // Query public key via helper function
        let queried_key = NuMail::get_public_key(&1).expect("public key should be queryable");
        assert_eq!(queried_key, public_key);
    });
}

#[test]
fn create_mailbox_fails_without_public_key() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        
        assert_noop!(
            NuMail::create_mailbox(
                RuntimeOrigin::signed(1),
                AcceptancePolicy::Open,
                None,
                vec![],
                vec![], // Empty public key
            ),
            Error::<Test>::PublicKeyRequired
        );
    });
}

#[test]
fn create_mailbox_fails_for_public_key_too_large() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let oversized_key = vec![0u8; 5000]; // Exceeds MaxPublicKeyLen (2048)
        
        assert_noop!(
            NuMail::create_mailbox(
                RuntimeOrigin::signed(1),
                AcceptancePolicy::Open,
                None,
                vec![],
                oversized_key,
            ),
            Error::<Test>::PublicKeyTooLarge
        );
    });
}

#[test]
fn public_key_not_found_for_non_existent_mailbox() {
    new_test_ext().execute_with(|| {
        // Account 999 has no mailbox
        assert_eq!(NuMail::get_public_key(&999), None);
    });
}
