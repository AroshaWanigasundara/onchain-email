use crate as pallet_numail;
use core::cell::RefCell;
use frame_support::{derive_impl, parameter_types};
use sp_core::H256;
use sp_runtime::BuildStorage;
use std::collections::{BTreeMap, BTreeSet};

type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::runtime]
mod runtime {
	// The main runtime
	#[runtime::runtime]
	// Runtime Types to be generated
	#[runtime::derive(
		RuntimeCall,
		RuntimeEvent,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask,
		RuntimeViewFunction
	)]
	pub struct Test;

	#[runtime::pallet_index(0)]
	pub type System = frame_system::Pallet<Test>;

	#[runtime::pallet_index(1)]
	pub type NuMail = pallet_numail::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const MaxRecipients: u32 = 16;
	pub const MaxAttachments: u32 = 8;
	pub const MaxFolderNameLen: u32 = 32;
	pub const MaxFoldersPerAccount: u32 = 16;
	pub const MaxMailPerFolder: u32 = 256;
	pub const MaxThreadSize: u32 = 256;
	pub const MaxBlocklistSize: u32 = 64;
}

thread_local! {
	// Toggled from within tests to exercise both the "refused" and "allowed" branches of
	// `AcceptancePolicy::ContactsOnly` / `MinTrustScore` without needing a real Reputation
	// pallet — see `set_is_contact` / `set_trust_score` below.
	static IS_CONTACT: RefCell<bool> = const { RefCell::new(false) };
	static TRUST_SCORE: RefCell<u32> = const { RefCell::new(0) };
}

/// Test-only stand-in for a real Reputation-pallet adapter. Ignores which sender/recipient is
/// asked about and just returns whatever the current test has configured via the setters below;
/// that's enough to prove `pallet-numail` calls through the [`pallet_numail::RecipientPolicyProvider`]
/// trait correctly, without this crate depending on the real Reputation pallet.
pub struct MockRecipientPolicy;

impl<AccountId> pallet_numail::RecipientPolicyProvider<AccountId> for MockRecipientPolicy {
	fn is_contact(_sender: &AccountId, _recipient: &AccountId) -> bool {
		IS_CONTACT.with(|v| *v.borrow())
	}
	fn trust_score(_sender: &AccountId) -> u32 {
		TRUST_SCORE.with(|v| *v.borrow())
	}
}

pub fn set_is_contact(value: bool) {
	IS_CONTACT.with(|v| *v.borrow_mut() = value);
}

pub fn set_trust_score(value: u32) {
	TRUST_SCORE.with(|v| *v.borrow_mut() = value);
}

thread_local! {
	// A deliberately trivial ledger, just enough to prove `pallet-numail` calls through
	// `PostageCurrency::reserve`/`release` correctly — not anything close to a real currency
	// pallet. Balances default to 0, so a test must call `set_balance` before a `send_mail`
	// that needs to reserve postage, or `reserve` will (correctly) fail.
	static BALANCES: RefCell<BTreeMap<u64, u128>> = RefCell::new(BTreeMap::new());
}

pub struct MockPostageCurrency;

impl pallet_numail::PostageCurrency<u64> for MockPostageCurrency {
	fn reserve(payer: &u64, amount: u128) -> Result<(), ()> {
		BALANCES.with(|balances| {
			let mut balances = balances.borrow_mut();
			let balance = balances.entry(*payer).or_insert(0);
			if *balance >= amount {
				*balance -= amount;
				Ok(())
			} else {
				Err(())
			}
		})
	}

	fn release(payer: &u64, amount: u128) -> Result<(), ()> {
		BALANCES.with(|balances| {
			*balances.borrow_mut().entry(*payer).or_insert(0) += amount;
		});
		Ok(())
	}
}

pub fn set_balance(who: u64, amount: u128) {
	BALANCES.with(|balances| {
		balances.borrow_mut().insert(who, amount);
	});
}

pub fn balance_of(who: u64) -> u128 {
	BALANCES.with(|balances| *balances.borrow().get(&who).unwrap_or(&0))
}

thread_local! {
	// Which attachment hashes count as "DNC-anchored" for test purposes. Empty by default,
	// matching the pallet's fail-closed `()` behavior — a test must call `mark_anchored` before
	// `send_mail`-ing an attachment, or it will (correctly) be refused.
	static ANCHORED_HASHES: RefCell<BTreeSet<H256>> = RefCell::new(BTreeSet::new());
}

pub struct MockAttachmentAnchor;

impl pallet_numail::AttachmentAnchor<H256> for MockAttachmentAnchor {
	fn is_anchored(hash: &H256) -> bool {
		ANCHORED_HASHES.with(|anchored| anchored.borrow().contains(hash))
	}
}

pub fn mark_anchored(hash: H256) {
	ANCHORED_HASHES.with(|anchored| {
		anchored.borrow_mut().insert(hash);
	});
}

parameter_types! {
    pub const MaxEncryptedBodyLen: u32 = 65536;  // 64 KB max encrypted body
    pub const MaxEncryptedKeyLen: u32 = 2048;     // 2 KB max (RSA-4096)
	pub const MaxPublicKeyLen: u32 = 2048;  // 2 KB for RSA public key
}

impl pallet_numail::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type RecipientPolicy = MockRecipientPolicy;
	type PostageCurrency = MockPostageCurrency;
	type AttachmentAnchor = MockAttachmentAnchor;
	type SystemNoticeOrigin = frame_system::EnsureRoot<u64>;
	type MaxRecipients = MaxRecipients;
	type MaxAttachments = MaxAttachments;
	type MaxFolderNameLen = MaxFolderNameLen;
	type MaxFoldersPerAccount = MaxFoldersPerAccount;
	type MaxMailPerFolder = MaxMailPerFolder;
	type MaxThreadSize = MaxThreadSize;
	type MaxBlocklistSize = MaxBlocklistSize;
	type MaxEncryptedBodyLen = MaxEncryptedBodyLen;
    type MaxEncryptedKeyLen = MaxEncryptedKeyLen;
	type MaxPublicKeyLen = MaxPublicKeyLen;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	IS_CONTACT.with(|v| *v.borrow_mut() = false);
	TRUST_SCORE.with(|v| *v.borrow_mut() = 0);
	BALANCES.with(|b| b.borrow_mut().clear());
	ANCHORED_HASHES.with(|a| a.borrow_mut().clear());
	frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into()
}