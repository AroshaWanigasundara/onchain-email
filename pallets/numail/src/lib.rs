//! # NuMail Pallet — On-Chain Email
//!
//! Module 13 of the NuTrust 4 network: a structured, asynchronous, evidential correspondence
//! layer. Where the Secure Messaging Pallet provides conversational user-to-user messaging,
//! this pallet provides the enterprise correspondence layer — subject-lined, threaded,
//! folder-organised mail with attachments, delivery states and retention rules.
//!
//! ## Status
//!
//! **Phase 8**: attachments are no longer trusted blindly. A new `AttachmentAnchor` local trait
//! (same pattern as `RecipientPolicyProvider`/`PostageCurrency`) is checked in `send_mail` for
//! every attachment hash before a mail item is accepted — the blanket `()` impl fails closed, so
//! an un-wired runtime can only send mail with an empty `attachments` list.
//!
//! Remaining deferred integrations: FastLane pre-consensus attestation (spec §2.6 step 3 — this
//! happens *before* the extrinsic reaches this pallet at all, more naturally a
//! `TransactionExtension`/transaction-pool concern than something inside `send_mail` itself, so
//! it's being treated as its own later phase rather than folded in here), and the acceptance
//! criteria's remaining items (real benchmark numbers instead of placeholders, a full rustdoc
//! pass, an integration guide for the front-end team). `PostageEscrow`'s per-mail granularity
//! also remains unchanged from earlier phases.
//!
//! ## Architecture note
//!
//! `pallet-numail` must never take a hard crate dependency on any other custom pallet (DNC,
//! Reputation, FastLane, Multicoin). `AcceptancePolicy::ContactsOnly` and `MinTrustScore` are
//! resolved through the local [`pallet::RecipientPolicyProvider`] trait on [`Config`] rather
//! than calling the Reputation pallet directly; a real runtime supplies an adapter. The blanket
//! `()` impl always refuses, so an un-wired runtime fails closed (`ContactsOnly`/`MinTrustScore`
//! policies refuse everyone) rather than silently accepting everything; the test mock swaps in a
//! toggleable stand-in (`mock::MockRecipientPolicy`) so both branches are exercised.
//! Attachments/subject/body stay as opaque `T::Hash` references; attachment verification goes
//! through the local `AttachmentAnchor` trait (Phase 8), never a direct DNC dependency, and
//! `PostageBalance` stays a self-contained `u128`; actual postage movement goes through the
//! local `PostageCurrency` trait (Phase 7), never a direct Multicoin dependency.
//!
//! Run `cargo doc --package pallet-numail --open` to view this pallet's documentation.

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// `send_mail`/`create_mailbox` take unbounded `Vec` extrinsic arguments (bounded once validated
// against the `Config` limits inside the call), so we need `alloc` explicitly under `no_std`.
extern crate alloc;

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

// FRAME pallets require their own "mock runtimes" to be able to run unit tests. This module
// contains a mock runtime specific for testing this pallet's functionality.
#[cfg(test)]
mod mock;

// This module contains the unit tests for this pallet.
// Learn about pallet unit testing here: https://docs.substrate.io/test/unit-testing/
#[cfg(test)]
mod tests;

// Every callable function or "dispatchable" a pallet exposes must have weight values that
// correctly estimate a dispatchable's execution time. The benchmarking module is used to
// calculate weights for each dispatchable and generates this pallet's weight.rs file.
// Learn more about benchmarking here: https://docs.substrate.io/test/benchmark/
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
	// Import various useful types required by all FRAME pallets.
	use super::*;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	// `pallet_prelude::*` covers `Encode`/`Decode`/`TypeInfo`/`MaxEncodedLen`, but
	// `DecodeWithMemTracking` (needed on any type used directly as a `#[pallet::call]`
	// argument, e.g. `AcceptancePolicy` in `create_mailbox`) is imported explicitly here in
	// case this frame-support version doesn't glob-export it.
	use codec::DecodeWithMemTracking;
	// Same caution for `EnsureOrigin`, used by `Config::SystemNoticeOrigin`.
	use frame_support::traits::EnsureOrigin;

	/// Local integration point for the sender-standing checks a mailbox's [`AcceptancePolicy`]
	/// can demand — "is this sender an established contact?" (would, in a full deployment, be
	/// backed by an address-book / Secure Messaging concept) and "what is this sender's current
	/// trust score?" (Module 10 — Reputation).
	///
	/// Per the project's architecture rule, `pallet-numail` never depends on the Reputation
	/// pallet (or anything else) directly. A real runtime implements this trait with an adapter
	/// that calls into whichever pallet actually holds that data; tests use a mock. The blanket
	/// `()` impl below always refuses, so an un-wired runtime fails closed (mail using
	/// `ContactsOnly`/`MinTrustScore` policies is refused) rather than silently accepting
	/// everything.
	pub trait RecipientPolicyProvider<AccountId> {
		/// Whether `sender` is an established contact of `recipient`.
		fn is_contact(sender: &AccountId, recipient: &AccountId) -> bool;
		/// `sender`'s current trust score, on whatever scale the runtime's Reputation source
		/// uses.
		fn trust_score(sender: &AccountId) -> u32;
	}

	impl<AccountId> RecipientPolicyProvider<AccountId> for () {
		fn is_contact(_sender: &AccountId, _recipient: &AccountId) -> bool {
			false
		}
		fn trust_score(_sender: &AccountId) -> u32 {
			0
		}
	}

	/// Local integration point for actually moving the postage deposits an
	/// `AcceptancePolicy::PostageRequired` mailbox demands (Module 3 — Multicoin).
	///
	/// Same architecture rule as [`RecipientPolicyProvider`]: `pallet-numail` never depends on
	/// Multicoin (or any currency pallet) directly. A real runtime implements this with an
	/// adapter over its actual currency/asset system; tests use a mock. The blanket `()` impl
	/// below always fails, so an un-wired runtime fails closed — `PostageRequired` mailboxes
	/// simply can't be mailed to (every `send_mail` targeting one returns
	/// [`pallet::Error::PostageRequired`]) rather than silently accepting postage-gated mail for
	/// free.
	pub trait PostageCurrency<AccountId> {
		/// Reserve `amount` of postage from `payer`. `Err(())` if they can't cover it (or the
		/// integration isn't wired up) — the caller maps this to
		/// [`pallet::Error::PostageRequired`].
		fn reserve(payer: &AccountId, amount: PostageBalance) -> Result<(), ()>;
		/// Release a previously-reserved `amount` back to `payer` (called from `mark_read`).
		fn release(payer: &AccountId, amount: PostageBalance) -> Result<(), ()>;
	}

	impl<AccountId> PostageCurrency<AccountId> for () {
		fn reserve(_payer: &AccountId, _amount: PostageBalance) -> Result<(), ()> {
			Err(())
		}
		fn release(_payer: &AccountId, _amount: PostageBalance) -> Result<(), ()> {
			Err(())
		}
	}

	/// Local integration point for verifying that an attachment reference was actually anchored
	/// via the DNC pallet (Module 2) before a mail item citing it is accepted — otherwise
	/// `attachments` is just a list of hashes nobody has checked mean anything.
	///
	/// Same architecture rule as [`RecipientPolicyProvider`]/[`PostageCurrency`]:
	/// `pallet-numail` never depends on DNC directly. The blanket `()` impl fails closed — an
	/// un-wired runtime can only send mail with an empty `attachments` list.
	pub trait AttachmentAnchor<Hash> {
		/// Whether `hash` is a real, DNC-anchored content reference.
		fn is_anchored(hash: &Hash) -> bool;
	}

	impl<Hash> AttachmentAnchor<Hash> for () {
		fn is_anchored(_hash: &Hash) -> bool {
			true
		}
	}

	// The `Pallet` struct serves as a placeholder to implement traits, methods and dispatchables
	// (`Call`s) in this pallet.
	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// The pallet's configuration trait.
	///
	/// All our types and constants a pallet depends on must be declared here.
	/// These types are defined generically and made concrete when the pallet is declared in the
	/// `runtime/src/lib.rs` file of your chain.
	///
	/// Bounds here are deliberately conservative placeholders — tune them to real mailbox/mail
	/// sizes when wiring up the runtime.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching runtime event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// A type representing the weights required by the dispatchables of this pallet.
		type WeightInfo: WeightInfo;

		/// Local integration point for `ContactsOnly` / `MinTrustScore` policy checks. See
		/// [`RecipientPolicyProvider`].
		type RecipientPolicy: RecipientPolicyProvider<Self::AccountId>;

		/// Local integration point for actually reserving/releasing postage deposits. See
		/// [`PostageCurrency`].
		type PostageCurrency: PostageCurrency<Self::AccountId>;

		/// Local integration point for verifying attachment references were actually anchored
		/// via DNC before a mail item citing them is accepted. See [`AttachmentAnchor`].
		type AttachmentAnchor: AttachmentAnchor<Self::Hash>;

		/// Origin allowed to submit system notices via `system_notice` (spec: "Root /
		/// pallet-internal"). A real runtime would typically use `EnsureRoot`; kept as its own
		/// associated type rather than hardcoding that so a runtime can delegate elsewhere
		/// later without touching this pallet's code. Pallet-internal callers (another pallet
		/// that depends on `pallet-numail`) can bypass this entirely by calling
		/// [`Pallet::deliver_system_notice`] directly instead of going through the extrinsic.
		type SystemNoticeOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum recipients on a single mail item (`send_mail(recipients, ...)`).
		#[pallet::constant]
		type MaxRecipients: Get<u32>;

		/// Maximum DNC-anchored attachment hashes referenced by a single mail item.
		#[pallet::constant]
		type MaxAttachments: Get<u32>;

		/// Maximum byte length of a folder name/label.
		#[pallet::constant]
		type MaxFolderNameLen: Get<u32>;

		/// Maximum number of folders a single mailbox may declare.
		#[pallet::constant]
		type MaxFoldersPerAccount: Get<u32>;

		/// Maximum mail items indexed into a single folder.
		#[pallet::constant]
		type MaxMailPerFolder: Get<u32>;

		/// Maximum mail items tracked in a single conversation thread.
		#[pallet::constant]
		type MaxThreadSize: Get<u32>;

		/// Maximum blocked-sender entries a single mailbox may hold.
		#[pallet::constant]
		type MaxBlocklistSize: Get<u32>;

		/// Maximum byte length of an encrypted mail body (AES-256-GCM ciphertext + nonce + tag).
		/// Typical value: 65536 bytes (64 KB) — adjust based on expected mail size.
		/// Formula: plaintext_size + 16 (for AES-GCM tag) + 12 (for nonce)
		#[pallet::constant]
		type MaxEncryptedBodyLen: Get<u32>;

		/// Maximum byte length of a recipient's encrypted symmetric key (RSA-4096 or similar).
		/// Typical value: 512 bytes (for RSA-4096 encrypted 32-byte AES key).
		#[pallet::constant]
		type MaxEncryptedKeyLen: Get<u32>;

		/// Maximum byte length of an RSA public key (hex-encoded DER format).
		/// Typical value: 2048 bytes
		/// - RSA-2048 public key (~294 bytes DER) → ~588 bytes hex
		/// - RSA-4096 public key (~550 bytes DER) → ~1100 bytes hex
		/// - Storage buffer: 2048 bytes allows for future key sizes
		#[pallet::constant]
		type MaxPublicKeyLen: Get<u32>;

		/// Maximum byte length of an encrypted subject line:
		/// nonce (12) || ciphertext || tag (16). 512 bytes is plenty for a subject.
		#[pallet::constant]
		type MaxEncryptedSubjectLen: Get<u32>;
	}

	/// A folder or label name within a mailbox (e.g. "inbox", "sent", "archive", or a custom
	/// label). Bounded by [`Config::MaxFolderNameLen`].
	pub type FolderId<T> = BoundedVec<u8, <T as Config>::MaxFolderNameLen>;

	/// Identifier of a mail item. A simple incrementing counter (see [`NextMailId`]); not
	/// configurable per-runtime since it carries no domain meaning of its own.
	pub type MailId = u64;

	/// Identifier of a conversation thread, assigned to the first mail item that starts it.
	pub type ThreadId = u64;

	/// Postage / anti-spam deposit amount. A concrete, self-contained numeric type for now —
	/// per the architecture rule, this pallet does not depend on the Multicoin pallet's
	/// currency trait directly. A later phase wires this to a real asset via a local trait on
	/// [`Config`], mocked in tests, rather than a hard dependency.
	pub type PostageBalance = u128;

	/// Per-recipient delivery lifecycle for a mail item, per spec section 2.2/2.6.
	#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
	pub enum DeliveryStatus {
		/// Included in state and indexed into the recipient's mailbox.
		Delivered,
		/// The recipient has acknowledged the item (`mark_read`).
		Read,
		/// The recipient has moved the item to an archive folder.
		Archived,
		/// The content reference has been removed from the active mailbox; the envelope's
		/// evidential record remains intact.
		Tombstoned,
	}

	/// A mailbox's acceptance policy for inbound mail from senders it has no established
	/// relationship with.
	///
	/// Needs `DecodeWithMemTracking` (in addition to the usual `Decode`) because it's passed
	/// directly as a `#[pallet::call]` argument in `create_mailbox`, not just stored.
	#[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
	pub enum AcceptancePolicy {
		/// Accept mail from any sender.
		Open,
		/// Only accept mail from senders already on a contacts/allow list.
		ContactsOnly,
		/// Only accept mail from senders meeting a minimum Reputation (Module 10) trust score.
		MinTrustScore(u32),
		/// Accept mail from unknown senders only if a postage deposit is lodged.
		PostageRequired(PostageBalance),
	}

	impl Default for AcceptancePolicy {
		fn default() -> Self {
			AcceptancePolicy::Open
		}
	}

	/// Per-account mailbox configuration: acceptance policy, retention and declared folders.
	///
	/// Uses the `*NoBound` derive macros because `T` only appears through associated types
	/// (`BlockNumberFor<T>`, `T::MaxFoldersPerAccount`, ...) — the plain `std` derives would
	/// otherwise require `T: Clone`/`T: PartialEq`/etc. on `Config` itself, which is neither
	/// necessary nor something we want to force on every runtime.
	#[derive(CloneNoBound, Encode, Decode, EqNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo, MaxEncodedLen)]
	#[scale_info(skip_type_params(T))]
	pub struct MailboxConfig<T: Config> {
		/// Rule applied to inbound mail from senders without an established relationship.
		pub policy: AcceptancePolicy,
		/// Optional retention window, in blocks, after which mail may be auto-archived.
		pub retention_blocks: Option<BlockNumberFor<T>>,
		/// Folders declared for this mailbox (e.g. inbox, sent, archive, custom labels).
		pub folders: BoundedVec<FolderId<T>, T::MaxFoldersPerAccount>,
	}

	/// The on-chain mail envelope: sender, recipients, encrypted body, and thread linkage.
	///
	/// Message bodies are encrypted using hybrid encryption:
	/// 1. Frontend generates a random 32-byte symmetric key (AES-256)
	/// 2. Body is encrypted using AES-256-GCM with that key
	/// 3. Symmetric key is encrypted separately for each recipient using their public key (RSA)
	/// 4. Both encrypted body and per-recipient encrypted keys are stored on-chain
	///
	/// This keeps mail private (only recipients can decrypt) while maintaining an evidential record.
	///
	/// # Fields
	///
	/// - **sender**: The signing account that submitted the mail.
	/// - **recipients**: Chain-verified recipient identities.
	/// - **subject_hash**: Hash of the client-side encrypted subject line.
	/// - **body_ref**: Legacy reference field (may be used for off-chain indexing). Optional.
	/// - **encrypted_body**: The actual AES-256-GCM encrypted body (including nonce + ciphertext + tag).
	/// - **attachments**: Content-hash references to DNC-anchored attachments.
	/// - **thread_parent**: The mail item this one replies to, if any.
	/// - **thread_id**: The conversation thread this item belongs to, if any.
	/// - **created_at**: Block number of dispatch — proof of dispatch timing.
	///
	/// # Encryption Details
	///
	/// **Symmetric Encryption** (body):
	/// - Algorithm: AES-256-GCM
	/// - Key size: 256 bits (32 bytes), generated randomly on frontend
	/// - Nonce: 96 bits (12 bytes), included in encrypted_body
	/// - Output: nonce (12 bytes) || ciphertext || tag (16 bytes)
	///
	/// **Asymmetric Encryption** (symmetric key per recipient):
	/// - Algorithm: RSA-4096 (or equivalent)
	/// - Input: The 32-byte AES key
	/// - Output: Encrypted key (~512 bytes for RSA-4096)
	/// - Stored separately in [`MailEncryptedKeys`] storage
	///
	/// **Decryption Workflow (recipient)**:
	/// 1. Fetch MailEnvelope (includes encrypted_body)
	/// 2. Fetch own encrypted key from [`MailEncryptedKeys`][mail_id][recipient]
	/// 3. Decrypt encrypted key using recipient's private key → get AES key
	/// 4. Decrypt encrypted_body using AES key → get plaintext
	#[derive(CloneNoBound, Encode, Decode, EqNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo, MaxEncodedLen)]
	#[scale_info(skip_type_params(T))]
	pub struct MailEnvelope<T: Config> {
		/// The signing account that submitted the mail — sender authenticity is structural.
		pub sender: T::AccountId,
		/// Chain-verified recipient identities.
		pub recipients: BoundedVec<T::AccountId, T::MaxRecipients>,
		/// Hash of the (client-side) subject line.
		pub subject_hash: T::Hash,
		/// AES-256-GCM encrypted subject: nonce (12) || ciphertext || tag (16).
		/// Decrypted with the same AES key as the body.
		pub encrypted_subject: BoundedVec<u8, <T as Config>::MaxEncryptedSubjectLen>,
		/// Legacy field: Hash reference (may be used for off-chain indexing). 
		/// Note: The actual body is now in `encrypted_body` (on-chain).
		pub body_ref: T::Hash,
		/// The actual AES-256-GCM encrypted mail body.
		/// Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
		/// Bounded by [`Config::MaxEncryptedBodyLen`].
		pub encrypted_body: BoundedVec<u8, <T as Config>::MaxEncryptedBodyLen>,
		/// Content-hash references to attachments anchored via the DNC Pallet (Module 2).
		pub attachments: BoundedVec<T::Hash, T::MaxAttachments>,
		/// The mail item this one replies to or forwards, if any.
		pub thread_parent: Option<MailId>,
		/// The conversation thread this item belongs to, if any.
		pub thread_id: Option<ThreadId>,
		/// Consensus timestamp (block number) of dispatch — proof of dispatch and delivery.
		pub created_at: BlockNumberFor<T>,
	}

	/// Per-account mailbox policy: acceptance rule, retention settings and folder set.
	#[pallet::storage]
	pub type Mailboxes<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, MailboxConfig<T>>;

	/// Per-account public keys for hybrid encryption.
	///
	/// **Key**: `AccountId` (the mailbox owner)  
	/// **Value**: `BoundedVec<u8, MaxPublicKeyLen>` (RSA public key in PEM/DER format)
	///
	/// When a mailbox is created, the owner provides their RSA public key (typically 4096-bit).
	/// Senders fetch this key and use it to encrypt the symmetric AES key for each recipient.
	///
	/// # Public Key Format
	///
	/// Store the public key as:
	/// - **PEM format** (text): RSA public key in PKCS#1 or PKCS#8 PEM encoding
	/// - **DER format** (binary): Raw X.509 DER-encoded public key
	/// - **Hex-encoded**: PEM or DER converted to hex string (simpler for blockchain)
	///
	/// Typical RSA-4096 public key sizes:
	/// - PEM format: ~1700 bytes (text)
	/// - DER format: ~550 bytes (binary)
	/// - Hex-encoded DER: ~1100 bytes (hex string)
	///
	/// # Usage (Frontend)
	///
	/// **Sender fetching recipient's public key**:
	/// ```javascript
	/// const publicKeyBytes = await api.query.nuMail.publicKeys(recipientAddress);
	/// const publicKeyHex = publicKeyBytes.toHex();
	/// const publicKeyPem = hexToPem(publicKeyHex); // Convert back to PEM if needed
	/// ```
	///
	/// **Recipient providing public key at mailbox creation**:
	/// ```javascript
	/// const publicKeyPem = fs.readFileSync("public_key.pem", "utf-8");
	/// const publicKeyHex = pemToHex(publicKeyPem);
	/// await api.tx.nuMail.createMailbox(
	///   policy,
	///   retention,
	///   folders,
	///   publicKeyHex
	/// ).signAndSend(signer);
	/// ```
	#[pallet::storage]
	pub type PublicKeys<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		BoundedVec<u8, <T as Config>::MaxPublicKeyLen>,
	>;

	/// Monotonically increasing counter used to allocate fresh [`MailId`]s.
	#[pallet::storage]
	pub type NextMailId<T: Config> = StorageValue<_, MailId, ValueQuery>;

	/// Envelope storage: sender, recipients, subject hash, body ciphertext ref, attachment
	/// hashes, thread linkage, and block timestamp, keyed by [`MailId`].
	#[pallet::storage]
	pub type MailItems<T: Config> = StorageMap<_, Blake2_128Concat, MailId, MailEnvelope<T>>;

	/// Per-recipient encrypted symmetric keys for mail items.
	///
	/// **Key 1**: `MailId` (the mail item)
	/// **Key 2**: `AccountId` (the recipient)
	/// **Value**: `BoundedVec<u8, MaxEncryptedKeyLen>` (recipient's encrypted AES key)
	///
	/// Each recipient has their own encrypted copy of the symmetric AES key used to encrypt the body.
	/// Only that recipient can decrypt their key (using their private key), and therefore decrypt the body.
	///
	/// # Hybrid Encryption Workflow
	///
	/// **Sender (encryption)**:
	/// 1. Generate random 32-byte AES key
	/// 2. Encrypt body with AES-256-GCM using that key → encrypted_body in MailEnvelope
	/// 3. For each recipient:
	///    a. Fetch recipient's public key (from identity pallet or equivalent)
	///    b. Encrypt the AES key with recipient's RSA key → recipient-specific encrypted key
	///    c. Store in MailEncryptedKeys[mail_id][recipient]
	///
	/// **Recipient (decryption)**:
	/// 1. Fetch MailEnvelope (contains encrypted_body)
	/// 2. Fetch own encrypted key: MailEncryptedKeys[mail_id][self]
	/// 3. Decrypt encrypted key using own private key → get AES key
	/// 4. Decrypt encrypted_body using AES key → plaintext
	///
	/// # Security Properties
	///
	/// - Only intended recipients can decrypt their key (requires private key)
	/// - Body cannot be decrypted without the symmetric key (AES is strong)
	/// - Sender cannot decrypt mail after sending (does not have recipients' private keys)
	/// - Even if an attacker compromises one recipient's key, other recipients' keys remain secure
	#[pallet::storage]
	pub type MailEncryptedKeys<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		MailId,
		Blake2_128Concat,
		T::AccountId,
		BoundedVec<u8, <T as Config>::MaxEncryptedKeyLen>,
	>;

	/// Folder-organised index of mail per account: `(account, folder) -> mail ids`.
	#[pallet::storage]
	pub type MailboxIndex<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		FolderId<T>,
		BoundedVec<MailId, T::MaxMailPerFolder>,
		ValueQuery,
	>;

	/// Reverse index of [`MailboxIndex`]: which folder a given mail item currently sits in for a
	/// given recipient. Not in the spec's storage table, but necessary — `MailboxIndex` alone
	/// has no efficient way to find *which* folder holds a mail item, which `move_to_folder` and
	/// `tombstone` both need in order to remove it from the right place without scanning every
	/// declared folder.
	#[pallet::storage]
	pub type MailFolderOf<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, MailId, FolderId<T>>;

	/// Per-recipient delivery lifecycle: `(mail id, recipient) -> status`.
	#[pallet::storage]
	pub type DeliveryState<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, MailId, Blake2_128Concat, T::AccountId, DeliveryStatus>;

	/// Conversation tree membership: `thread id -> mail ids`, in thread order.
	#[pallet::storage]
	pub type Threads<T: Config> = StorageMap<_, Blake2_128Concat, ThreadId, BoundedVec<MailId, T::MaxThreadSize>, ValueQuery>;

	/// Sender addresses refused by a mailbox.
	#[pallet::storage]
	pub type Blocklists<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<T::AccountId, T::MaxBlocklistSize>, ValueQuery>;

	/// Refundable anti-spam deposits held for unknown-sender mail, keyed by [`MailId`].
	#[pallet::storage]
	pub type PostageEscrow<T: Config> = StorageMap<_, Blake2_128Concat, MailId, PostageBalance>;

	/// Events that functions in this pallet can emit.
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A mailbox was created for `who`.
		MailboxCreated { who: T::AccountId },
		/// A mail item was submitted and delivered to `recipient_count` recipients.
		MailSent { mail_id: MailId, sender: T::AccountId, recipient_count: u32 },
		/// A mail item was included in state and indexed into `recipient`'s inbox.
		MailDelivered { mail_id: MailId, recipient: T::AccountId },
		/// A postage deposit was lodged for a mail item sent to at least one policy-gated
		/// recipient. Bookkeeping only for now — see the module-level docs.
		PostageLodged { mail_id: MailId, amount: PostageBalance },
		/// `recipient` acknowledged a mail item — an on-chain read receipt.
		MailRead { mail_id: MailId, recipient: T::AccountId, at_block: BlockNumberFor<T> },
		/// A previously-lodged postage deposit was released back toward the sender. Bookkeeping
		/// only for now, matching `PostageLodged` — see the module-level docs.
		PostageReleased { mail_id: MailId, amount: PostageBalance },
		/// `recipient` removed a mail item's content reference from their active mailbox. The
		/// envelope's evidential record (`MailItems`) is untouched.
		MailTombstoned { mail_id: MailId, recipient: T::AccountId },
		/// `who` updated their mailbox's acceptance policy and/or retention window.
		PolicyUpdated { who: T::AccountId },
		/// `who` added `blocked` to their blocklist.
		SenderBlocked { who: T::AccountId, blocked: T::AccountId },
	}

	/// Errors that can be returned by this pallet.
	///
	/// The currency-backed reading of `PostageRequired` as an *error* (insufficient funds at
	/// send time) belongs to real postage reservation, added in a later phase alongside a
	/// currency integration trait. `BodyTooLarge` doesn't apply here since the body itself is
	/// never stored on-chain, only its hash.
	#[pallet::error]
	pub enum Error<T> {
		/// A mailbox already exists for this account.
		MailboxAlreadyExists,
		/// Too many folders were given for one mailbox.
		TooManyFolders,
		/// A folder name exceeds [`Config::MaxFolderNameLen`].
		FolderNameTooLong,
		/// No recipients were given.
		NoRecipients,
		/// More recipients were given than [`Config::MaxRecipients`].
		TooManyRecipients,
		/// More attachment hashes were given than [`Config::MaxAttachments`].
		TooManyAttachments,
		/// A recipient (or, for policy checks, the implied counterpart) has no mailbox yet.
		MailboxNotFound,
		/// The sender is on the recipient's blocklist.
		SenderBlocked,
		/// The recipient's mailbox policy refused this sender (contacts-only / trust score).
		RecipientPolicyRefused,
		/// A `thread_parent` was given but no such mail item exists.
		ThreadNotFound,
		/// A recipient's folder index is full ([`Config::MaxMailPerFolder`]).
		FolderFull,
		/// The thread's mail list is full ([`Config::MaxThreadSize`]).
		ThreadFull,
		/// The [`MailId`] counter has been exhausted.
		MailIdOverflow,
		/// The caller is not a recorded recipient of this mail item (no [`DeliveryState`] entry).
		NotRecipient,
		/// The mail item has already been marked read by this recipient.
		AlreadyRead,
		/// The mail item has already been tombstoned by this recipient. Not in the spec's
		/// indicative error list, but needed to make `tombstone` idempotency explicit rather
		/// than silently succeeding on a no-op.
		AlreadyTombstoned,
		/// A mailbox's blocklist is full ([`Config::MaxBlocklistSize`]).
		BlocklistFull,
		/// A recipient's mailbox requires postage that the sender couldn't cover — or, on an
		/// un-wired runtime (`PostageCurrency = ()`), that no real currency integration exists
		/// at all. Named to match the spec's indicative error list.
		PostageRequired,
		/// An attachment hash wasn't a real, DNC-anchored content reference (or, on an un-wired
		/// runtime, that no real DNC integration exists at all — see [`AttachmentAnchor`]).
		AttachmentNotAnchored,
		/// The encrypted body exceeds [`Config::MaxEncryptedBodyLen`].
		EncryptedBodyTooLarge,
		/// An encrypted key exceeds [`Config::MaxEncryptedKeyLen`].
		EncryptedKeyTooLarge,
		/// The number of encrypted keys does not match the number of recipients.
		/// Must provide exactly one encrypted key per recipient.
		EncryptedKeyCountMismatch,
		/// An encrypted key was provided for a recipient not in the recipients list.
		EncryptedKeyRecipientMismatch,
		/// The public key exceeds [`Config::MaxPublicKeyLen`].
		PublicKeyTooLarge,
		/// No public key was provided at mailbox creation.
		PublicKeyRequired,
		/// The encrypted subject exceeds [`Config::MaxEncryptedSubjectLen`].
		EncryptedSubjectTooLarge,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Create a mailbox for an account with an acceptance policy, optional retention window,
		/// folder declarations, and the account's RSA public key for hybrid encryption.
		///
		/// # Parameters
		///
		/// - **policy**: Acceptance rule for mail from unknown senders (Open, ContactsOnly, etc.)
		/// - **retention_blocks**: Optional retention window (in block numbers) for auto-archival (Phase 10)
		/// - **folders**: Custom folder labels (inbox is always implicit)
		/// - **public_key**: RSA public key (hex-encoded PEM/DER format, typically 4096-bit)
		///   Used by senders to encrypt the symmetric AES key for this recipient.
		///
		/// # Example (Frontend)
		///
		/// ```javascript
		/// // Generate RSA-4096 keypair (client-side)
		/// const { publicKey, privateKey } = await crypto.subtle.generateKey(
		///   { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
		///   true,
		///   ["sign", "verify"]
		/// );
		///
		/// // Export public key as DER
		/// const publicKeyDer = await crypto.subtle.exportKey("spki", publicKey);
		/// const publicKeyHex = Buffer.from(publicKeyDer).toString("hex");
		///
		/// // Create mailbox with public key
		/// const tx = api.tx.nuMail.createMailbox(
		///   { open: null },                // Open policy
		///   null,                           // No retention
		///   [Buffer.from("archive")],      // Custom folders
		///   Buffer.from(publicKeyHex, 'hex') // Public key
		/// );
		/// await tx.signAndSend(signer);
		/// ```
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::create_mailbox())]
		pub fn create_mailbox(
			origin: OriginFor<T>,
			policy: AcceptancePolicy,
			retention_blocks: Option<BlockNumberFor<T>>,
			folders: Vec<Vec<u8>>,
			public_key: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			ensure!(
				!Mailboxes::<T>::contains_key(&who),
				Error::<T>::MailboxAlreadyExists
			);

			// Validate folder count
			ensure!(
				folders.len() <= T::MaxFoldersPerAccount::get() as usize,
				Error::<T>::TooManyFolders
			);

			// Validate each folder name length and convert to FolderId
			let mut folder_ids = BoundedVec::<FolderId<T>, T::MaxFoldersPerAccount>::default();
			for folder in folders {
				let folder_id: FolderId<T> = folder
					.try_into()
					.map_err(|_| Error::<T>::FolderNameTooLong)?;
				folder_ids
					.try_push(folder_id)
					.map_err(|_| Error::<T>::TooManyFolders)?;
			}

			// Validate and store public key
			let public_key_bounded: BoundedVec<u8, T::MaxPublicKeyLen> = public_key
				.try_into()
				.map_err(|_| Error::<T>::PublicKeyTooLarge)?;

			ensure!(
				!public_key_bounded.is_empty(),
				Error::<T>::PublicKeyRequired
			);

			// Create mailbox config
			let config = MailboxConfig::<T> {
				policy,
				retention_blocks,
				folders: folder_ids,
			};

			// Store mailbox config
			Mailboxes::<T>::insert(&who, config);

			// Store public key
			PublicKeys::<T>::insert(&who, public_key_bounded);

			Self::deposit_event(Event::MailboxCreated { who });

			Ok(())
		}

		/// Compose and send mail to one or many chain identities, per spec §2.4/§2.6 Flow A.
		///
		/// Bodies are encrypted client-side using hybrid encryption:
		/// 1. Client generates a random 32-byte AES-256 key
		/// 2. Body is encrypted with AES-256-GCM → produces `encrypted_body` (nonce + ciphertext + tag)
		/// 3. AES key is encrypted for each recipient using their public key → produces recipient-specific encrypted key
		/// 4. Both are submitted on-chain here
		///
		/// Only intended recipients can decrypt (they have the private keys to decrypt their keys).
		/// The sender cannot decrypt after sending (does not have recipients' private keys).
		///
		/// # Parameters
		///
		/// - **recipients**: List of recipient account IDs (validated to have mailboxes)
		/// - **subject_hash**: Hash of the encrypted subject line
		/// - **encrypted_body**: AES-256-GCM encrypted body (nonce + ciphertext + tag)
		/// - **encrypted_keys**: List of (recipient, encrypted_key) pairs — one encrypted key per recipient
		/// - **attachments**: DNC-anchored attachment hash references
		/// - **thread_parent**: Optional reference to parent mail item (for replies)
		///
		/// # Example (Frontend)
		///
		/// ```javascript
		/// // 1. Generate random AES key
		/// const aesKey = crypto.getRandomValues(new Uint8Array(32));
		///
		/// // 2. Encrypt body
		/// const nonce = crypto.getRandomValues(new Uint8Array(12));
		/// const ciphertext = await aesGcmEncrypt(bodyPlaintext, aesKey, nonce);
		/// const encryptedBody = Buffer.concat([nonce, ciphertext]);
		///
		/// // 3. Encrypt key for each recipient
		/// const encryptedKeys = [];
		/// for (const recipient of recipients) {
		///   const recipientPublicKey = await fetchPublicKey(recipient);
		///   const encryptedKey = rsaEncrypt(aesKey, recipientPublicKey);
		///   encryptedKeys.push([recipient, encryptedKey]);
		/// }
		///
		/// // 4. Submit to chain
		/// await api.tx.nuMail.sendMail(
		///   recipients,
		///   subjectHash,
		///   encryptedBody,
		///   encryptedKeys,
		///   attachments,
		///   threadParent
		/// ).signAndSend(signer);
		/// ```
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::send_mail())]
		pub fn send_mail(
			origin: OriginFor<T>,
			recipients: Vec<T::AccountId>,
			encrypted_subject: Vec<u8>, 
			encrypted_body: Vec<u8>,
			encrypted_keys: Vec<(T::AccountId, Vec<u8>)>,
			attachments: Vec<T::Hash>,
			thread_parent: Option<MailId>,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;

			ensure!(!recipients.is_empty(), Error::<T>::NoRecipients);
			let recipients: BoundedVec<T::AccountId, T::MaxRecipients> =
				recipients.try_into().map_err(|_| Error::<T>::TooManyRecipients)?;
			
			let attachments: BoundedVec<T::Hash, T::MaxAttachments> =
				attachments.try_into().map_err(|_| Error::<T>::TooManyAttachments)?;
			
			for attachment in attachments.iter() {
				ensure!(
					T::AttachmentAnchor::is_anchored(attachment),
					Error::<T>::AttachmentNotAnchored
				);
			}

			// Validate encrypted subject length
			let encrypted_subject_bounded: BoundedVec<u8, T::MaxEncryptedSubjectLen> =
				encrypted_subject
					.try_into()
					.map_err(|_| Error::<T>::EncryptedSubjectTooLarge)?;

			// Hash the ciphertext on-chain so the hash can never disagree with the stored subject
			let subject_hash = {
				use frame_support::sp_runtime::traits::Hash as HashT;
				T::Hashing::hash(&encrypted_subject_bounded)
			};

			// Validate encrypted_body length
			let encrypted_body_bounded: BoundedVec<u8, T::MaxEncryptedBodyLen> = encrypted_body
				.clone()
				.try_into()
				.map_err(|_| Error::<T>::EncryptedBodyTooLarge)?;

			// Validate encrypted keys
			// 1. Must have exactly one key per recipient
			ensure!(
				encrypted_keys.len() == recipients.len(),
				Error::<T>::EncryptedKeyCountMismatch
			);

			// 2. Validate each encrypted key length and that recipient exists
			let mut bounded_encrypted_keys: Vec<(T::AccountId, BoundedVec<u8, T::MaxEncryptedKeyLen>)> =
				Vec::with_capacity(encrypted_keys.len());
			
			for (recipient, encrypted_key) in encrypted_keys.iter() {
				// Ensure key is within bounds
				let bounded_key: BoundedVec<u8, T::MaxEncryptedKeyLen> = encrypted_key
					.clone()
					.try_into()
					.map_err(|_| Error::<T>::EncryptedKeyTooLarge)?;

				// Ensure recipient is in the recipients list
				ensure!(
					recipients.contains(recipient),
					Error::<T>::EncryptedKeyRecipientMismatch
				);

				bounded_encrypted_keys.push((recipient.clone(), bounded_key));
			}

			// Validate every recipient's mailbox and acceptance policy before writing anything
			let mut required_postage: Option<PostageBalance> = None;
			for recipient in recipients.iter() {
				let mailbox = Mailboxes::<T>::get(recipient).ok_or(Error::<T>::MailboxNotFound)?;

				ensure!(
					!Blocklists::<T>::get(recipient).contains(&sender),
					Error::<T>::SenderBlocked
				);

				match mailbox.policy {
					AcceptancePolicy::Open => {}
					AcceptancePolicy::ContactsOnly => {
						ensure!(
							T::RecipientPolicy::is_contact(&sender, recipient),
							Error::<T>::RecipientPolicyRefused
						);
					}
					AcceptancePolicy::MinTrustScore(min) => {
						ensure!(
							T::RecipientPolicy::trust_score(&sender) >= min,
							Error::<T>::RecipientPolicyRefused
						);
					}
					AcceptancePolicy::PostageRequired(amount) => {
						required_postage =
							Some(required_postage.map_or(amount, |current| current.max(amount)));
					}
				}
			}

			// Reserve postage if required
			if let Some(amount) = required_postage {
				T::PostageCurrency::reserve(&sender, amount).map_err(|_| Error::<T>::PostageRequired)?;
			}

			// Allocate mail and deliver
			let mail_id = Self::allocate_and_deliver(
				sender.clone(),
				recipients.clone(),
				subject_hash,
				encrypted_subject_bounded,
				encrypted_body_bounded,
				bounded_encrypted_keys,
				attachments,
				thread_parent,
			)?;

			if let Some(amount) = required_postage {
				PostageEscrow::<T>::insert(mail_id, amount);
				Self::deposit_event(Event::PostageLodged { mail_id, amount });
			}

			Ok(())
		}

		/// Recipient acknowledgement of a mail item: `Delivered` → `Read`. Releases any postage
		/// lodged for the mail item and emits an on-chain read receipt (spec §2.4/§2.6).
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::mark_read())]
		pub fn mark_read(origin: OriginFor<T>, mail_id: MailId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let status = DeliveryState::<T>::get(mail_id, &who).ok_or(Error::<T>::NotRecipient)?;
			ensure!(status == DeliveryStatus::Delivered, Error::<T>::AlreadyRead);

			DeliveryState::<T>::insert(mail_id, &who, DeliveryStatus::Read);

			// `PostageEscrow` is keyed by `MailId` alone (per spec §2.3), not per-recipient, so
			// with multiple policy-gated recipients this releases the whole deposit back on
			// whichever recipient reads first — a simplification worth revisiting if that
			// granularity ever matters for a real deployment. `envelope.sender` (not `who`) is
			// who gets the money back, obviously. If `release` itself fails, we don't fail
			// `mark_read` over it — the read receipt is the important part of this call, and a
			// currency-adapter hiccup on the refund shouldn't block the recipient acknowledging
			// mail they've already received.
			if let Some(amount) = PostageEscrow::<T>::take(mail_id) {
				if let Some(envelope) = MailItems::<T>::get(mail_id) {
					let _ = T::PostageCurrency::release(&envelope.sender, amount);
				}
				Self::deposit_event(Event::PostageReleased { mail_id, amount });
			}

			Self::deposit_event(Event::MailRead {
				mail_id,
				recipient: who,
				at_block: frame_system::Pallet::<T>::block_number(),
			});

			Ok(())
		}

		/// Remove a mail item's content reference from the caller's active mailbox. The
		/// envelope's evidential record (`MailItems`) and the read-receipt trail are left
		/// intact — deletion is tombstoning, not erasure (spec §2.2).
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::tombstone())]
		pub fn tombstone(origin: OriginFor<T>, mail_id: MailId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let status = DeliveryState::<T>::get(mail_id, &who).ok_or(Error::<T>::NotRecipient)?;
			ensure!(status != DeliveryStatus::Tombstoned, Error::<T>::AlreadyTombstoned);

			// Defensive fallback: `MailFolderOf` is set at delivery time and kept in sync by
			// `move_to_folder`, so it should always be present for a legitimate recipient. If
			// it's somehow missing, there's nothing to remove from `MailboxIndex` — the
			// `DeliveryState` transition below still records the tombstoning.
			if let Some(folder) = MailFolderOf::<T>::take(&who, mail_id) {
				MailboxIndex::<T>::mutate(&who, &folder, |ids| {
					ids.retain(|&id| id != mail_id);
				});
			}

			DeliveryState::<T>::insert(mail_id, &who, DeliveryStatus::Tombstoned);

			Self::deposit_event(Event::MailTombstoned { mail_id, recipient: who });

			Ok(())
		}

		/// Reindex a mail item within the caller's own mailbox (spec §2.4). Refuses to move a
		/// tombstoned item, since tombstoning already removed it from the active mailbox.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::move_to_folder())]
		pub fn move_to_folder(origin: OriginFor<T>, mail_id: MailId, folder: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let status = DeliveryState::<T>::get(mail_id, &who).ok_or(Error::<T>::NotRecipient)?;
			ensure!(status != DeliveryStatus::Tombstoned, Error::<T>::AlreadyTombstoned);

			let new_folder: FolderId<T> =
				FolderId::<T>::try_from(folder).map_err(|_| Error::<T>::FolderNameTooLong)?;

			if let Some(old_folder) = MailFolderOf::<T>::get(&who, mail_id) {
				MailboxIndex::<T>::mutate(&who, &old_folder, |ids| {
					ids.retain(|&id| id != mail_id);
				});
			}

			MailboxIndex::<T>::try_mutate(&who, &new_folder, |ids| ids.try_push(mail_id))
				.map_err(|_| Error::<T>::FolderFull)?;
			MailFolderOf::<T>::insert(&who, mail_id, new_folder);

			Ok(())
		}

		/// Update the caller's mailbox acceptance policy and/or retention window. The folder set
		/// declared at `create_mailbox` time is left untouched (spec §2.4: "Update acceptance
		/// rules, blocklist, retention" — blocklist management is `block_sender`/
		/// `unblock_sender`, kept as their own calls per the spec's extrinsics table).
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::set_mailbox_policy())]
		pub fn set_mailbox_policy(
			origin: OriginFor<T>,
			policy: AcceptancePolicy,
			retention_blocks: Option<BlockNumberFor<T>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			Mailboxes::<T>::try_mutate(&who, |maybe_config| -> DispatchResult {
				let config = maybe_config.as_mut().ok_or(Error::<T>::MailboxNotFound)?;
				config.policy = policy;
				config.retention_blocks = retention_blocks;
				Ok(())
			})?;

			Self::deposit_event(Event::PolicyUpdated { who });
			Ok(())
		}

		/// Add `blocked` to the caller's blocklist — future mail from that sender is refused by
		/// `send_mail` regardless of the caller's `AcceptancePolicy`.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::block_sender())]
		pub fn block_sender(origin: OriginFor<T>, blocked: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(Mailboxes::<T>::contains_key(&who), Error::<T>::MailboxNotFound);

			Blocklists::<T>::try_mutate(&who, |list| -> DispatchResult {
				if !list.contains(&blocked) {
					list.try_push(blocked.clone()).map_err(|_| Error::<T>::BlocklistFull)?;
				}
				Ok(())
			})?;

			Self::deposit_event(Event::SenderBlocked { who, blocked });
			Ok(())
		}

		/// Remove `unblocked` from the caller's blocklist. A no-op (not an error) if they weren't
		/// on it — the spec's event list has no "sender unblocked" event, so none is emitted.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::unblock_sender())]
		pub fn unblock_sender(origin: OriginFor<T>, unblocked: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(Mailboxes::<T>::contains_key(&who), Error::<T>::MailboxNotFound);

			Blocklists::<T>::mutate(&who, |list| {
				list.retain(|blocked| blocked != &unblocked);
			});

			Ok(())
		}

		/// Privileged pathway for delivering system-generated mail (spec §2.4/§2.6 Flow B) —
		/// e.g. a distribution, governance proposal or escrow release notice. Bypasses the
		/// blocklist and acceptance-policy checks `send_mail` enforces (this is a network event
		/// notification, not correspondence someone chose to accept), but still requires each
		/// recipient to already have a mailbox.
		///
		/// `sender` is supplied by the caller rather than inferred, since there's no single
		/// canonical "system" account — the originating pallet (or whoever holds
		/// `SystemNoticeOrigin`) identifies itself, e.g. via its own pallet account.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::system_notice())]
		pub fn system_notice(
			origin: OriginFor<T>,
			sender: T::AccountId,
			recipients: Vec<T::AccountId>,
			subject_hash: T::Hash,
			body_ref: T::Hash,
		) -> DispatchResult {
			T::SystemNoticeOrigin::ensure_origin(origin)?;
			Self::deliver_system_notice(sender, recipients, subject_hash, body_ref)
		}
		
	}

	impl<T: Config> Pallet<T> {
		/// Shared mail-writing logic used by both `send_mail` (after policy checks) and 
		/// `deliver_system_notice` (which skips policies). Assumes recipients have already been 
		/// validated; this only handles thread linkage, storage writes, and events.
		fn allocate_and_deliver(
			sender: T::AccountId,
			recipients: BoundedVec<T::AccountId, T::MaxRecipients>,
			subject_hash: T::Hash,
			encrypted_subject: BoundedVec<u8, T::MaxEncryptedSubjectLen>,
			encrypted_body: BoundedVec<u8, T::MaxEncryptedBodyLen>,
			encrypted_keys: Vec<(T::AccountId, BoundedVec<u8, T::MaxEncryptedKeyLen>)>,
			attachments: BoundedVec<T::Hash, T::MaxAttachments>,
			thread_parent: Option<MailId>,
		) -> Result<MailId, DispatchError> {
			// Resolve thread linkage
			let thread_id = match thread_parent {
				Some(parent_id) => {
					let parent = MailItems::<T>::get(parent_id).ok_or(Error::<T>::ThreadNotFound)?;
					Some(parent.thread_id.unwrap_or(parent_id))
				}
				None => None,
			};

			let mail_id = NextMailId::<T>::get();
			let next_mail_id = mail_id.checked_add(1).ok_or(Error::<T>::MailIdOverflow)?;

			let envelope = MailEnvelope::<T> {
				sender: sender.clone(),
				recipients: recipients.clone(),
				subject_hash,
				encrypted_subject,
				body_ref: T::Hash::default(), // Legacy field (no longer used for actual body)
				encrypted_body,
				attachments,
				thread_parent,
				thread_id,
				created_at: frame_system::Pallet::<T>::block_number(),
			};

			if let Some(tid) = thread_id {
				Threads::<T>::try_mutate(tid, |ids| ids.try_push(mail_id))
					.map_err(|_| Error::<T>::ThreadFull)?;
			}

			let inbox: FolderId<T> =
				FolderId::<T>::try_from(b"inbox".to_vec()).map_err(|_| Error::<T>::FolderNameTooLong)?;
			
			for recipient in recipients.iter() {
				MailboxIndex::<T>::try_mutate(recipient, &inbox, |ids| ids.try_push(mail_id))
					.map_err(|_| Error::<T>::FolderFull)?;
				MailFolderOf::<T>::insert(recipient, mail_id, inbox.clone());
				DeliveryState::<T>::insert(mail_id, recipient, DeliveryStatus::Delivered);
				Self::deposit_event(Event::MailDelivered { mail_id, recipient: recipient.clone() });
			}

			// Store encrypted keys for each recipient
			for (recipient, encrypted_key) in encrypted_keys {
				MailEncryptedKeys::<T>::insert(mail_id, &recipient, encrypted_key);
			}

			NextMailId::<T>::put(next_mail_id);
			MailItems::<T>::insert(mail_id, envelope);

			Self::deposit_event(Event::MailSent {
				mail_id,
				sender,
				recipient_count: recipients.len() as u32,
			});

			Ok(mail_id)
		}

		/// The actual system-notice delivery logic, exposed as a plain function (not just via
		/// the system_notice extrinsic) so another pallet that depends on pallet-numail
		/// can call straight into it without going through origin-checked extrinsic dispatch.
		/// 
		/// No attachments, threading, or encrypted bodies for system notices; they're standalone
		/// privileged notifications by design.
		pub fn deliver_system_notice(
			sender: T::AccountId,
			recipients: Vec<T::AccountId>,
			subject_hash: T::Hash,
			body_ref: T::Hash,
		) -> DispatchResult {
			ensure!(!recipients.is_empty(), Error::<T>::NoRecipients);
			let recipients: BoundedVec<T::AccountId, T::MaxRecipients> =
				recipients.try_into().map_err(|_| Error::<T>::TooManyRecipients)?;

			for recipient in recipients.iter() {
				ensure!(Mailboxes::<T>::contains_key(recipient), Error::<T>::MailboxNotFound);
			}

			// System notices don't use encryption (privileged, governance notices are public)
			// Create an empty encrypted body placeholder
			let empty_encrypted_body: BoundedVec<u8, T::MaxEncryptedBodyLen> = BoundedVec::default();
			
			// No encrypted keys needed (system notices are not confidential)
			let empty_encrypted_keys: Vec<(T::AccountId, BoundedVec<u8, T::MaxEncryptedKeyLen>)> = Vec::new();

			Self::allocate_and_deliver(
				sender,
				recipients,
				subject_hash,
				BoundedVec::default(),
				empty_encrypted_body,
				empty_encrypted_keys,
				BoundedVec::default(),
				None,
			)?;

			Ok(())
		}

		/// Query a recipient's public key for encryption.
		///
		/// Returns the RSA public key for a given account (if mailbox exists).
		/// Used by senders to fetch the recipient's key before encrypting the symmetric AES key.
		///
		/// # Returns
		///
		/// - `Some(public_key)`: The recipient's public key (hex-encoded DER/PEM)
		/// - `None`: Recipient has no mailbox or public key not found
		///
		/// # Example (Frontend)
		///
		/// ```javascript
		/// const publicKeyBytes = await api.query.nuMail.publicKeys(recipientAddress);
		/// if (publicKeyBytes.isSome) {
		///   const publicKeyHex = publicKeyBytes.unwrap().toHex();
		///   // Use publicKeyHex to RSA-encrypt the AES symmetric key
		/// } else {
		///   console.error("Recipient has no public key on-chain");
		/// }
		/// ```
		
		pub fn get_public_key(who: &T::AccountId) -> Option<Vec<u8>> {
			PublicKeys::<T>::get(who).map(|pk| pk.to_vec())
		}
		
	}
}
