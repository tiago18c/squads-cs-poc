use anchor_lang::prelude::*;

#[error_code]
pub enum ClearSigningError {
    #[msg("Transaction account is not owned by the Squads v4 program")]
    InvalidTransactionOwner,
    #[msg("Transaction account does not match the PDA derived from (multisig, transaction_index)")]
    TransactionPdaMismatch,
    #[msg("Account is not a Squads v4 VaultTransaction (discriminator mismatch)")]
    NotAVaultTransaction,
    #[msg("Failed to deserialize the VaultTransaction account data")]
    TransactionDeserializationError,
    #[msg("VaultTransaction.multisig does not match the expected multisig")]
    MultisigMismatch,
    #[msg("VaultTransaction.index does not match the expected transaction_index")]
    TransactionIndexMismatch,
    #[msg("VaultTransaction.vault_index does not match the expected vault_index")]
    VaultIndexMismatch,
    #[msg("Number of ephemeral signers does not match the expected count")]
    EphemeralSignersMismatch,
    #[msg("Wrong number of address lookup table accounts supplied as remaining accounts")]
    LookupTableCountMismatch,
    #[msg("Supplied lookup table account does not match the address referenced by the message")]
    LookupTableAddressMismatch,
    #[msg("Lookup table account is not owned by the address lookup table program")]
    InvalidLookupTableOwner,
    #[msg("Failed to parse the address lookup table account")]
    InvalidLookupTableData,
    #[msg("Address lookup table index is out of bounds")]
    LookupTableIndexOutOfBounds,
    #[msg("Message references an account index that is out of bounds")]
    AccountIndexOutOfBounds,
    #[msg("Number of instructions in the vault transaction does not match the expected list")]
    InstructionCountMismatch,
    #[msg("Instruction program id does not match the expected program id")]
    ProgramIdMismatch,
    #[msg("Instruction account count does not match the expected accounts")]
    AccountCountMismatch,
    #[msg("Instruction account pubkey does not match the expected account")]
    AccountKeyMismatch,
    #[msg("Instruction account writable flag does not match the expected flag")]
    AccountWritableMismatch,
    #[msg("Instruction account signer flag does not match the expected flag")]
    AccountSignerMismatch,
    #[msg("Instruction data does not match the expected data")]
    DataMismatch,
    #[msg("Failed to read the instructions sysvar")]
    InstructionsSysvarError,
    #[msg("Transaction contains an instruction to a program that is not allowed alongside a clear-signed vote")]
    ForbiddenInstruction,
    #[msg("Squads instruction in this transaction is not the expected vote instruction")]
    UnexpectedSquadsInstruction,
    #[msg("Squads vote instruction has too few accounts")]
    MalformedVoteInstruction,
    #[msg("Squads vote instruction targets a different multisig")]
    VoteMultisigMismatch,
    #[msg("Squads vote instruction targets a different proposal")]
    VoteProposalMismatch,
    #[msg("Squads vote instruction member does not match the expected member")]
    VoteMemberMismatch,
    #[msg("Squads vote instruction member is not a transaction signer")]
    VoteMemberNotSigner,
    #[msg("Transaction does not contain the expected Squads vote instruction")]
    MissingVoteInstruction,
    #[msg("Buffer account does not match the address in the args")]
    BufferKeyMismatch,
    #[msg("Buffer account is not owned by the BPF upgradeable loader")]
    InvalidBufferOwner,
    #[msg("Account is not an initialized BPF loader Buffer")]
    NotABuffer,
    #[msg("Buffer program bytes do not hash to the expected value")]
    BufferHashMismatch,
}
