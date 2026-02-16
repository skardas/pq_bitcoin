use sp1_sdk::{HashableKey, Prover, ProverClient, include_elf};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const PQ_BITCOIN_ELF: &[u8] = include_elf!("pq_bitcoin-program");

fn main() {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(PQ_BITCOIN_ELF);
    println!("{}", vk.bytes32());
}
