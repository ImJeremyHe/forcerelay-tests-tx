use std::str::FromStr;

use ckb_hash::new_blake2b;
use ckb_jsonrpc_types;
use ckb_sdk::{
    traits::SecpCkbRawKeySigner,
    unlock::{ScriptSigner, SecpSighashScriptSigner},
    Address, AddressPayload, NetworkType, ScriptGroup, ScriptGroupType,
};
use ckb_types::{
    core::{DepType, ScriptHashType, TransactionView},
    h256,
    // molecule::pack_number,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, ScriptOpt},
    prelude::*,
};
use secp256k1::{Secp256k1, SecretKey};

#[test]
fn build_test() {
    const PRIVKEY: &str = "63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d";
    let input = CellInput::new_builder()
        .previous_output(
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x227de871ce6ab120a67960f831b04148bf79b4e56349dde7a8001f93191736ed")
                        .pack(),
                )
                .index(8u32.pack())
                .build(),
        )
        .build();

    let mut blake_2b = new_blake2b();
    blake_2b.update(input.as_slice());
    blake_2b.update(0u64.to_le_bytes().as_slice());
    let mut type_0_args = [0; 32];
    blake_2b.finalize(&mut type_0_args);
    println!("contract type args{:?}", hex::encode(&type_0_args));

    let mut blake_2b = new_blake2b();
    blake_2b.update(input.as_slice());
    blake_2b.update(1u64.to_le_bytes().as_slice());
    let mut type_1_args = [0; 32];
    blake_2b.finalize(&mut type_1_args);

    let secret_key = SecretKey::from_str(PRIVKEY).unwrap();
    let public_key = secret_key.public_key(&Secp256k1::signing_only());
    let address_payload = AddressPayload::from_pubkey(&public_key);
    let addr = Address::new(NetworkType::Dev, address_payload, true);
    let lock_script = Script::from(&addr);

    let empty_lock_type_id_script = Script::new_builder()
        .code_hash(
            h256!("0x00000000000000000000000000000000000000000000000000545950455f4944").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .args(type_1_args.as_slice().pack())
        .build();

    let empty_lock_output = CellOutput::new_builder()
        .type_(
            ScriptOpt::new_builder()
                .set(Some(empty_lock_type_id_script.clone()))
                .build(),
        )
        .lock(lock_script.clone())
        .capacity(20_000_000_000_000u64.pack())
        .build();

    let lightclient_type_id_script = ScriptOpt::new_builder()
        .set(Some(
            Script::new_builder()
                .code_hash(
                    h256!("0x00000000000000000000000000000000000000000000000000545950455f4944")
                        .pack(),
                )
                .hash_type(ScriptHashType::Type.into())
                .args(type_0_args.as_slice().pack())
                .build(),
        ))
        .build();

    let empty_lock_type_id_script_hash = empty_lock_type_id_script.calc_script_hash();
    println!(
        "contract lock args{:?}",
        hex::encode(type_1_args.as_slice())
    );

    let lightclient_output = CellOutput::new_builder()
        .type_(lightclient_type_id_script)
        .lock(
            Script::new_builder()
                .code_hash(empty_lock_type_id_script_hash)
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .capacity(20_000_000_000_000u64.pack())
        .build();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(
            CellDep::new_builder()
                .dep_type(DepType::DepGroup.into())
                .out_point(
                    OutPoint::new_builder()
                        .tx_hash(
                            h256!(
                            "0x29ed5663501cd171513155f8939ad2c9ffeb92aa4879d39cde987f8eb6274407"
                        )
                            .pack(),
                        )
                        .index(0u32.pack())
                        .build(),
                )
                .build(),
        )
        .input(input)
        .output(lightclient_output)
        .output(empty_lock_output)
        .output_data(
            std::fs::read("./eth_light_client-client_type_lock")
                .unwrap()
                .pack(),
        )
        .output_data(std::fs::read("./empty_lock").unwrap().pack())
        .build();

    let signer =
        SecpSighashScriptSigner::new(Box::new(SecpCkbRawKeySigner::new_with_secret_keys(vec![
            secret_key,
        ])));
    let tx = signer
        .sign_tx(
            &tx,
            &ScriptGroup {
                script: lock_script,
                group_type: ScriptGroupType::Lock,
                input_indices: vec![0],
                output_indices: vec![0],
            },
        )
        .unwrap();
    let tx = ckb_jsonrpc_types::TransactionView::from(tx);
    let tx_content = serde_json::to_string(&tx.inner).unwrap();
    std::fs::write("./deploy-contracts.json", tx_content).unwrap();
}
