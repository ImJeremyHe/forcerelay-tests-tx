use std::str::FromStr;

use ckb_hash::new_blake2b;
use ckb_sdk::constants::TYPE_ID_CODE_HASH;
use ckb_sdk::unlock::{ScriptSigner, SecpSighashScriptSigner};
use ckb_sdk::{traits::SecpCkbRawKeySigner, Address, AddressPayload, NetworkType};
use ckb_sdk::{ScriptGroup, ScriptGroupType};
use ckb_types::core::{DepType, TransactionView};
use ckb_types::packed::{Byte32, CellDep, Uint32};
use ckb_types::{
    core::ScriptHashType,
    h256,
    packed::{CellInput, CellOutput, OutPoint, Script, ScriptOpt},
    prelude::*,
};
use eth_light_client_in_ckb_verification::types::packed::{Client, Hash, HeaderDigest, Uint64};

use secp256k1::{Secp256k1, SecretKey};

const PRIVKEY: &str = "63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d";

#[test]
fn build_verifier_tx() {
    let (tx1, client_type_script_hash, _verifiy_type_script_hash, _business_type_script_hash) =
        generate_tx_to_deploy_client_and_verify_bin_and_business();
    println!("tx1 hash: {:?}", tx1.hash());

    let tx2 = generate_tx_to_deploy_mmr_root_cell(tx1.hash(), client_type_script_hash.clone());
    print!("tx2 hash: {:?}", tx2.hash());

    let tx1 = ckb_jsonrpc_types::TransactionView::from(tx1);
    let tx2 = ckb_jsonrpc_types::TransactionView::from(tx2);

    let tx1_content = serde_json::to_string(&tx1.inner).unwrap();
    let rpc_content1 = format!(
        "{{\"id\": 3, \"jsonrpc\": \"2.0\", \"method\": \"send_transaction\", \"params\": [{}]}}",
        tx1_content
    );

    let tx2_content = serde_json::to_string(&tx2.inner).unwrap();
    let rpc_content2 = format!(
        "{{\"id\": 3, \"jsonrpc\": \"2.0\", \"method\": \"send_transaction\", \"params\": [{}]}}",
        tx2_content
    );

    std::fs::write("./deploy-verify-lightclient.json", rpc_content1).unwrap();
    std::fs::write("./deploy-mmr-root.json", rpc_content2).unwrap();
}

fn generate_tx_to_deploy_client_and_verify_bin_and_business(
) -> (TransactionView, Byte32, Byte32, Byte32) {
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

    let secret_key = SecretKey::from_str(PRIVKEY).unwrap();
    let lock_script = {
        let public_key = secret_key.public_key(&Secp256k1::signing_only());
        let address_payload = AddressPayload::from_pubkey(&public_key);
        let addr = Address::new(NetworkType::Dev, address_payload, true);
        Script::from(&addr)
    };

    let (client_output, client_type_script_hash) = {
        let mut blake = new_blake2b();
        blake.update(input.as_slice());
        blake.update(0u64.to_le_bytes().as_slice());
        let mut type_id_args = [0; 32];
        blake.finalize(&mut type_id_args);

        println!("contract type args:{:?}", hex::encode(&type_id_args));

        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.0.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(type_id_args.as_slice().pack())
            .build();

        let type_script_hash = type_script.calc_script_hash();

        let output = CellOutput::new_builder()
            .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
            // The lock in the light client cell should be made by relayer's private key.
            // But we don't need it in this integration test.
            .lock(lock_script.clone())
            .capacity(20_000_000_000_000_u64.pack())
            .build();
        (output, type_script_hash)
    };

    let (verify_bin_output, verify_type_script_hash) = {
        let mut blake = new_blake2b();
        blake.update(input.as_slice());
        blake.update(1u64.to_le_bytes().as_slice());
        let mut type_id_args = [0; 32];
        blake.finalize(&mut type_id_args);

        println!("verifiy bin type args:{:?}", hex::encode(&type_id_args));
        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.0.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(type_id_args.as_slice().pack())
            .build();

        let script_hash = type_script.calc_script_hash();
        println!("verify type script hash: {:?}", script_hash);

        let output = CellOutput::new_builder()
            .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
            .lock(lock_script.clone())
            .capacity(20_000_000_000_000_u64.pack())
            .build();
        (output, script_hash)
    };

    let balance = {
        CellOutput::new_builder()
            .lock(lock_script.clone())
            .type_(ScriptOpt::new_builder().set(None).build())
            .capacity(409873_000_000_000_000_u64.pack())
            .build()
    };

    let (business_output, business_type_script_hash) = {
        let mut blake = new_blake2b();
        blake.update(input.as_slice());
        blake.update(3u64.to_le_bytes().as_slice());
        let mut type_id_args = [0; 32];
        blake.finalize(&mut type_id_args);

        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.0.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(type_id_args.as_slice().pack())
            .build();

        let script_hash = type_script.calc_script_hash();

        let output = CellOutput::new_builder()
            .lock(lock_script.clone())
            .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
            .capacity(20_000_000_000_000_u64.pack())
            .build();
        (output, script_hash)
    };

    let client_data = {
        // we use an always success lock here to avoid verification of the mmr root cell.
        std::fs::read("./empty_lock").unwrap().pack()
    };

    let verify_bin_data = {
        std::fs::read("./eth_light_client-verify_bin")
            .unwrap()
            .pack()
    };

    let empty_data = "0x".as_bytes().to_vec().pack();

    let business_contract_data = std::fs::read("./eth_light_client-mock_business_type_lock")
        .unwrap()
        .pack();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(
            CellDep::new_builder()
                .dep_type(DepType::DepGroup.into())
                .out_point(
                    OutPoint::new_builder()
                        .tx_hash(h256!("0x29ed5663501cd171513155f8939ad2c9ffeb92aa4879d39cde987f8eb6274407").pack())
                        .build()
                )
                .build(),
        )
        .input(input)
        .output(client_output)
        .output(verify_bin_output)
        .output(balance)
        .output(business_output)
        .output_data(client_data)
        .output_data(verify_bin_data)
        .output_data(empty_data)
        .output_data(business_contract_data)
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
                output_indices: vec![], // why should i assign the output in signing inputs?
            },
        )
        .unwrap();

    println!("client type script hash:{:?}", client_type_script_hash);
    println!("business type script hash:{:?}", business_type_script_hash);
    (
        tx,
        client_type_script_hash,
        verify_type_script_hash,
        business_type_script_hash,
    )
}

fn generate_tx_to_deploy_mmr_root_cell(
    previous_tx_hash: Byte32,
    client_type_script_hash: Byte32,
) -> TransactionView {
    let input = {
        CellInput::new_builder()
            .previous_output(
                OutPoint::new_builder()
                    .tx_hash(previous_tx_hash.clone())
                    .index(u32_to_uint32(2))
                    .build(),
            )
            .build()
    };
    let secp256k1_dep = CellDep::new_builder()
        .dep_type(DepType::DepGroup.into())
        .out_point(
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x29ed5663501cd171513155f8939ad2c9ffeb92aa4879d39cde987f8eb6274407")
                        .pack(),
                )
                .build(),
        )
        .build();

    let lightclient_dep = CellDep::new_builder()
        .dep_type(DepType::Code.into())
        .out_point(
            OutPoint::new_builder()
                .tx_hash(previous_tx_hash)
                .index(u32_to_uint32(0))
                .build(),
        )
        .build();

    let secret_key = SecretKey::from_str(PRIVKEY).unwrap();
    let lock_script = {
        let public_key = secret_key.public_key(&Secp256k1::signing_only());
        let address_payload = AddressPayload::from_pubkey(&public_key);
        let addr = Address::new(NetworkType::Dev, address_payload, true);
        Script::from(&addr)
    };

    let type_script = Script::new_builder()
        .code_hash(client_type_script_hash)
        .args("ibc-ckb-1".as_bytes().to_vec().pack())
        .hash_type(ScriptHashType::Type.into())
        .build();
    let mmr_root_output = {
        println!(
            "mmr root type script hash:{:?}",
            type_script.calc_script_hash()
        );
        println!("mmr root cell type script:{:?}", type_script);
        CellOutput::new_builder()
            .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
            .lock(lock_script.clone())
            .capacity(20_000_000_000_000_u64.pack())
            .build()
    };

    let balance = CellOutput::new_builder()
        .lock(lock_script.clone())
        .capacity(319873_000_000_000_000_u64.pack())
        .build();

    let mmr_root_data = {
        let min_slot = u64_to_uint64(5787808);
        let max_slot = u64_to_uint64(5787839);
        let tip_valid_header_root: Hash = Hash::from_slice(
            h256!("0xd5d43d373474c15856b155877994e551e40477c0a57d0b5abbdcf94904881623")
                .pack()
                .as_slice(),
        )
        .unwrap();
        let mmr_root = HeaderDigest::from_slice(
            h256!("0x1503a6ebfb7a3a117b1e176742f173665fd169e930a0d85f9da153918b98c34b")
                .pack()
                .as_slice(),
        )
        .unwrap();
        Client::new_builder()
            .minimal_slot(min_slot)
            .maximal_slot(max_slot)
            .tip_valid_header_root(tip_valid_header_root)
            .headers_mmr_root(mmr_root)
            .build()
            .as_bytes()
            .pack()
    };

    let empty_data = "0x".as_bytes().to_vec().pack();

    let signer =
        SecpSighashScriptSigner::new(Box::new(SecpCkbRawKeySigner::new_with_secret_keys(vec![
            secret_key,
        ])));

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(secp256k1_dep)
        .cell_dep(lightclient_dep)
        .input(input)
        .output(mmr_root_output)
        .output(balance)
        .output_data(mmr_root_data)
        .output_data(empty_data)
        .build();

    let tx = signer
        .sign_tx(
            &tx,
            &ScriptGroup {
                script: lock_script,
                group_type: ScriptGroupType::Lock,
                input_indices: vec![0],
                output_indices: vec![], // why should i assign the output in signing inputs?
            },
        )
        .unwrap();
    tx
}

fn u64_to_uint64(n: u64) -> Uint64 {
    let bytes: [u8; 8] = n.to_le_bytes();
    Uint64::from_slice(&bytes).unwrap()
}

fn u32_to_uint32(n: u32) -> Uint32 {
    let bytes: [u8; 4] = n.to_le_bytes();
    Uint32::from_slice(&bytes).unwrap()
}
