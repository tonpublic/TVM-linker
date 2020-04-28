/*
 * Copyright 2018-2019 TON DEV SOLUTIONS LTD.
 *
 * Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at: https://ton.dev/licenses
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific TON DEV software governing permissions and
 * limitations under the License.
 */
use crate::config::Config;
use crate::crypto::generate_keypair_from_mnemonic;
use crate::helpers::read_keys;
use ton_client_rs::{
    TonClient, TonClientConfig, TonAddress, Ed25519KeyPair, EncodedMessage
};
use hex;
use std::fs::File;
use std::io::Write;

fn load_keypair(keys: Option<String>) -> Result<Option<Ed25519KeyPair>, String> {
    match keys {
        Some(keys) => {
            let words: Vec<&str> = keys.split(' ').collect();
            if words.len() == 0 {
                let keys = read_keys(&keys)?;
                Ok(Some(keys))
            } else {
                let pair = generate_keypair_from_mnemonic(&keys)?;

                let mut buffer = [0u8; 64];
                let public_vec = hex::decode(&pair.public)
                    .map_err(|e| format!("failed to decode public key: {}", e))?;
                let private_vec = hex::decode(&pair.secret)
                    .map_err(|e| format!("failed to decode private key: {}", e))?;
                
                buffer[..32].copy_from_slice(&private_vec);
                buffer[32..].copy_from_slice(&public_vec);

                let ed25519pair = Ed25519KeyPair::zero();
                Ok(Some(ed25519pair.from_bytes(buffer)))
            }
        },
        None => Ok(None),
    }
}

fn create_client(url: String) -> Result<TonClient, String> {
    TonClient::new(&TonClientConfig{
        base_url: Some(url),
        message_retries_count: Some(0),
        message_expiration_timeout: Some(20000),
        message_expiration_timeout_grow_factor: Some(1.5),
        message_processing_timeout: Some(20000),
        message_processing_timeout_grow_factor: Some(1.5),
        wait_for_timeout: None,
        access_key: None,
    })
    .map_err(|e| format!("failed to create tonclient: {}", e.to_string()))
}

pub fn prepare_message(
    ton: &TonClient,
    addr: &TonAddress,
    abi: &str,
    method: &str,
    params: &str,
    header: Option<String>,
    keys: Option<String>,
) -> Result<EncodedMessage, String> {    
    
    let keys = load_keypair(keys)?;

    ton.contracts.create_run_message(
        addr,
        abi,
        method,
        None,
        params.into(),
        keys.as_ref(),
        None,
    )
    .map_err(|e| format!("failed to create inbound message: {}", e))
}

fn print_encoded_message(msg: &EncodedMessage) {
    println!("MessageId: {}", msg.message_id);
    if msg.expire.is_some() {
        println!("Will expire at: {}", msg.expire.unwrap());
    }
}

fn msg_to_json(msg: &EncodedMessage, method: &str) -> String {
    let json_msg = json!({
        "msg": {
            "message_id": msg.message_id,
            "message_body": base64::encode(&msg.message_body),
            "expire": msg.expire
        },
        "method": method,
    });

    serde_json::to_string(&json_msg).unwrap()
}

fn msg_from_json(str_msg: &str) -> Result<(EncodedMessage, String), String> {
    let json_msg: serde_json::Value = serde_json::from_str(str_msg)
        .map_err(|e| format!("couldn't decode message: {}", e))?;
    let method = json_msg["method"].as_str()
        .ok_or(r#"couldn't find "method" key in message"#)?
        .to_owned();
    let message_id = json_msg["msg"]["message_id"].as_str()
        .ok_or(r#"couldn't find "message_id" key in message"#)?
        .to_owned();
    let body = json_msg["msg"]["message_body"].as_str()
        .ok_or(r#"couldn't find "message_body" key in message"#)?
        .to_owned();
    let message_body = base64::decode(&body).unwrap();
    let expire = json_msg["msg"]["expire"].as_u64().map(|x| x as u32);
    let msg = EncodedMessage {
        message_id, message_body, expire
    };
    Ok((msg, method))
}

pub fn call_contract(
    conf: Config,
    addr: &str,
    abi: String,
    method: &str,
    params: &str,
    keys: Option<String>,
    local: bool,
) -> Result<(), String> {
    let ton = create_client(conf.url.clone())?;

    let ton_addr = TonAddress::from_str(addr)
        .map_err(|e| format!("failed to parse address: {}", e.to_string()))?;

    let result = if local {
        println!("Running get-method...");
        ton.contracts.run_local(
            &ton_addr,
            None,
            &abi,
            method,
            None,
            params.into(),
            None
        )
        .map_err(|e| format!("run failed: {}", e.to_string()))?
    } else {
        println!("Generating external inbound message...");
        let msg = prepare_message(
            &ton,
            &ton_addr,
            &abi,
            method,
            params,
            None,
            keys,
        )?;

        print_encoded_message(&msg);
        println!("Processing message...");

        ton.contracts.process_message(msg, Some(&abi), Some(method), None)
            .map_err(|e| format!("transaction failed: {}", e.to_string()))?
            .output
    };

    println!("Succeded.");
    if !result.is_null() {
        println!("Result: {}", serde_json::to_string_pretty(&result).unwrap());
    }
    Ok(())
}


pub fn generate_message(
    conf: Config,
    addr: &str,
    abi: String,
    method: &str,
    params: &str,
    keys: Option<String>,
    msg_path: &str,
    lifetime: u32,
) -> Result<(), String> {
    let ton = create_client(conf.url.clone())?;

    let ton_addr = TonAddress::from_str(addr)
        .map_err(|e| format!("failed to parse address: {}", e.to_string()))?;

    let header = json!({
        "expire": lifetime
    });

    let msg = prepare_message(
        &ton,
        &ton_addr,
        &abi,
        method,
        params,
        Some(serde_json::to_string(&header).unwrap()),
        keys,
    )?;
    print_encoded_message(&msg);

    let str_msg = msg_to_json(&msg, method);

    let mut file = File::create(msg_path)
        .map_err(|e| format!("failed to create file for msg: {}", e))?;
    file.write_all(str_msg.as_bytes())
        .map_err(|e| format!("failed to write message to file: {}", e))?;
        Ok(())
}

pub fn call_contract_with_msg(conf: Config, str_msg: String, abi: String) -> Result<(), String> {
    let ton = create_client(conf.url.clone())?;
    //let json_msg = std::fs::read_to_string(str_msg)
    //    .map_err(|e| format!("failed to read from file: {}", e))?;

    let (msg, method) = msg_from_json(&str_msg)?;
    print_encoded_message(&msg);

    let params = ton.contracts.decode_input_message_body(
        &abi,
        &msg.message_body[..]
    ).unwrap();

    println!("Calling method {} with parameters:", params.function);
    println!("{}", params.output);
    println!("Processing message...");
    let result = ton.contracts.process_message(
        msg,
        Some(&abi),
        Some(&method),
        None
    )
    .map_err(|e| format!("Failed: {}", e.to_string()));

    match result {
        Ok(val) => {
            println!("Succeded.");
            if !val.output.is_null() {
                println!("Result: {}", serde_json::to_string_pretty(&val.output).unwrap());
            }
        },
        Err(estr) => { println!("Error: {}", estr); }
    };
    
    Ok(())
}