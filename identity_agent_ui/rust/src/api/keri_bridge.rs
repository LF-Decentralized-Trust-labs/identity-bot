use flutter_rust_bridge::frb;
use keri_core::actor::prelude::*;
use keri_core::event::sections::key_config::nxt_commitment;
use keri_core::keys::PublicKey;
use keri_core::prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use keri_core::signer::CryptoBox;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

static INSTANCES: Mutex<Option<HashMap<String, KeriInstance>>> = Mutex::new(None);

struct KeriInstance {
    prefix: IdentifierPrefix,
    crypto_box: CryptoBox,
    kel: Vec<String>,
}

fn get_or_init_instances() -> std::sync::MutexGuard<'static, Option<HashMap<String, KeriInstance>>> {
    let mut guard = INSTANCES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

#[derive(Serialize, Deserialize)]
pub struct InceptionResult {
    pub aid: String,
    pub public_key: String,
    pub kel: String,
}

#[derive(Serialize, Deserialize)]
pub struct RotationResult {
    pub aid: String,
    pub new_public_key: String,
    pub kel: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub public_key: String,
}

#[frb(sync)]
pub fn incept_aid(name: String, code: String) -> Result<InceptionResult, String> {
    let crypto_box = CryptoBox::new().map_err(|e| format!("Key generation failed: {}", e))?;

    let current_pk = crypto_box.public_key();
    let next_pk = crypto_box.next_pub_key();

    let nxt = nxt_commitment(
        1,
        &[BasicPrefix::Ed25519(PublicKey::new(next_pk.to_vec()))],
        &cesrox::primitives::codes::self_addressing::SelfAddressing::Blake3_256,
    );

    let icp_event = keri_core::event::event_data::inception::InceptionEvent::new(
        keri_core::event::sections::key_config::KeyConfig::new(
            vec![BasicPrefix::Ed25519(PublicKey::new(current_pk.to_vec()))],
            nxt,
            Some(1),
        ),
        None,
        None,
    );

    let prefix = icp_event.event.get_prefix();
    let aid = prefix.to_string();
    let kel_entry = serde_json::to_string(&icp_event)
        .map_err(|e| format!("KEL serialization failed: {}", e))?;

    let mut instances = get_or_init_instances();
    let map = instances.as_mut().unwrap();
    map.insert(
        name.clone(),
        KeriInstance {
            prefix,
            crypto_box,
            kel: vec![kel_entry.clone()],
        },
    );

    Ok(InceptionResult {
        aid,
        public_key: base64::encode(current_pk),
        kel: kel_entry,
    })
}

#[frb(sync)]
pub fn rotate_aid(name: String) -> Result<RotationResult, String> {
    let mut instances = get_or_init_instances();
    let map = instances.as_mut().unwrap();

    let instance = map
        .get_mut(&name)
        .ok_or_else(|| format!("No AID found with name: {}", name))?;

    let new_crypto_box =
        CryptoBox::new().map_err(|e| format!("Key generation failed: {}", e))?;
    let new_pk = new_crypto_box.public_key();

    let rot_event = serde_json::json!({
        "type": "rot",
        "aid": instance.prefix.to_string(),
        "new_public_key": base64::encode(&new_pk),
        "sn": instance.kel.len(),
    });

    let kel_entry =
        serde_json::to_string(&rot_event).map_err(|e| format!("KEL serialization failed: {}", e))?;
    instance.kel.push(kel_entry.clone());
    instance.crypto_box = new_crypto_box;

    let aid = instance.prefix.to_string();

    Ok(RotationResult {
        aid,
        new_public_key: base64::encode(new_pk),
        kel: kel_entry,
    })
}

#[frb(sync)]
pub fn sign_payload(name: String, data: Vec<u8>) -> Result<SignResult, String> {
    let instances = get_or_init_instances();
    let map = instances.as_ref().unwrap();

    let instance = map
        .get(&name)
        .ok_or_else(|| format!("No AID found with name: {}", name))?;

    let signature = instance
        .crypto_box
        .sign(&data)
        .map_err(|e| format!("Signing failed: {}", e))?;

    let pk = instance.crypto_box.public_key();

    Ok(SignResult {
        signature: base64::encode(signature.as_ref()),
        public_key: base64::encode(pk),
    })
}

#[frb(sync)]
pub fn get_current_kel(name: String) -> Result<String, String> {
    let instances = get_or_init_instances();
    let map = instances.as_ref().unwrap();

    let instance = map
        .get(&name)
        .ok_or_else(|| format!("No AID found with name: {}", name))?;

    let kel_json = serde_json::to_string_pretty(&instance.kel)
        .map_err(|e| format!("KEL serialization failed: {}", e))?;

    Ok(kel_json)
}

#[frb(sync)]
pub fn verify_signature(data: Vec<u8>, signature: String, public_key: String) -> Result<bool, String> {
    let sig_bytes = base64::decode(&signature)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;
    let pk_bytes = base64::decode(&public_key)
        .map_err(|e| format!("Invalid public key encoding: {}", e))?;

    let pk = PublicKey::new(pk_bytes);
    let bp = BasicPrefix::Ed25519(pk);
    let ssp = SelfSigningPrefix::Ed25519Sha512(sig_bytes);

    let valid = bp.verify(&data, &ssp)
        .map_err(|e| format!("Verification failed: {}", e))?;

    Ok(valid)
}
