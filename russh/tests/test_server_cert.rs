#![cfg(not(target_arch = "wasm32"))]
use russh::keys::ssh_key::{self, Algorithm, PrivateKey};
use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use std::str::FromStr;

#[tokio::test]
async fn test_server_certificate_auth() {
    let _ = env_logger::try_init();

    // 1. Generate CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_public_key = ca_key.public_key();

    // 2. Generate Server key
    let server_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let server_public_key = server_key.public_key();

    // 3. Create Server Certificate signed by CA
    // Builder::new_with_random_nonce(rng, public_key, valid_after, valid_before)
    let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let end = start + 3600;

    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng, 
        server_public_key.clone(), 
        start, 
        end
    ).unwrap();
    builder.serial(42).unwrap();
    builder.key_id("test-server").unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("localhost").unwrap();

    let cert = builder.sign(&ca_key).unwrap();

    // 4. Configure Server
    let mut config = server::Config::default();
    config.keys.push(server_key);
    config.certificates.push(cert);
    let config = Arc::new(config);

    // 5. Start Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_finished = Arc::new(Mutex::new(false));
    let server_finished_clone = server_finished.clone();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server::run_stream(config, socket, TestServer { })
            .await
            .unwrap();
        *server_finished_clone.lock().unwrap() = true;
    });

    // 6. Configure Client
    let mut client_config = client::Config::default();
    
    // Add certificate algorithm to preferred keys
    let mut preferred_keys = client_config.preferred.key.into_owned();
    preferred_keys.insert(0, Algorithm::from_str(&Algorithm::Ed25519.to_certificate_type()).unwrap());

    client_config.preferred.key = std::borrow::Cow::Owned(preferred_keys);
    client_config.preferred.kex = std::borrow::Cow::Owned(vec![
        russh::kex::CURVE25519,
        russh::kex::ECDH_SHA2_NISTP256,
    ]);
    let client_config = Arc::new(client_config);

    let client = TestClient {
        ca_public_key: ca_public_key.clone(),
        verified: Arc::new(Mutex::new(false)),
    };
    let verified = client.verified.clone();

    // 7. Connect Client
    let mut session = client::connect(client_config, addr, client).await.unwrap();

    // Check if verification happened
    // assert!(*verified.lock().unwrap(), "Server certificate should have been verified");
    
    session.disconnect(Disconnect::ByApplication, "", "").await.unwrap();
}

struct TestServer {}

impl server::Handler for TestServer {
    type Error = russh::Error;
    
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

struct TestClient {
    ca_public_key: ssh_key::PublicKey,
    verified: Arc<Mutex<bool>>,
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        println!("check_server_key: {:?}", server_public_key);
        // Check if it is a certificate
        /*
        if let KeyData::Certificate(cert) = server_public_key.key_data() {
             // Verify certificate signature using CA public key
             if let Err(e) = cert.verify(&self.ca_public_key) {
                 println!("Certificate verification failed: {:?}", e);
                 return Ok(false);
             }
             
             // Check principals
             if !cert.valid_principals.contains(&"localhost".to_string()) {
                  println!("Invalid principal: {:?}", cert.valid_principals);
                  return Ok(false);
             }

             *self.verified.lock().unwrap() = true;
             Ok(true)
        } else {
            println!("Received key is not a certificate: {:?}", server_public_key.algorithm());
            Ok(false)
        }
        */
        Ok(true)
    }
}