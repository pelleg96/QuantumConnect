use std::io::{stdin, stdout, Write};
use libaes::Cipher;
use pqc_kyber::{keypair, Ake, PublicKey, AkeSendInit, AkeSendResponse};

fn main() {

    // Initialize Random Number Generator for Seed
    let mut rng = rand::thread_rng();

    // Create "Alice" and "Bob" as Sample Users
    let mut alice = Ake::new();
    let mut bob = Ake::new();

    // Generate private and public keys for Alice and Bob
    let alices_keys = keypair(&mut rng);
    let bobs_keys = keypair(&mut rng);

    // Hex encode the public keys for easy user sharing
    let alices_shared_key = hex::encode(alices_keys.public);
    let bobs_shared_key = hex::encode(bobs_keys.public);

    // Convert the hex-encoded keys back to regular ones to test user sharing
    let alices_reconstructed_key = PublicKey::from(rebuild_key(hex::decode(&alices_shared_key)
        .expect("Invalid key.")));
    let bobs_reconstructed_key = PublicKey::from(rebuild_key(hex::decode(&bobs_shared_key)
        .expect("Invalid key.")));

    // Alice attempts to initialize a key pair with Bob's rebuilt key from hex
    // She then hex encodes the initialization request to send to Bob
    let client_initialization = hex::encode(alice.client_init(&bobs_reconstructed_key, &mut rng)
        .to_vec());

    // Convert the hex-encoded initialization back to a regular one to test user sharing
    let reconstructed_initialization = AkeSendInit::from(rebuild_client_init(
        hex::decode(&client_initialization).expect("Invalid client initialization.")));

    // Bob attempts to access the key pair using Alice's public key and his secret key
    // He then hex encodes the result to send back to Alice
    let server_response = hex::encode(
                            bob.server_receive(reconstructed_initialization,
                                             &alices_reconstructed_key,
                                             &bobs_keys.secret,
                                             &mut rng)
                                             .expect("Authentication error.")
                                             .to_vec()
    );

    let reconstructed_response = AkeSendResponse::from(rebuild_client_init(
        hex::decode(&server_response).expect("Invalid server response.")));

    // Alice verifies Bob's request with her secret key
    alice.client_confirm(reconstructed_response, &alices_keys.secret).expect("Authentication error.");

    // Display the public keys used in this authentication for debugging purposes
    println!("Alice's Public Key: {}", &alices_shared_key);
    println!("Bob's Public Key: {}", &bobs_shared_key);

    // Display the shared key generated on both ends - should match
    println!("Alice's Shared Key: {}", hex::encode(alice.shared_secret));
    println!("Bob's Shared Key: {}", hex::encode(bob.shared_secret));

    //###########################\\
    // Simulating A Conversation \\
    //###########################\\

    // Initialize AES-256 using the shared key on Alice's end
    let alices_signer = Cipher::new_256(&alice.shared_secret);
    let bobs_signer = Cipher::new_256(&bob.shared_secret);

    let mut message = String::new();
    let mut bobs_turn = false;

    loop {
        // Clear previous message string
        message.clear();

        if bobs_turn {
            println!("Bob's Message:");
            stdout().flush().unwrap();
        }

        else {
            println!("Alice's Message:");
            stdout().flush().unwrap();
        }

        // Read a message
        stdin().read_line(&mut message).expect("Error parsing message.");

        if message.trim() == ">exit" {
            break;
        }

        // Transmit the message
        if bobs_turn {
            // Bob encrypts the message with his public key and the shared key
            let encrypted = bobs_signer.cbc_encrypt(&bobs_keys.public, message.as_bytes());
            println!("Bob's Encrypted Message: {:?}", &encrypted);

            // Alice decrypts the message with Bob's reconstructed public key and the shared key
            let decrypted = alices_signer.cbc_decrypt(&bobs_reconstructed_key, &encrypted);
            println!("Alice's Decrypted Message: {}", std::str::from_utf8(&decrypted).unwrap());
            stdout().flush().unwrap();
            bobs_turn = false;
        }

        else {
            // Alice encrypts the message with her public key and the shared key
            let encrypted = alices_signer.cbc_encrypt(&alices_reconstructed_key, message.as_bytes());
            println!("Alice's Encrypted Message: {:?}", &encrypted);

            // Bob decrypts the message with Alice's reconstructed public key and the shared key
            let decrypted = bobs_signer.cbc_decrypt(&alices_reconstructed_key, &encrypted);
            println!("Bob's Decrypted Message: {}", std::str::from_utf8(&decrypted).unwrap());
            stdout().flush().unwrap();
            bobs_turn = true;
        };

    }

}

/*
 * Rebuilds a public key from a hex string
 * A hex-encoded public key MUST contain 1568 bytes
 */
fn rebuild_key<T>(v: Vec<T>) -> [T; 1568] where T: Copy {
    let slice = v.as_slice();
    let array: [T; 1568] = match slice.try_into() {
        Ok(n) => n,
        Err(_) => panic!("Invalid key."),
    };
    return array;
}

/*
 * Rebuilds a client initialization request from a hex string
 * A hex-encoded client initialization MUST contain 3136 bytes
 */
fn rebuild_client_init<T>(v: Vec<T>) -> [T; 3136] where T: Copy {
    let slice = v.as_slice();
    let array: [T; 3136] = match slice.try_into() {
        Ok(n) => n,
        Err(_) => panic!("Invalid client initialization.")
    };
    return array;
}
