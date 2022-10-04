extern crate core;

use std::io::{stdin, stdout, Write};
use libaes::Cipher;
use pqc_kyber::{keypair, Ake, PublicKey, AkeSendInit, AkeSendResponse};

/*
 * Main file for QuantumConnect project.
 *
 * Written by Alexander M. Pellegrino
 * Created September 22, 2022
 *
 * Last Update: October 4, 2022
 */

// EARLY PROTOTYPE - NO NETWORK CAPABILITIES

fn main() {

    // Initialize Random Number Generator for Seed
    let mut rng = rand::thread_rng();

    // Create "Alice" and "Bob" as Sample Users - TO BE REPLACED WITH CLIENT INITIALIZATION
    let mut alice = Ake::new();
    let mut bob = Ake::new();

    // Generate private and public keys for Alice and Bob
    let alices_keys = keypair(&mut rng);
    let bobs_keys = keypair(&mut rng);

    // base2048 encode the public keys for easy user sharing
    let alices_shared_key = base2048::encode(alices_keys.public.as_slice());
    let bobs_shared_key = base2048::encode(bobs_keys.public.as_slice());

    // Convert the base2048-encoded keys back to regular ones to test user sharing
    let alices_reconstructed_key = PublicKey::from(rebuild_key(base2048::decode(&alices_shared_key)
        .expect("Invalid key.")));
    let bobs_reconstructed_key = PublicKey::from(rebuild_key(base2048::decode(&bobs_shared_key)
        .expect("Invalid key.")));

    // Alice attempts to initialize a key pair with Bob's rebuilt key from base2048
    // She then base2048 encodes the initialization request to send to Bob
    let client_initialization = base2048::encode(
        alice.client_init(&bobs_reconstructed_key, &mut rng).as_slice()
    );

    // Convert the base2048-encoded initialization back to a regular one to test user sharing
    let reconstructed_initialization = AkeSendInit::from(rebuild_init_response(
        base2048::decode(&client_initialization).expect("Invalid client initialization.")));

    // Bob attempts to access the key pair using Alice's public key and his secret key
    // He then base2048 encodes the result to send back to Alice
    let server_response = base2048::encode(
                            bob.server_receive(reconstructed_initialization,
                                             &alices_reconstructed_key,
                                             &bobs_keys.secret,
                                             &mut rng)
                                             .expect("Authentication error.")
                                             .as_slice()
    );

    // Convert the base2048-encoded response back to a regular one to test user sharing
    let reconstructed_response = AkeSendResponse::from(rebuild_init_response(
        base2048::decode(&server_response).expect("Invalid server response.")));

    // Alice verifies Bob's request with her secret key
    alice.client_confirm(reconstructed_response, &alices_keys.secret)
        .expect("Authentication error.");

    // Display the public keys used in this authentication for debugging purposes
    println!("Alice's Public Key: {}", &alices_shared_key);
    println!("Bob's Public Key: {}", &bobs_shared_key);

    // Display the shared key generated on both ends - should match
    println!("Alice's Shared Key: {}", base2048::encode(alice.shared_secret.as_slice()));
    println!("Bob's Shared Key: {}", base2048::encode(bob.shared_secret.as_slice()));

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
            println!("Bob's Message to Send:");
            stdout().flush().unwrap();
        }

        else {
            println!("Alice's Message to Send:");
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
            println!("Alice's Decrypted Message:\n{}", std::str::from_utf8(&decrypted).unwrap());
            stdout().flush().unwrap();
            bobs_turn = false;
        }

        else {
            // Alice encrypts the message with her public key and the shared key
            let encrypted = alices_signer.cbc_encrypt(
                &alices_reconstructed_key, message.as_bytes()
            );
            println!("Alice's Encrypted Message: {:?}", &encrypted);

            // Bob decrypts the message with Alice's reconstructed public key and the shared key
            let decrypted = bobs_signer.cbc_decrypt(&alices_reconstructed_key, &encrypted);
            println!("Bob's Decrypted Message:\n{}", std::str::from_utf8(&decrypted).unwrap());
            stdout().flush().unwrap();
            bobs_turn = true;
        };

    }

}

/*
 * Rebuilds a public key byte array from a parsed Vector
 * A proper public key MUST contain 1568 bytes
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
 * Rebuilds a client initialization request or server response byte array from a parsed Vector
 * A proper client initialization MUST contain 3136 bytes
 */
fn rebuild_init_response<T>(v: Vec<T>) -> [T; 3136] where T: Copy {
    let slice = v.as_slice();
    let array: [T; 3136] = match slice.try_into() {
        Ok(n) => n,
        Err(_) => panic!("Invalid client initialization.")
    };
    return array;
}
