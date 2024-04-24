// Import required crates and modules, including big number handling and standard input for console interaction.
use num_bigint::BigUint;
use std::io::stdin;

// Include the generated gRPC client and request/response types.
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};
use ::zkp_auth::Protocol; // Import the ZKP Protocol logic.

// The entry point for the asynchronous client application.
#[tokio::main]
async fn main() {
    let mut buf = String::new(); // Buffer to hold user input.
    let (alpha, beta, p, q) = Protocol::get_constants(); // Retrieve ZKP constants.
    
    // Initialize a ZKP Protocol instance with the retrieved constants.
    let zkp = Protocol {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    // Establish a connection to the authentication server.
    let mut client = AuthClient::connect("http://host.docker.internal:50051")
        .await
        .expect("could not connect to the server");
    println!("Connected to the server");
    
    // Prompt and read username
    println!("Please provide the username:");
    let mut username = String::new();
    stdin()
        .read_line(&mut username)
        .expect("Could not get the username from stdin");
    if username.trim().is_empty() {
        println!("Username cannot be empty.");
        return; // or handle it as needed
    }
    let username = username.trim().to_string();
    buf.clear(); // Clear the buffer for the next input.

    // Prompt the user for a password and read it from the console.
    println!("Please provide the password:");
    let mut password_str = String::new();
    stdin()
        .read_line(&mut password_str)
        .expect("Could not get the password from stdin");
    if password_str.trim().is_empty() {
        println!("Password cannot be empty.");
        return; // or handle it as needed
    }
    let password = BigUint::from_bytes_be(password_str.trim().as_bytes());
    buf.clear();

    // Compute Y1 and Y2 parameters based on the provided password and prepare a registration request.
    let (y1, y2) = zkp.compute_params(&password);
    let request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    // Send the registration request to the server.
    let _response = client
        .register(request)
        .await
        .expect("Could not register in server");

    println!("Registration was successful");

    // Prompt the user for the password again for login purposes.
    println!("Please provide the password (to login):");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    // Generate a random number below `q` and compute R1 and R2 parameters for the authentication challenge.
    let k = Protocol::generate_random_number_below(&q);
    let (r1, r2) = zkp.compute_params(&k);

    // Prepare and send the authentication challenge request to the server.
    let request = AuthenticationChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let response = client
        .create_authentication_challenge(request)
        .await
        .expect("Could not request challenge to server")
        .into_inner();

    // Extract the authentication ID and challenge `c` from the server's response.
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    // Solve the challenge using the provided password and send the solution to the server.
    let s = zkp.solve_challenge(&k, &c, &password);
    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    // Verify the authentication with the server and log the result.
    let response = client
        .verify_authentication(request)
        .await
        .expect("Could not verify authentication in server")
        .into_inner();
    println!("Logging successful! session_id: {}", response.session_id);
}
