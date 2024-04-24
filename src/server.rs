// Standard library imports for collections and thread-safe wrappers.
use std::{collections::HashMap, sync::Mutex};

// External crate imports for big integer arithmetic and tonic for gRPC services.
use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

// Importing the Protocol trait from the zkp_auth crate.
use ::zkp_auth::Protocol;

// Including the auto-generated code from the zkp_auth.proto file.
pub mod protocol_auth {
    include!("./zkp_auth.rs");
}

// Using the services and message types defined in the auto-generated module.
use protocol_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

// Definition of the AuthImpl struct, which holds user information and mappings between authentication IDs and usernames.
#[derive(Debug, Default)]
pub struct AuthImpl {
    // A thread-safe map of usernames to UserInfo structs.
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    // A thread-safe map of authentication IDs to usernames.
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

// Definition of the UserInfo struct, which stores information related to a user's registration, authorization, and verification.
#[derive(Debug, Default)]
pub struct UserInfo {
    // User's name.
    pub user_name: String,
    // Public keys y1 and y2, used in the registration phase.
    pub y1: BigUint,
    pub y2: BigUint,
    // Random numbers r1 and r2, used in the authorization phase.
    pub r1: BigUint,
    pub r2: BigUint,
    // Challenge c and response s, used in the verification phase.
    pub c: BigUint,
    pub s: BigUint,
    // A unique session identifier.
    pub session_id: String,
}

// Implementing the Auth service trait for AuthImpl, enabling it to respond to gRPC requests.
#[tonic::async_trait]
impl Auth for AuthImpl {
    // Handles user registration requests.
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();

        let user_name = request.user;
          // Ensure username is not empty
        if user_name.trim().is_empty() {
            return Err(Status::new(Code::InvalidArgument, "Username cannot be empty"));
        }

        // Ensure y1 and y2 (public keys) are not empty
        if request.y1.is_empty() || request.y2.is_empty() {
            return Err(Status::new(Code::InvalidArgument, "Public keys cannot be empty"));
        }
        println!("Processing Registration username: {:?}", user_name);

        // Creating a new UserInfo instance with the provided user name and public keys.
        let user_info = UserInfo {
            user_name: user_name.clone(),
            y1: BigUint::from_bytes_be(&request.y1),
            y2: BigUint::from_bytes_be(&request.y2),
            ..Default::default()
        };

        // Inserting the new user info into the user_info map.
        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        user_info_hashmap.insert(user_name.clone(), user_info);

        println!("Successful Registration username: {:?}", user_name);
        // Returning an empty response on successful registration.
        Ok(Response::new(RegisterResponse {}))
    }

    // Handles requests to create an authentication challenge for a user.
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();

        let user_name = request.user;
        // Ensure username is not empty
        if user_name.trim().is_empty() {
            return Err(Status::new(Code::InvalidArgument, "Username cannot be empty"));
        }

        // Ensure r1 and r2 (random numbers for challenge) are not empty
        if request.r1.is_empty() || request.r2.is_empty() {
            return Err(Status::new(Code::InvalidArgument, "Random numbers for challenge cannot be empty"));
        }
        println!("Processing Challenge Request username: {:?}", user_name);

        let user_info_hashmap = &mut self.user_info.lock().unwrap();

        // Checking if the user exists and creating a challenge if they do.
        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            // Generating a random challenge and authentication ID.
            let (_, _, _, q) = Protocol::get_constants();
            let c = Protocol::generate_random_number_below(&q);
            let auth_id = Protocol::generate_random_string(12);

            // Storing the challenge and random numbers in the user's info.
            user_info.c = c.clone();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            // Mapping the generated auth ID to the user's name.
            let auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_to_user.insert(auth_id.clone(), user_name.clone());

            println!("Successful Challenge Request username: {:?}", user_name);
            
            // Returning the authentication ID and challenge to the user.
            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            // Returning an error if the user is not found.
            Err(Status::new(
                Code::NotFound,
                format!("User: {} not found in database", user_name),
            ))
        }
    }
    // Handles the verification of the authentication challenge response from a user.
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let request = request.into_inner();

        let auth_id = request.auth_id;
        println!("Processing Challenge Solution auth_id: {:?}", auth_id);

        // Retrieving the username associated with the provided auth ID.
        let auth_id_to_user_hashmap = &mut self.auth_id_to_user.lock().unwrap();

        // Verifying if the auth ID exists and corresponds to a user.
        if let Some(user_name) = auth_id_to_user_hashmap.get(&auth_id) {
            let user_info_hashmap = &mut self.user_info.lock().unwrap();
            // Retrieving the user's information using their username.
            let user_info = user_info_hashmap
                .get_mut(user_name)
                .expect("AuthId not found on hashmap");

            // Updating the user's info with the response 's' from the authentication challenge.
            let s = BigUint::from_bytes_be(&request.s);
            user_info.s = s;

            // Getting protocol constants to use for verification.
            let (alpha, beta, p, q) = Protocol::get_constants();
            let protocol = Protocol { alpha, beta, p, q };

            // Verifying the user's response to the challenge.
            let verification = protocol.verify_proof(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &user_info.s,
            );

            // If the verification is successful, generate a new session ID for the user.
            if verification {
                let session_id = Protocol::generate_random_string(12);

                println!("Correct Challenge Solution username: {:?}", user_name);

                // Returning the new session ID.
                Ok(Response::new(AuthenticationAnswerResponse { session_id }))
            } else {
                // If the verification fails, return an error.
                println!("Wrong Challenge Solution username: {:?}", user_name);

                Err(Status::new(
                    Code::PermissionDenied,
                    format!("AuthId: {} bad solution to the challenge", auth_id),
                ))
            }
        } else {
            // If the auth ID does not exist, return an error.
            Err(Status::new(
                Code::NotFound,
                format!("AuthId: {} not found in database", auth_id),
            ))
        }
    }
}

// The entry point of the server application.
#[tokio::main]
async fn main() {
    // Define the address on which the server will listen.
    let addr = "0.0.0.0:50051".to_string();

    println!("Running the server in {}", addr);

    // Initialize the AuthImpl struct which implements the Auth service.
    let auth_impl = AuthImpl::default();

    // Build and run the gRPC server, serving the Auth service.
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        // Parse the address string into a SocketAddr and start the server.
        .serve(addr.parse().expect("could not convert address"))
        .await
        .unwrap(); // Unwrapping is used here for simplicity, but proper error handling is recommended for production code.
}
