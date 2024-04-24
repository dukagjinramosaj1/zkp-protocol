# ZKP-Protocol

## Context:
PoC of ZKP implementation of Chaum-Pedersen Protocol a basic  application that utilizes the protocol to register and authenticate users. This project uses gRPC protocol for server-client communication and RUST as development language

### Registration Process 
The prover (client) has a secret password x (i.e. it is a number) and wishes to register it with the verifier (server). To do that, they calculate y1 and y2 using public g and h and the secret x and sends to the verifier y1, y2.


## Project structure
- `src/server.rs` runs the gRPC server implementation for authenticating the user and verifying the challenge.
- `src/client.rs` has the gRPC client implementation that authenticates itself against the server.
- `src/lib.rs` contains all algorithm logic as a Protocol lib of Chaum-Pedersen protocol.
- `src/proto/` contains the Protobuf definitions. 

## Dependencies
- docker 
- docker-compose

## Setup Locally

To run the protocol, you can use docker-compose to run the server locally and then run the client in as interactive container to authenticate with the server.

- Inside the zkp_auth repo run `docker-compose build`
- Inside the zkp_auth repo run `docker-compose up server` to run the server (-d  if we need to run it as detached if you want to run the server in background but would be good to check the logs)
- Inside the zkp_auth repo run`docker run -it zkp_auth-client` run the container client in interactive mode.

## Tests
- `cargo test` in root path of the repository to run unit tests and some edge cases for the zkp protocol functionality