LCX - Linux Command eXecutor
A lightweight HTTP API service for executing Linux commands remotely with JWT authentication.
Features

Execute Linux shell commands via HTTP API
JWT token-based authentication
Configurable port (default: 8088)
Returns command output in JSON format

Installation
bashCopycargo build --release
Usage

Start the service:

bashCopy./lcx --port 8088

Get the JWT token:
The token will be automatically generated and saved to token.txt when starting the service.
Execute commands:

bashCopycurl -X POST http://127.0.0.1:8088/execute \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la"}'
Response format:
jsonCopy{
    "stdout": "command output",
    "stderr": "error output if any",
    "status": 0
}
Security Notes

Service binds to localhost (127.0.0.1) by default
Requires valid JWT token for authentication
Please be cautious when exposing this service to network

Build Requirements

Rust 1.7x or higher
Dependencies listed in Cargo.toml

License
MIT
