# Riot API

## Table of Contents

- [Project Overview](#project-overview)
- [Prerequisites](#prerequisites)
- [Install & Clone](#install--clone)
- [Build](#build)
- [Run](#run)
- [API Documentation](#api-documentation)
- [API Endpoints](#api-endpoints)
  - [/encrypt (POST)](#1-encrypt-post)
  - [/decrypt (POST)](#2-decrypt-post)
  - [/sign (POST)](#3-sign-post)
  - [/verify (POST)](#4-verify-post)
- [Project Structure](#project-structure)
- [Testing and Coverage](#testing-and-coverage)
- [Latency Testing](#latency-testing)
- [Security Considerations](#security-considerations)
- [Suggested Improvements](#suggested-improvements)

## Project Overview

The Riot API is a security-focused REST API built with Go and the Gin framework. It provides endpoints for encryption, decryption, signing, and signature verification. The encryption and decryption logic uses Base64 encoding, but the implementation is designed to allow **easy substitution** of different encryption methods in the future. The API also includes basic cryptographic signing and signature verification endpoints using HMAC.

## Prerequisites

- Go version **1.21** or later.
- You can also run directly the binary `./app`

## Install & Clone

Clone the repository to your local machine:

```bash
git clone git@github.com:affanydev/riot-api.git
cd riot-api
```

## Build

Build the application using:

```bash
go build -o app
```

This will generate an executable named `app`.

## Run

Run the application with:

```bash
./app
```

## API Documentation

The API is documented using **Swagger**. You can explore and interact with the API through the Swagger UI.

To access the documentation:

1. Run the application.
2. Open your browser and navigate to: http://localhost:8022/swagger/index.html

This will open the interactive Swagger UI, where you can see all available endpoints, test them, and view their details such as request parameters, response formats, and error messages.

## API Endpoints

### 1. `/encrypt` (POST)

Encrypts every value in the JSON object at depth 1 using Base64 encoding.

#### Example Request:

```json
{
  "foo": "foobar",
  "bar": {
    "isBar": true
  }
}
```

#### Example Response:

```json
{
  "bar": "eyJpc0JhciI6dHJ1ZX0=",
  "foo": "ImZvb2JhciI="
}
```

### 2. `/decrypt` (POST)

Detects encrypted Base64 strings in the JSON payload and decrypts them. The decrypted values are returned in the response.

#### Example Request:

```json
{
  "bar": "eyJpc0JhciI6dHJ1ZX0=",
  "foo": "ImZvb2JhciI=",
  "foo1": "MjIy",
  "foo2": "MjIyLjU=",
  "foo3": "WyJmZiIsNV0="
}
```

#### Example Response:

```json
{
  "bar": {
    "isBar": true
  },
  "foo": "foobar",
  "foo1": 222,
  "foo2": 222.5,
  "foo3": ["ff", 5]
}
```

### 3. `/sign` (POST)

Computes a cryptographic signature (HMAC) for the provided JSON payload and returns the signature in the response.

#### Example Request:

```json
{
  "bar": {
    "isBar": true
  },
  "foo": "foobar",
  "foo1": 222,
  "foo2": 222.5,
  "foo3": ["ff", 5]
}
```

#### Example Response:

```json
{
  "signature": "l7ykPE...."
}
```

### 4. `/verify` (POST)

Verifies the provided HMAC signature against the data. If the signature is valid, it returns a `204 No Content` status. Otherwise, it returns a `400 Bad Request` status.

#### Example Request:

```json
{
  "signature": "somesignaturevalue",
  "data": {
    "foo": "foobar",
    "bar": "barfoo"
  }
}
```

#### Example Response:

- **Success**: `204 No Content`
- **Failure**: `400 Bad Request`

## Project Structure

To avoid circular dependencies and maintain clean architecture, the project is structured as follows:

- **Controller**: Handles the API routes and request handling.
- **Service**: Contains the core business logic.
- **Tools**: Utility functions for encryption and signing.
- **Main**: The entry point of the application, where the server is initialized.

The architecture is designed to be modular and flexible, with a clear separation between the application layers to promote maintainability.

## Testing and Coverage

To run tests and see test coverage:

1. Run the following command to execute all tests:

   ```bash
   go test -v ./...
   ```

2. For detailed test coverage, use the following:

   ```bash
   go test --cover -v ./... -coverprofile=cover.out
   ```

3. To view the coverage report, run:

   ```bash
   go tool cover -html=cover.out
   ```

## Latency Testing

To test the API’s latency under load, install the `hey` tool:

```bash
go install github.com/rakyll/hey@latest
```

You can then test the `/encrypt` and `/decrypt` endpoints with the following commands:

1. Test the `/encrypt` endpoint:

   ```bash
   hey -n 10000 -c 50 -m POST -H "Content-Type: application/json" -d '{"foo": "foobar", "bar": {"isBar": true }}' http://localhost:8022/encrypt
   ```

2. Test the `/decrypt` endpoint:

   ```bash
   hey -n 10000 -c 50 -m POST -H "Content-Type: application/json" -d '{"bar": "eyJpc0JhciI6dHJ1ZX0=", "foo": "ImZvb2JhciI="}' http://localhost:8022/decrypt
   ```

Where:

- `-n 10000`: Number of requests (10,000)
- `-c 50`: Number of concurrent clients (50)

### Latency Testing Results in local

The following results are from a load test conducted in dev server.

#### Summary:

- **Total Time**: 0.4966 secs
- **Slowest Request**: 0.0417 secs
- **Fastest Request**: 0.0001 secs
- **Average Response Time**: 0.0024 secs
- **Requests per second**: 20137.9090

**Note** : Latency tests should, of course, be conducted on specifications similar to those of the deployment server, with request sizes close to those encountered in real-world conditions.

## Security Considerations

- **Logging**: Logs and response messages are intentionally kept minimal to ensure that sensitive information is not exposed. For instance, detailed error messages are not logged.
- **Encryption**: The encryption used in the `/encrypt` and `/decrypt` endpoints is currently Base64, which is not secure for real-world applications. However, the design allows easy replacement with a more robust encryption algorithm.

## Suggested Improvements

- **Deployment**: Implement Docker support to facilitate deployment in different environments.
- **Encryption**: Add more robust encryption methods for secure data transmission, like added AES-256-CGM encryption in tools.
- **Rate Limiting**: Implement **distributed** rate limiting to prevent abuse of the API.
