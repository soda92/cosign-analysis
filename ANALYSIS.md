# Analysis of BJCA Co-Sign App (Coss)

## Overview
This document details the reverse engineering of the BJCA Co-Sign Android application. The goal was to understand the cryptographic protocol used for user registration, certificate download, and QR code-based login, and to replicate this logic in a standalone Python client.

## Reverse Engineering Steps

### 1. APK Decompilation
*   **Tools**: `apktool`, `jadx`
*   **Initial Finding**: The app is packed with **360 Jiagu** (`com.stub.StubApp`), hiding the Java DEX code.
*   **Bypass**:
    *   Found `libapp.so` (Flutter) was **not encrypted**, revealing strings like API endpoints.
    *   Attempted runtime dumping using `frida-dexdump`.
    *   Encountered "Bad Checksum" anti-dumping protection.
    *   Created `fix_dex.py` to repair Adler-32 checksums in dumped DEX headers.
    *   Successfully decompiled the repaired DEX files using `jadx`.

### 2. Code Analysis
*   **Flutter-Java Bridge**:
    *   Identified `NativeRouter` and `CertEvents` classes handling communication between Flutter UI and Native Java logic.
    *   Traced "Download Cert" action to `CossReqCert.java` and `k.java`.
*   **Cryptographic Core**:
    *   Located `CossApiCore` and `CollaborateUtil`.
    *   Identified the app uses **SM2 Collaborative Signatures (Co-Sign)**.
    *   Found the provider implementation in `JeProvider.java` (Pure Java, based on Bouncy Castle).

### 3. Protocol Re-implementation
*   **Key Generation Logic**:
    *   The client generates a 32-byte random secret (Key Share A).
    *   The client computes a `ClientSecret` scalar using: `SM3(IMEI) XOR SM3(PIN) XOR RandomSecret`.
    *   The client sends `P = ClientSecret * G` (Public Point) to the server during `genkey`.
*   **Co-Signing Logic (`reqcert` & `sign`)**:
    *   The server sends a challenge (Hash `e`) and a Point `P_server` (`signParam`).
    *   The client performs SM2 math:
        1.  Generate randoms `k1, k2`.
        2.  Calculate `R = k1 * P_server + k2 * G`.
        3.  Calculate partial signatures `s1, s2, s3`:
            *   `s1 = (R.x + e) mod N`
            *   `s2 = (d_client * k1) mod N`
            *   `s3 = (d_client * (s1 + k2)) mod N`
    *   The client sends `s1, s2, s3` (Base64 encoded, Java BigInteger format) to the server.

### 4. Traffic Analysis
*   **Tool**: `mitmproxy` + Custom `parse_flows.py` (TNetString parser).
*   **Findings**:
    *   **App ID**: `APP_09613F880BA343DC95E31B17096A0471` (critical for API access).
    *   **IMEI Format**: `Base64(SHA1(AndroidID + PackageName))`.
    *   **Data Formats**:
        *   `genkey`: Sends Uncompressed Point (65 bytes).
        *   `reqcert`: Sends 33-byte signed BigIntegers (if high bit set) for `s1, s2, s3`.

## Python Implementation (`coss_client`)

A pure Python package was created to interact with the API.

*   **`coss_client/api/client.py`**: Handles HTTP flow (Register -> GenKey -> ReqCert -> Login).
*   **`coss_client/crypto/sm2.py`**: Pure Python implementation of SM2 Elliptic Curve math.
*   **`coss_client/crypto/utils.py`**: Implements the specific hashing, XORing, and Co-Sign math (`server_sem_sign`).

### Features
*   **Registration**: Parsed encrypted QR code (`o` field) using cyclic XOR key `MSSPoper@2018`.
*   **Identity Persistence**: Saves IMEI, Keys, and MSSP ID to `coss_identity.json` for subsequent logins.
*   **Login**: Supports scanning Login QR codes and performing the cryptographic handshake.

## Usage

```bash
# Register and Download Certificate
python main.py register '{"cv":"2.0", "o":"ENCRYPTED...", ...}' '123456'

# Login (after registration)
python main.py login '{"cv":"2.0", "o":"ENCRYPTED_LOGIN...", ...}' '123456'
```

## Remaining Issues
*   The `reqcert` step sometimes fails with `89002025` (Key calculation error). This suggests a subtle mismatch in the `ClientSecret` scalar calculation or the SM2 point math edge cases (e.g., specific padding expected by the server). However, the logic aligns strictly with the decompiled Java code.
