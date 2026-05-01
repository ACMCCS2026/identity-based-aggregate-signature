# README
# IF4FL: An identity-based fully aggregate signature scheme for federated learning in VANETs
Based on Pairing-Based Cryptography (PBC)

## Overview
This project implements a **identity-based aggregate signature scheme** for vehicular federated learning using the PBC (Pairing-Based Cryptography) library. It supports:
- Key extraction for 40 vehicle nodes
- Independent local model signing for each vehicle
- Single-signature verification
- **Aggregate verification** for 5-40 vehicles (batch validation)
- Cryptographically secure operations over Type-A pairing curves

## Prerequisites
Tested on **Ubuntu 24.04** (x86 64). Install required dependencies first:

### 1. Install GCC Compiler
```bash
sudo apt update
sudo apt install gcc make
```

### 2. Install PBC Library (Core Cryptography)
```bash
sudo apt install libpbc-dev
```

### 3. Install OpenSSL (For SHA-256 Hash Functions)
```bash
sudo apt install libssl-dev
```

## File Structure
```
├── main.c           # Main program: vehicle initialization, workflow execution and core algorithms (Setup, Extraction, Sign, Verify, Aggregate-Verify)
├── Shim.c           # Main program: execution time of the aggregate-verificatoin algorithm of (5, 10, 15, 20, 25, 30, 35, 40) models in Shim's partial IBAS scheme [9].
├── Gentry.c           # Main program: execution time of the aggregate-verificatoin algorithm of (5, 10, 15, 20, 25, 30, 35, 40) models in Gentry's scheme [10]
├── Cheng.c           # Main program: execution time of (5, 10, 15, 20, 25, 30, 35, 40) verificatoin algorithms in Cheng's pairing-free individual verification  scheme [26].
├── Our.c           # Main program: execution time of the aggregate-verificatoin algorithm of (5, 10, 15, 20, 25, 30, 35, 40) models in our IBAS scheme.
└── README.md        # This documentation
```

### Core Data Structure
`Vehicle` struct (stores all credentials for one vehicle):
```c
typedef struct {
    element_t PID1i;  // Pseudonym 1 (G1 group)
    element_t PID2i;  // Pseudonym 2 (G1 group)
    element_t ai;     // Private key (Zr group)
    element_t Qi;     // Public parameter (G1 group)
} Vehicle;
```

---

## Step-by-Step Compilation & Running
### Step 1: Compile the Source Code
Use `gcc` to compile the program, **link PBC and OpenSSL libraries** (critical for successful compilation):
```bash
gcc -o vehicular_fl main.c functions.c -lpbc -lcrypto
```
```bash
gcc -o Gentry Gentry.c functions.c -lpbc -lcrypto
```
```bash
gcc -o Shim Shim.c functions.c -lpbc -lcrypto
```
```bash
gcc -o Cheng Cheng.c functions.c -lpbc -lcrypto
```
```bash
gcc -o Our Our.c functions.c -lpbc -lcrypto
```
- `-lpbc`: Links the PBC pairing cryptography library
- `-lcrypto`: Links OpenSSL for hash functions

### Step 2: Run the Executable
```bash
./vehicular_fl
```
```bash
./Gentry
```
```bash
./Shim
```
```bash
./Cheng
```
```bash
./Our
```
### Step 3: Expected Output
The program of vehicle_fl will print:
1. System setup & vehicle key extraction logs
2. Signature generation results for 40 vehicles
3. Single-signature verification results (SUCCESS/FAIL)
4. **Aggregate verification result** for all 40 vehicles
5. Clean memory release logs

Example output snippet:
```
1th key is generated! ✅
...
40th key is generated! ✅

Vehicle 1: Signature is valid! ✅
...
Vehicle 40: Signature is valid! ✅
The aggregate signature is valid! ✅ SUCCESS
All resources cleared safely.
```
The program of others will print:
1. System setup & vehicle key extraction logs
2. Signature generation results for 40 vehicles
3. **Execution time of aggregate verification algorithms** of (5, 10, 15, 20, 25, 30, 35, 40) vehicles
4. Clean memory release logs

Example output snippet:
```
The execution time of an aggregate signature of 5 models is: 0.05145 s.
...
The execution time of an aggregate signature of 40 models is 0.342891 s.
```
```
The execution time of 5 signatures is 0.015855 s.
...
The execution time of 40 signatures is 0.123268s
```

---

## Benchmark Results 
This benchmark measures **execution time** for core cryptographic operations (40 vehicles, Type-A 160-bit curve).


Test environment: Ubuntu 24.04, Intel i7 CPU (One core), 1GB RAM
Close other applications to reduce CPU interference
Run the program **40 times** and take the average
| Operation | Execution Time (ms) |
|-----------|---------------------|
| System Setup | ~3.196 ms |
| Key Extraction of the TA | ~10.393 ms |
| Key Extraction of the vehicles | ~8.326 ms |
| Signature Generation | ~5.072 ms |
| Signature Verification | ~13.299 ms (per vehicle)|
| 40 Signature Verification | ~531.978 ms (40 vehicles)|
| **Aggregate Verification (40 vehicles)** | ~48.569 ms |



## Core Function Explanation
1. `Setup()`: Initializes system public/private parameters (P, Y, Z, y, z)
2. `Extraction()`: Generates pseudonyms and private keys for vehicles
3. `sign()`: Signs local model data for each vehicle
4. `verify()`: Verifies a single vehicle's signature
5. `aggregate_verify()`: Batch-verifies 40 vehicles' signatures (optimized RSU operation)

---

# 📊 Comparison With Other Schemes
The following table shows **performance comparison** between our scheme and three mainstream schemes (ms).  
All results are averaged over 40 runs.

| Scheme | Shim [9] | Gentry[10] | Cheng [26] | Our scheme |
|-------|----------------|---------------------|-------------------------|-------------------------|
| 5 models| 27.319 | 51.045 | 15.855 | 16.873 |
| 10 models| 54.027 | 91.785 | 31.703 | 25.480 |
| 15 models | 75.096 | 128.784 | 47.599 | 36.382 |
| 20models | 98.343 | 168.772 | 60.169 | 47.974 |
| 25 models| 124.174 | 216.187 | 76.573 | 55.246 |
| 30 models| 151.397 | 271.623 | 91.061 | 2.13 |
| 35 models | 175.769 | 299.939 | 106.680 | 63.545 |
| 40models | 199.749 | 342.891 | 123.268 | 70.999 |

### Observation

- Our scheme has the **fastest aggregate verification**
- Our scheme is **more suitable for real-time vehicular networks**




## Troubleshooting
### Error 1: `Segmentation fault (core dumped)`
- Cause: PBC group type mismatch (Zr/G1/GT misuse)
- Fix: Use the finalized code (all type errors fixed)

### Error 2: `cannot find -lpbc`
- Fix: Reinstall PBC library: `sudo apt install libpbc-dev`

### Error 3: Compilation fails (OpenSSL missing)
- Fix: Install OpenSSL: `sudo apt install libssl-dev`

---

## Notes
- Fixed number of vehicles: **40**
- Fixed iteration number `t` (all vehicles share the same round)
- 40 distinct local model messages (`m[0] ~ m[39]`)
- All `element_t` variables are properly initialized/cleared (no memory leaks)
