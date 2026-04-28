# README
# IF4FL: An identity-based fully aggregate signature scheme for federated learning in VANETs
Based on Pairing-Based Cryptography (PBC)

## Overview
This project implements a **identity-based aggregate signature scheme** for vehicular federated learning using the PBC (Pairing-Based Cryptography) library. It supports:
- Key extraction for 20 vehicle nodes
- Independent local model signing for each vehicle
- Single-signature verification
- **Aggregate verification** for 20 vehicles (batch validation)
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
- `-lpbc`: Links the PBC pairing cryptography library
- `-lcrypto`: Links OpenSSL for hash functions

### Step 2: Run the Executable
```bash
./vehicular_fl
```

### Step 3: Expected Output
The program will print:
1. System setup & vehicle key extraction logs
2. Signature generation results for 20 vehicles
3. Single-signature verification results (SUCCESS/FAIL)
4. **Aggregate verification result** for all 20 vehicles
5. Clean memory release logs

Example output snippet:
```
1th key is generated! ✅
...
20th key is generated! ✅

Vehicle 1: Signature is valid! ✅
...
Vehicle 20: Signature is valid! ✅
The aggregate signature is valid! ✅ SUCCESS
All resources cleared safely.
```

---

## Benchmark Results Reproduction
This benchmark measures **execution time** for core cryptographic operations (20 vehicles, Type-A 160-bit curve).

### Step 1: Enable Time Measurement (Optional Modification)
Add time-test code to `main.c` (insert at the start/end of workflows):
```c
#include <time.h>

// Example: Measure aggregate verification time
    clock_gettime(CLOCK_MONOTONIC, &start);
    Setup(P, Y, Z, y, z);
    clock_gettime(CLOCK_MONOTONIC, &end); 
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9; 
printf("Execution time of Setup algorithm: %f seconds\n", elapsed);
```

### Step 2: Recompile & Run
```bash
gcc -o vehicle main.c -lpbc -lgmp -lcrypto
./vehicle
```

### Step 3: Standard Benchmark Results (Reference)
Test environment: Ubuntu 24.04, Intel i7 CPU (One core), 1GB RAM
| Operation | Execution Time (ms) |
|-----------|---------------------|
| System Setup | ~5.482 ms |
| Key Extraction of the TA(20 vehicles) | ~447.775 ms |
| Key Extraction of the vehicles (20 vehicles) | ~366.517 ms |
| Signature Generation (20 vehicles) | ~165.169 ms |
| Single Signature Verification | ~517.362 ms per vehicle |
| **Aggregate Verification (20 vehicles)** | ~108.965 ms |

### Step 4: Reproduce Consistently
- Run the program **20 times** and take the average
- Close other applications to reduce CPU interference
- Use the fixed 160-bit Type-A curve (hardcoded in the code)

---

## Core Function Explanation
1. `Setup()`: Initializes system public/private parameters (P, Y, Z, y, z)
2. `Extraction()`: Generates pseudonyms and private keys for vehicles
3. `sign()`: Signs local model data for each vehicle
4. `verify()`: Verifies a single vehicle's signature
5. `aggregate_verify()`: Batch-verifies 20 vehicles' signatures (optimized RSU operation)

---

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
- Fixed number of vehicles: **20**
- Fixed iteration number `t` (all vehicles share the same round)
- 20 distinct local model messages (`m[0] ~ m[19]`)
- All `element_t` variables are properly initialized/cleared (no memory leaks)