# clipaha-rs

A Rust implementation of the [**Cli**entside **pa**ssword **ha**shing research](https://eprint.iacr.org/2022/1746.pdf) and [clipaha JS/WASM library](https://github.com/clipaha/clipaha) by Francisco et. al.  
Inspired by Francisco's talk at FOSSNorth 2023.

Used to offload password hashing to the client, different strengths available which target different system specs. E.g. it’s not suitable to run with Ultra strength on an old smartphone.

The resulting hashes should still be hashed with a low-cost hash before being stored in a DB, such as SHA-384, or SHA-512, to prevent direct usage of the hash in the database for authentication against the service should the database be compromised.
