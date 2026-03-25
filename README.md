# SHA-1 Z3 Solver

An implementation of the SHA-1 cryptographic hash function using Z3 SMT (`z3-solver`) BitVectors.

## Purpose
This project provides a formal SMT model of the SHA-1 compression function. It translates the 80-round SHA-1 operation (including the message schedule and state updates) into Z3 constraints. This is the foundational constraint system required for replicating collision attacks against SHA-1.

## Setup
Requires the Z3 Python bindings:
```bash
pip install z3-solver
```
