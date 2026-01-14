# RSA-Digital-SigUp# RSA Digital Signing Tool

## Setup
1. Install dependencies: `pip install pycryptodome`
2. Generate keys: `python signer.py generate-keys`

## Usage
- Sign a file: `python signer.py sign example.txt`
- Verify a file: `python signer.py verify example.txt example.txt.sig`
