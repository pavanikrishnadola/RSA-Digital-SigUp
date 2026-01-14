import argparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

# ---------- Key Generation ----------
def generate_keys(private_path="private.pem", public_path="public.pem"):
    if os.path.exists(private_path) or os.path.exists(public_path):
        print("Keys already exist! Delete them first if you want new keys.")
        return
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_path, "wb") as f:
        f.write(private_key)
    with open(public_path, "wb") as f:
        f.write(public_key)
    
    print(f"Keys generated!\nPrivate key: {private_path}\nPublic key: {public_path}")

# ---------- File Signing ----------
def sign_file(file_path, private_key_path="private.pem"):
    if not os.path.exists(file_path):
        print(f"File '{file_path}' does not exist.")
        return
    if not os.path.exists(private_key_path):
        print(f"Private key '{private_key_path}' not found. Generate keys first.")
        return

    with open(file_path, "rb") as f:
        file_data = f.read()
    
    h = SHA256.new(file_data)

    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    
    signature = pkcs1_15.new(private_key).sign(h)

    sig_file = file_path + ".sig"
    with open(sig_file, "wb") as f:
        f.write(signature)
    
    print(f"File signed! Signature saved as '{sig_file}'")

# ---------- Signature Verification ----------
def verify_file(file_path, signature_path, public_key_path="public.pem"):
    if not os.path.exists(file_path) or not os.path.exists(signature_path):
        print("File or signature does not exist.")
        return
    if not os.path.exists(public_key_path):
        print(f"Public key '{public_key_path}' not found.")
        return

    with open(file_path, "rb") as f:
        file_data = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    h = SHA256.new(file_data)

    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("✅ Verification successful: Signature is valid!")
    except (ValueError, TypeError):
        print("❌ Verification failed: Signature is invalid.")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="RSA Digital Signing Tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # generate-keys
    parser_gen = subparsers.add_parser("generate-keys", help="Generate RSA public/private keys")

    # sign
    parser_sign = subparsers.add_parser("sign", help="Sign a file")
    parser_sign.add_argument("file", help="File to sign")

    # verify
    parser_verify = subparsers.add_parser("verify", help="Verify a file signature")
    parser_verify.add_argument("file", help="Original file")
    parser_verify.add_argument("signature", help="Signature file")

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys()
    elif args.command == "sign":
        sign_file(args.file)
    elif args.command == "verify":
        verify_file(args.file, args.signature)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
