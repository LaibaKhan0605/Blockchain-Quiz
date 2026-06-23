import hashlib
import random
import string
import json
import time # For simulating time-based operations if needed
import os   # For file path operations

# --- Flask Imports ---
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS

# --- Configuration ---
# In a real system, these would be robustly generated/managed
SALT_FOR_COMMITMENT = "anon_mixer_commitment_salt_abc123"
SALT_FOR_NULLIFIER = "anon_mixer_nullifier_xyz789"

# --- Helper Functions ---

def sha256_hash(data):
    """Computes the SHA-256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()

def generate_random_secret(length=32):
    """Generates a random alphanumeric secret string."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# --- Merkle Tree Implementation ---
class MerkleTree:
    """
    A simplified Merkle Tree implementation.
    Leaves are commitments, allowing proof of inclusion.
    """
    def __init__(self, leaves=None):
        # Expect leaves to be commitment hashes (already hashed by caller).
        # Do not re-hash here to avoid double-hashing commit values.
        self.leaves = list(leaves) if leaves else []
        self.tree = [] # Stores all nodes of the tree
        self.root = None
        if self.leaves:
            self._build_tree()

    def _hash_pair(self, left, right):
        """Hashes two child nodes together."""
        # Ensure consistent order for hashing pairs
        return sha256_hash(min(left, right) + max(left, right))

    def _build_tree(self):
        """Builds the Merkle tree from the current leaves."""
        if not self.leaves:
            self.root = None
            return

        current_level = list(self.leaves)
        self.tree = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left # Duplicate last if odd number
                next_level.append(self._hash_pair(left, right))
            current_level = next_level
            self.tree.append(current_level)

        self.root = current_level[0] if current_level else None

    def add_leaf(self, leaf_data):
        """Adds a new leaf (commitment hash) to the tree and rebuilds."""
        # Expect caller to provide a commitment hash (already hashed).
        # Append directly to avoid double-hashing.
        self.leaves.append(leaf_data)
        self._build_tree()

    def get_merkle_root(self):
        """Returns the Merkle root of the tree."""
        return self.root

    def get_merkle_proof(self, target_leaf_hash):
        """
        Generates a Merkle proof for a given leaf hash.
        Returns a list of sibling hashes and their positions ('left'/'right').
        """
        if not self.root or target_leaf_hash not in self.leaves:
            return None # Leaf not in tree

        index = self.leaves.index(target_leaf_hash)
        proof = []

        for level_idx in range(len(self.tree) - 1): # Iterate through levels up to root's parent
            current_level = self.tree[level_idx]
            is_left_node = (index % 2 == 0)
            sibling_index = index + 1 if is_left_node else index - 1

            if sibling_index < len(current_level): # Check if sibling exists
                sibling_hash = current_level[sibling_index]
                proof.append({'hash': sibling_hash, 'position': 'right' if is_left_node else 'left'})
            else:
                # If odd number of nodes, last node is duplicated. Sibling is self.
                # In this simplified implementation, we duplicate the last hash for the odd node.
                # A more robust solution might handle this edge case differently based on standard.
                proof.append({'hash': current_level[index], 'position': 'self_duplicated'})


            index //= 2 # Move up to the parent's index in the next level

        return proof

    @staticmethod
    def verify_merkle_proof(leaf_hash, proof, root_hash):
        """
        Verifies a Merkle proof against a given leaf hash and root hash.
        """
        current_hash = leaf_hash
        for p in proof:
            if p['position'] == 'left':
                current_hash = MerkleTree._hash_pair(p['hash'], current_hash)
            elif p['position'] == 'right':
                current_hash = MerkleTree._hash_pair(current_hash, p['hash'])
            elif p['position'] == 'self_duplicated':
                 current_hash = MerkleTree._hash_pair(current_hash, current_hash) # Re-hash if it was duplicated
            else:
                return False # Invalid proof position

        return current_hash == root_hash

# --- ZKP Simulation Functions (Conceptual, NOT a real zkSNARKs implementation) ---

def generate_proof_zkp_conceptual(secret, anonymity_set_merkle_root, anonymity_set_merkle_proof, commitment, nullifier):
    """
    Simulates the generation of a Zero-Knowledge Proof (ZKP).
    In a real zkSNARKs system:
    1. A circuit would be defined (e.g., in Circom) that takes `secret`,
       `anonymity_set_merkle_root`, `anonymity_set_merkle_proof` as private/public inputs.
    2. The circuit would check:
       a) That sha256(secret || SALT_FOR_COMMITMENT) == commitment
       b) That MerkleTree.verify_merkle_proof(commitment, anonymity_set_merkle_proof, anonymity_set_merkle_root) is true.
       c) That sha256(secret || SALT_FOR_NULLIFIER) == nullifier.
    3. The prover would generate a `witness` and use a zkSNARKs library (e.g., snarkjs) to generate a proof.

    For this simulation, we return a dictionary representing the public inputs
    and a dummy 'proof_data' indicating a successful conceptual proof.
    """
    # print(f"[ZKP_Sim] Generating conceptual ZKP for secret (first 5): {secret[:5]}...") # Commented for cleaner web logs
    # In reality, this would involve complex cryptographic operations.
    # Here, we return what a verifier would need to check.
    public_inputs = {
        "commitment": commitment,
        "nullifier": nullifier,
        "merkle_root": anonymity_set_merkle_root,
        "merkle_proof_elements": [item['hash'] for item in anonymity_set_merkle_proof] # Just hashes for public part
    }
    proof_data = "zkSNARKs_proof_payload_" + sha256_hash(secret + str(time.time())) # Dummy proof data
    # print(f"[ZKP_Sim] Conceptual ZKP generated.") # Commented for cleaner web logs
    return {"proof_data": proof_data, "public_inputs": public_inputs}

def verify_proof_zkp_conceptual(zkp_output, current_global_merkle_root, used_nullifiers):
    """
    Simulates the verification of a Zero-Knowledge Proof (ZKP).
    In a real zkSNARKs system:
    1. The verifier would use the `public_inputs` and `proof_data` to run the
       zkSNARKs verification algorithm against the pre-generated `verification_key`.
    2. If the zkSNARKs verification passes, it confirms that the prover correctly
       demonstrated knowledge of the secret and its relation to the Merkle tree
       and nullifier, *without revealing the secret*.

    For this simulation, we perform the logical checks that the zkSNARKs circuit
    would have enforced, plus the double-spending check.
    """
    # print(f"[ZKP_Sim] Verifying conceptual ZKP...") # Commented for cleaner web logs
    proof_data = zkp_output["proof_data"]
    public_inputs = zkp_output["public_inputs"]

    commitment = public_inputs["commitment"]
    nullifier = public_inputs["nullifier"]
    merkle_root_in_proof = public_inputs["merkle_root"]
    # merkle_proof_elements = public_inputs["merkle_proof_elements"] # Not directly used here, ZKP proves it internally

    # 1. Check if the Merkle root used in the proof matches the current active system root.
    # This ensures the proof is against the current anonymity set state.
    if current_global_merkle_root != merkle_root_in_proof:
        # print(f"[ZKP_Sim_Error] Merkle root mismatch. Proof created for an old root. Expected: {current_global_merkle_root[:10]}..., Got: {merkle_root_in_proof[:10]}...") # Commented for cleaner web logs
        return False, "Merkle root used in proof does not match current system root. Anonymity set changed."

    # 2. Check for double spending using the nullifier
    if nullifier in used_nullifiers:
        # print(f"[ZKP_Sim_Error] Nullifier already used: {nullifier[:10]}...") # Commented for cleaner web logs
        return False, "Double spending detected: nullifier already used."

    # 3. Conceptual ZKP specific verification (assuming the snarkjs library did its job)
    # If the `proof_data` is well-formed (not just empty), we conceptually assume the cryptographic part passed.
    if not proof_data.startswith("zkSNARKs_proof_payload_"):
        # print(f"[ZKP_Sim_Error] Invalid proof data format.") # Commented for cleaner web logs
        return False, "Invalid ZKP proof data."

    # print(f"[ZKP_Sim] Conceptual ZKP verification successful.") # Commented for cleaner web logs
    return True, "ZKP verified and nullifier is unique."


# --- AnonMixer Core Logic ---
class AnonMixer:
    """
    Manages the privacy-preserving transaction system.
    Implements commitment, proof, verification, and privacy layer.
    """
    _instance = None # Singleton pattern for easier global state management

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AnonMixer, cls).__new__(cls)
            cls._instance.initialize()
        return cls._instance

    @classmethod
    def get_instance(cls):
        return cls.__new__(cls)

    def initialize(self):
        """Initializes the mixer's state."""
        self.commitments = {}       # Stores {secret: commitment_hash} for known users
                                    # (for simulation, not public knowledge in real system)
        self.commitment_pool = []   # Stores just commitment_hashes (publicly visible)
        self.used_nullifiers = set() # Stores used nullifier hashes (publicly visible for double-spend checks)
        self.merkle_tree = MerkleTree()
        self.user_secrets = {}      # Stores {user_id: secret} for demo purposes, NOT in a real system.
        self.log_messages = []      # For Flask UI to fetch logs

        print("AnonMixer system initialized.")
        self._add_log("AnonMixer system initialized.")

    def _add_log(self, message):
        """Adds a message to the internal log."""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_messages.append(log_entry)
        if len(self.log_messages) > 20: # Keep log to a reasonable size
            self.log_messages.pop(0) # Remove oldest entry

    def _update_merkle_tree(self):
        """Rebuilds the Merkle tree from the current commitment pool."""
        self.merkle_tree = MerkleTree(self.commitment_pool)
        self._add_log(f"Merkle tree updated. Current root: {self.merkle_tree.get_merkle_root()[:10]}...")


    def deposit(self, user_id, secret):
        """
        Commitment Phase: Generates a commitment and adds it to the pool.
        """
        # In the web UI, user_id is implicit, secret is primary
        # If user_id is provided, check against self.user_secrets for demo consistency
        if secret in self.commitments:
            self._add_log(f"Error: Secret (first 5 chars): {secret[:5]}... already committed. Duplicate deposit attempt?")
            return False, "Secret already used for a deposit."


        commitment = sha256_hash(secret + SALT_FOR_COMMITMENT)

        if commitment in self.commitment_pool:
            self._add_log(f"Error: Commitment '{commitment[:10]}...' already exists in pool. Duplicate deposit attempt?")
            return False, "Commitment already exists in pool."

        self.commitments[secret] = commitment
        self.commitment_pool.append(commitment)
        # self.user_secrets[user_id] = secret # User_id concept is less relevant for web anonymous deposit
        self._update_merkle_tree() # Rebuild tree after adding commitment

        self._add_log(f"Deposit successful for secret (first 5 chars): {secret[:5]}... Commitment: {commitment[:10]}...")
        self._add_log(f"Current anonymity set size: {len(self.commitment_pool)}")
        return True, "Deposit successful."

    def withdraw(self, secret): # user_id removed as it's not needed for withdrawal via secret
        """
        Proof and Verification Phase: User proves ownership of a commitment
        without revealing the secret, and withdraws funds.
        Includes double-spending prevention.
        """
        self._add_log(f"Withdrawal Attempt for secret (first 5 chars): {secret[:5]}...")

        commitment = sha256_hash(secret + SALT_FOR_COMMITMENT)

        if commitment not in self.commitment_pool:
            self._add_log(f"Error: Commitment '{commitment[:10]}...' not found in the active pool.")
            return False, "Secret not found or invalid (commitment not in pool)."

        # --- Generate Nullifier ---
        nullifier = sha256_hash(secret + SALT_FOR_NULLIFIER)
        self._add_log(f"Generated Nullifier: {nullifier[:10]}...")

        if nullifier in self.used_nullifiers:
            self._add_log(f"Error: Nullifier '{nullifier[:10]}...' already used. Double spend detected!")
            return False, "Double spending detected."

        # --- Generate Merkle Proof for ZKP input ---
        merkle_root = self.merkle_tree.get_merkle_root()
        merkle_proof = self.merkle_tree.get_merkle_proof(commitment)

        if not merkle_proof:
            self._add_log(f"Error: Merkle proof for commitment '{commitment[:10]}...' could not be generated.")
            return False, "Could not generate Merkle proof."

        self._add_log(f"Merkle Root for proof: {merkle_root[:10]}...")
        # self._add_log(f"Merkle Proof (elements): {[p['hash'][:10] for p in merkle_proof]}") # Too verbose for log

        # --- ZKP Generation (Conceptual) ---
        self._add_log("Initiating ZKP Generation...")
        zkp_output = generate_proof_zkp_conceptual(
            secret,
            merkle_root,
            merkle_proof,
            commitment, # Public input
            nullifier   # Public input
        )
        if not zkp_output:
            self._add_log("Error: ZKP generation failed.")
            return False, "ZKP generation failed."

        # --- ZKP Verification (Conceptual) ---
        self._add_log("Initiating ZKP Verification...")
        is_valid_zkp, zkp_message = verify_proof_zkp_conceptual(
            zkp_output,
            self.merkle_tree.get_merkle_root(), # Current global root for verification
            self.used_nullifiers
        )

        if not is_valid_zkp:
            self._add_log(f"Error: ZKP verification failed: {zkp_message}")
            return False, f"ZKP verification failed: {zkp_message}"

        # If ZKP verification passes and nullifier is unique:
        self.used_nullifiers.add(nullifier)
        self._add_log(f"Withdrawal successful! Nullifier '{nullifier[:10]}...' recorded to prevent double spending.")
        return True, "Withdrawal successful."

    def get_system_status(self):
        """Returns current system status for debugging/monitoring."""
        return {
            "total_commitments_in_pool": len(self.commitment_pool),
            "merkle_root": self.merkle_tree.get_merkle_root(),
            "used_nullifiers_count": len(self.used_nullifiers),
            "commitments_sample": [c[:10] for c in self.commitment_pool], # Show all for web
            "nullifiers_sample": [n[:10] for n in list(self.used_nullifiers)], # Show all for web
            "transaction_log": self.log_messages # Include logs for web UI
        }

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app) # Enable CORS for frontend to interact with backend
mixer = AnonMixer.get_instance() # Get the singleton mixer instance

# Serve static files (HTML, CSS, JS) from the current directory
# WARNING: This is for development/demonstration only, not production!
@app.route('/')
def serve_index():
    # Read index.html content and render it directly.
    # Flask typically expects templates in a 'templates' folder.
    # For a single file solution, render_template_string is used.
    with open("index.html", "r") as f:
        html_content = f.read()
    return render_template_string(html_content)

@app.route('/<path:filename>')
def serve_static(filename):
    # Serve CSS and JS files directly from the current directory
    return send_from_directory('.', filename)

@app.route('/deposit', methods=['POST'])
def api_deposit():
    data = request.get_json()
    secret = data.get('secret')

    if not secret:
        return jsonify({'error': 'Secret is required'}), 400

    # For web demo, user_id is implicit or not strictly tracked per secret
    success, message = mixer.deposit("web_user", secret)
    status = 200 if success else 400
    return jsonify({'message': message, 'success': success, 'commitment': mixer.commitments.get(secret) if success else None}), status

@app.route('/withdraw', methods=['POST'])
def api_withdraw():
    data = request.get_json()
    secret = data.get('secret')

    if not secret:
        return jsonify({'error': 'Secret is required'}), 400

    success, message = mixer.withdraw(secret) # User_id removed from here
    status = 200 if success else 400
    return jsonify({'message': message, 'success': success}), status

@app.route('/status', methods=['GET'])
def api_get_status():
    status_data = mixer.get_system_status()
    return jsonify(status_data), 200

@app.route('/commitments', methods=['GET'])
def api_get_commitments():
    return jsonify({'commitments': mixer.commitment_pool}), 200


# --- Command Line Interface (CLI) ---
def run_cli():
    """Provides a simple command-line interface to interact with the AnonMixer."""
    user_data = {} # To store {user_id: secret} for easy testing

    print("\n--- AnonMixer CLI ---")
    print("Welcome to the Privacy-Preserving Transaction System (Tornado Cash Inspired)")

    # Simulate some initial deposits for a richer anonymity set
    print("\n[INIT] Simulating initial deposits for the anonymity pool...")
    for i in range(3):
        user_id = f"init_user_{i+1}"
        secret = generate_random_secret()
        success, message = mixer.deposit(user_id, secret) # CLI still uses user_id
        if success:
            user_data[user_id] = secret
        time.sleep(0.1) # Small delay for readability

    while True:
        print("\n--- Menu ---")
        print("1. Deposit Funds (CLI)")
        print("2. Withdraw Funds (CLI)")
        print("3. View System Status (CLI)")
        print("4. Add more initial pool users (for anonymity) (CLI)")
        print("5. Exit CLI")
        choice = input("Enter your choice: ")

        if choice == '1':
            user_id = input("Enter your User ID (e.g., 'Alice', 'Bob'): ")
            secret = generate_random_secret() # Generate new secret for deposit
            success, message = mixer.deposit(user_id, secret)
            if success:
                user_data[user_id] = secret # Store for later withdrawal
                print(f"Success: {message}")
            else:
                print(f"Failed: {message}")

        elif choice == '2':
            user_id = input("Enter your User ID to withdraw: ")
            if user_id not in user_data:
                print(f"Error: No deposit found for user '{user_id}'. Please deposit first.")
                continue
            secret = user_data[user_id] # Retrieve secret for withdrawal
            success, message = mixer.withdraw(secret) # CLI withdrawal now also uses just secret
            if success:
                print(f"Success: {message}")
                del user_data[user_id] # Remove user from active users after withdrawal
            else:
                print(f"Failed: {message}")

        elif choice == '3':
            status = mixer.get_system_status()
            print("\n--- Current System Status ---")
            print(f"Total Commitments in Pool: {status['total_commitments_in_pool']}")
            print(f"Current Merkle Root: {status['merkle_root']}")
            print(f"Used Nullifiers Count: {status['used_nullifiers_count']}")
            print(f"Sample Commitments: {status['commitments_sample']}")
            print(f"Sample Used Nullifiers: {status['nullifiers_sample']}")
            print(f"\nTransaction Log (latest):")
            for log_entry in status['transaction_log']:
                print(f"- {log_entry}")

        elif choice == '4':
            num_new_users = int(input("How many additional initial users to add to pool? "))
            for i in range(num_new_users):
                user_id = f"sim_user_cli_{len(user_data) + i + 1}"
                secret = generate_random_secret()
                success, message = mixer.deposit(user_id, secret) # CLI still uses user_id for demo
                if success:
                    user_data[user_id] = secret
                time.sleep(0.05)
            print(f"Added {num_new_users} simulated CLI users to the anonymity pool.")

        elif choice == '5':
            print("Exiting AnonMixer CLI. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# --- Main execution block ---
if __name__ == "__main__":
    print("Select run mode:")
    print("1. Run Web UI (Flask App)")
    print("2. Run CLI")
    mode_choice = input("Enter your choice (1 or 2): ")

    if mode_choice == '1':
        # Simulate initial deposits for the web UI's anonymity pool
        print("\n[WEB INIT] Simulating initial deposits for the web UI anonymity pool...")
        for i in range(5): # More initial users for better web demo
            secret = generate_random_secret()
            mixer.deposit(f"web_init_user_{i+1}", secret)
            time.sleep(0.1)

        print("\nStarting Flask web server...")
        print("Open your browser to http://127.0.0.1:5000")
        app.run(debug=True, port=5000)
    elif mode_choice == '2':
        run_cli()
    else:
        print("Invalid mode choice. Exiting.")