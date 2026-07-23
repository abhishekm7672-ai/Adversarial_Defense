"""
db/generate_seed_hashes.py
===========================
Run once to generate sha256_crypt hashes for the seed users,
then paste the output into schema.sql.

Usage:
    python db/generate_seed_hashes.py
"""

from passlib.hash import sha256_crypt

USERS = {
    "admin":   "navigo-admin-2026",
    "analyst": "navigo-analyst-2026",
}

print("-- Paste these UPDATE statements into psql after applying schema.sql:\n")
for username, password in USERS.items():
    hashed = sha256_crypt.hash(password)
    print(f"UPDATE users SET password_hash = '{hashed}'")
    print(f"  WHERE username = '{username}';\n")

print("-- Or use the INSERT values directly in schema.sql SEED DATA section.")