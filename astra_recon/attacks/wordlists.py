import os
from typing import List, Optional

# Top common WordPress passwords frequently tested in penetration tests
COMMON_WORDPRESS_PASSWORDS = [
    "admin",
    "password",
    "123456",
    "admin123",
    "12345678",
    "password123",
    "1234",
    "welcome",
    "pass@123",
    "toor",
    "root",
    "wordpress",
    "wp-admin",
    "qwerty",
    "letmein",
    "admin2024",
    "admin2023",
    "iloveyou",
    "princess",
    "dragon",
]


def load_wordlist(filepath: Optional[str] = None, limit: int = 15) -> List[str]:
    """
    Loads passwords from a custom wordlist file or falls back to
    top curated common WordPress passwords.
    """
    if filepath and os.path.isfile(filepath):
        passwords: List[str] = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pwd = line.strip()
                if pwd and pwd not in passwords:
                    passwords.append(pwd)
                if len(passwords) >= limit:
                    break
        return passwords

    return COMMON_WORDPRESS_PASSWORDS[:limit]
