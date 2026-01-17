import math
import os
import random
import string
import hashlib
import re
from datetime import datetime, timedelta

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty",
    "abc123", "password1"
}

ALLOWED_SPECIALS = "!@#$%^&*"

# ---------------- ENTROPY CALCULATION ----------------
def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in ALLOWED_SPECIALS for c in password):
        charset += len(ALLOWED_SPECIALS)

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

def classify_entropy(entropy):
    score = min(100, int(entropy))
    if score < 40:
        return "Weak", score
    elif score < 60:
        return "Moderate", score
    else:
        return "Strong", score

def explain_strength(password, strength):
    reasons = []
    if len(password) < 8:
        reasons.append("Too short (less than 8 characters).")
    if password.isalpha():
        reasons.append("Only letters used.")
    if password.isdigit():
        reasons.append("Only digits used.")
    if not any(c.isupper() for c in password):
        reasons.append("Missing uppercase letters.")
    if not any(c in ALLOWED_SPECIALS for c in password):
        reasons.append(f"Missing special characters ({ALLOWED_SPECIALS}).")

    if not reasons:
        return "Password has good length and character diversity."
    return " ".join(reasons)

def estimate_crack_time(entropy):
    guesses = 2 ** entropy
    guesses_per_second = 1e10
    seconds = guesses / guesses_per_second
    return str(timedelta(seconds=int(seconds)))

# ---------------- PATTERN CHECKS ----------------
def has_patterns(password):
    patterns = ["1234", "abcd", "qwerty", "1111"]
    for p in patterns:
        if p in password.lower():
            return True
    if re.search(r"(.)\1{2,}", password):
        return True
    return False

def contains_personal_info(password, context_data):
    for item in context_data:
        if item.lower() in password.lower():
            return True
    return False

# ---------------- PASSWORD GENERATOR ----------------
def generate_strong_password(length=14):
    chars = string.ascii_letters + string.digits + ALLOWED_SPECIALS
    return "".join(random.choice(chars) for _ in range(length))

# ---------------- SINGLE PASSWORD ANALYSIS ----------------
def save_password_analysis(password, context_data):
    entropy = calculate_entropy(password)
    strength, score = classify_entropy(entropy)
    crack_time = estimate_crack_time(entropy)
    explanation = explain_strength(password, strength)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = [
        f"--- Password Analysis Report ({now}) ---",
        f"Context Info: {' | '.join(context_data) if context_data else 'N/A'}",
        f"Password: {'*' * len(password)}",
        f"Entropy: {entropy} bits",
        f"Strength: {strength} ({score}/100)",
        f"Estimated Crack Time: {crack_time}",
        f"Reason: {explanation}"
    ]

    if password in COMMON_PASSWORDS:
        result.append("[!] Warning: Commonly used password.")
    if has_patterns(password):
        result.append("[!] Warning: Predictable pattern detected.")
    if contains_personal_info(password, context_data):
        result.append("[!] Warning: Personal information detected.")

    if strength != "Strong":
        result.append(f"[+] Suggested Strong Password: {generate_strong_password()}")

    with open("password.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(result))

    print("\n".join(result))
    print("\n[✓] Analysis saved to password.txt")

# ---------------- FILE SCAN ----------------
def scan_password_file(filepath, context_data, redact=False, encrypt=False):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = f.readlines()

        seen_hashes = set()
        report = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report.append(f"--- Password File Scan Report ({now}) ---")
        report.append(f"File Scanned: {filepath}")
        report.append(f"Context Info: {' | '.join(context_data) if context_data else 'N/A'}\n")

        for pw in passwords:
            pw = pw.strip()
            if not pw:
                continue

            hash_pw = hashlib.sha256(pw.encode()).hexdigest()
            duplicate = hash_pw in seen_hashes
            seen_hashes.add(hash_pw)

            entropy = calculate_entropy(pw)
            strength, score = classify_entropy(entropy)
            crack_time = estimate_crack_time(entropy)

            display_pw = "******" if redact else (hash_pw if encrypt else pw)

            report.extend([
                f"Password: {display_pw}",
                f"Strength: {strength} ({score}/100)",
                f"Entropy: {entropy} bits",
                f"Estimated Crack Time: {crack_time}"
            ])

            if duplicate:
                report.append("[!] Duplicate password detected.")
            if pw in COMMON_PASSWORDS:
                report.append("[!] Common password warning.")
            if has_patterns(pw):
                report.append("[!] Pattern detected.")
            if contains_personal_info(pw, context_data):
                report.append("[!] Personal info detected.")
            if strength != "Strong":
                report.append(f"[+] Suggested Strong Password: {generate_strong_password()}")

            report.append("-" * 60)

        output_file = "passwords_report.txt"
        with open(output_file, "w", encoding="utf-8") as rf:
            rf.write("\n".join(report))

        print(f"\n[✓] File scan report saved to {output_file}")

    except Exception as e:
        print(f"[!] Error: {e}")

# ---------------- MAIN MENU ----------------
def main():
    context_data = []
    print("Optional: Enter your name, email, or birthdate (press Enter to skip)")
    user_input = input("Context Info: ").strip()
    if user_input:
        context_data = re.split(r"\W+", user_input)

    while True:
        print("\n--- Password Strength Tool ---")
        print("1. Check a password")
        print("2. Scan a password file")
        print("3. Generate strong password")
        print("4. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            pw = input("Enter password: ").strip()
            save_password_analysis(pw, context_data)

        elif choice == "2":
            path = input("Enter password file path: ").strip()
            redact = input("Redact passwords? (y/n): ").lower().startswith("y")
            encrypt = input("Encrypt passwords? (y/n): ").lower().startswith("y")
            scan_password_file(path, context_data, redact, encrypt)

        elif choice == "3":
            print("[✓] Generated Strong Password:", generate_strong_password())

        elif choice == "4":
            print("Exiting tool...")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
