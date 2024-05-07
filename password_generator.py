import argparse
import random
import string

def generate_password(length, uppercase=False, lowercase=False, digits=False, special=False):
    """
    Generate a random password based on specified length and complexity.

    Parameters:
    length (int): Length of the password.
    uppercase (bool): Include uppercase letters.
    lowercase (bool): Include lowercase letters.
    digits (bool): Include digits.
    special (bool): Include special characters.

    Returns:
    str: Generated password.
    """
    characters = ''
    if uppercase:
        characters += string.ascii_uppercase
    if lowercase:
        characters += string.ascii_lowercase
    if digits:
        characters += string.digits
    if special:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one option among --uppercase, --lowercase, --digits, --special must be selected.")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    parser = argparse.ArgumentParser(description="Random Password Generator")
    parser.add_argument("--length", type=int, required=True, help="Length of the password")
    parser.add_argument("--uppercase", action="store_true", help="Include uppercase letters")
    parser.add_argument("--lowercase", action="store_true", help="Include lowercase letters")
    parser.add_argument("--digits", action="store_true", help="Include digits")
    parser.add_argument("--special", action="store_true", help="Include special characters")
    args = parser.parse_args()

    try:
        password = generate_password(args.length, args.uppercase, args.lowercase, args.digits, args.special)
        print("Generated Password:", password)
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
