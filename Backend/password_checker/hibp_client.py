import hashlib
import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def check_pwned_password(password: str) -> int:
    """
    Check if a password appears in the HIBP Pwned Passwords database.

    Returns:
        -1  -> API error (we could not check the password)
         0  -> password not found in HIBP
        >0  -> number of times the password appeared in breaches
    """
    if not password:
        return 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    headers = {
        "User-Agent": "SentinelAI-PasswordChecker/1.0",
        "Add-Padding": "true",
    }

    try:
        response = requests.get(
            HIBP_RANGE_URL + prefix,
            headers=headers,
            timeout=5,
        )
    except requests.RequestException:
        return -1

    if response.status_code != 200:
        return -1

    for line in response.text.splitlines():
        try:
            hash_suffix, count_str = line.split(":")
        except ValueError:
            continue

        if hash_suffix == suffix:
            try:
                return int(count_str)
            except ValueError:
                return -1

    return 0
