import argparse
import os
import requests


def check_mfa_status_https(username, password):
    """Port 443 (HTTPS) ROPC Authentication ကို သုံးပြီး MFA Status စစ်ဆေးခြင်း။

    Basic Auth SMTP အစား Modern Auth Endpoint သို့ Request ပို့သည့်အတွက်
    Connection Closed Timeouts များ မဖြစ်တော့ပါ။
    """
    # Microsoft Public OAuth2 Endpoint (Common Tenant)
    url = "https://login.microsoftonline.com/common/oauth2/token"

    payload = {
        "grant_type": "password",
        "resource": "https://graph.microsoft.com",
        "client_id": "1b7311cd-0542-4465-b510-9a8ff844b784",  # Native PowerShell Public App ID
        "username": username,
        "password": password,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(url, data=payload, timeout=10)
        data = response.json()

        if "access_token" in data:
            # Token ရရှိပါက MFA မဖွင့်ရသေးပါ (သို့မဟုတ်) MFA/Conditional Access Disable ဖြစ်နေပါသည်
            return "SUCCESS (No MFA Required / Password Valid)"

        elif "error" in data:
            error_code = data.get("error_codes", [])
            error_desc = data.get("error_description", "")

            # AADSTS50076 / AADSTS50079: User must use multi-factor authentication
            if (
                50076 in error_code
                or 50079 in error_code
                or "multi-factor authentication" in error_desc.lower()
            ):
                return "MFA ENABLED / ENFORCED"
            # AADSTS50126: Invalid credentials
            elif 50126 in error_code:
                return "FAILED (Invalid Password)"
            # AADSTS53003: Access blocked by Conditional Access policies
            elif 53003 in error_code:
                return "BLOCKED (Conditional Access Policy / MFA Enforced)"
            else:
                return (
                    f"FAILED ({data.get('error')}: {error_code})"
                )

    except requests.exceptions.RequestException as e:
        return f"ERROR (Network Error: {str(e)})"


def main():
    parser = argparse.ArgumentParser(
        description="Check O365 MFA status via HTTPS OAuth Endpoint."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to input text file"
    )
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] File not found: {args.file}")
        return

    print(f"[*] Processing accounts via HTTPS (Port 443)...")
    print(f"[*] Target File: {args.file}\n")
    print(f"{'DOMAIN':<20} | {'FULL EMAIL (UPN)':<35} | {'STATUS'}")
    print("-" * 80)

    with open(args.file, "r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line or ":" not in line:
                continue

            parts = line.split(":")
            if len(parts) < 3:
                continue

            domain = parts[0].strip()
            raw_username = parts[1].strip()
            password = ":".join(parts[2:]).strip()

            if "@" not in raw_username:
                full_username = f"{raw_username}@{domain}"
            else:
                full_username = raw_username

            status = check_mfa_status_https(full_username, password)
            print(f"{domain:<20} | {full_username:<35} | {status}")


if __name__ == "__main__":
    main()
