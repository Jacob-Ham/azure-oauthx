from flask import Flask, render_template, request, jsonify, session
import secrets
import hashlib
import base64
import urllib.parse
import requests
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Predefined working authentication profiles
AUTH_PROFILES = {
    "Device Registration": {
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "redirect_uri": "https://login.microsoftonline.com/applebroker/msauth",
        "scope": "openid profile offline_access urn:ms-drs:enterpriseregistration.windows.net/.default",
        "resource_name": "Device Registration",
        "response_mode": "fragment",
    },
    "Azure CLI (localhost)": {
        "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        "redirect_uri": "http://localhost",
        "scope": "openid profile offline_access https://graph.microsoft.com/.default",
        "resource_name": "Microsoft Graph",
        "response_mode": "query",
    },
    "Azure PowerShell (localhost)": {
        "client_id": "1950a258-227b-4e31-a9cf-717495945fc2",
        "redirect_uri": "http://localhost",
        "scope": "openid profile offline_access https://graph.microsoft.com/.default",
        "resource_name": "Microsoft Graph",
        "response_mode": "query",
    },
}


def generate_pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


@app.route("/")
def index():
    return render_template("index.html", profiles=AUTH_PROFILES)


@app.route("/generate-url", methods=["POST"])
def generate_url():
    data = request.get_json()
    profile_name = data.get("profile")
    force_login = data.get("force_login", False)
    require_mfa = data.get("require_mfa", False)

    if not profile_name or profile_name not in AUTH_PROFILES:
        return jsonify({"error": "Invalid profile selected"}), 400

    profile = AUTH_PROFILES[profile_name]

    verifier, challenge = generate_pkce()
    session["code_verifier"] = verifier
    session["client_id"] = profile["client_id"]
    session["redirect_uri"] = profile["redirect_uri"]
    session["scope"] = profile["scope"]
    session["response_mode"] = profile.get("response_mode", "fragment")

    params = {
        "client_id": profile["client_id"],
        "response_type": "code",
        "redirect_uri": profile["redirect_uri"],
        "scope": profile["scope"],
        "response_mode": profile.get("response_mode", "fragment"),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    if force_login:
        params["prompt"] = "login"

    if require_mfa:
        claims = {"access_token": {"amr": {"values": ["mfa"]}}}
        params["claims"] = json.dumps(claims, separators=(",", ":"))

    auth_url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        + urllib.parse.urlencode(params)
    )

    return jsonify(
        {"auth_url": auth_url, "code_verifier": verifier, "code_challenge": challenge}
    )


@app.route("/exchange", methods=["POST"])
def exchange():
    data = request.get_json()
    callback_url = data.get("callback_url")

    if not callback_url:
        return jsonify({"error": "Missing callback URL"}), 400

    code = None
    callback_url = callback_url.strip()

    # Check if it's a raw authorization code (no URL structure)
    if (
        not callback_url.startswith(("http://", "https://", "microsoft-edge://"))
        and len(callback_url) > 20
    ):
        # Looks like a raw code
        code = callback_url
    else:
        # First check for fragment (response_mode=fragment)
        if "#code=" in callback_url:
            fragment = callback_url.split("#code=")[1]
            code = fragment.split("&")[0]
        # Then check for query parameter (response_mode=query)
        elif "?code=" in callback_url or "&code=" in callback_url:
            # Extract from query string
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(callback_url)
            params = parse_qs(parsed.query)
            if "code" in params:
                code = params["code"][0]
            elif "code=" in callback_url:
                code = callback_url.split("code=")[1].split("&")[0]

    if not code:
        return jsonify(
            {
                "error": "No authorization code found. Paste either the full callback URL or just the authorization code."
            }
        ), 400

    verifier = session.get("code_verifier")
    client_id = session.get("client_id")
    redirect_uri = session.get("redirect_uri")
    scope = session.get("scope")

    if not verifier or not client_id:
        return jsonify({"error": "Session expired. Please generate a new URL."}), 400

    token_data = {
        "client_id": client_id,
        "scope": scope,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }

    try:
        response = requests.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data=token_data,
        )
        response.raise_for_status()
        tokens = response.json()

        return jsonify(
            {
                "access_token": tokens.get("access_token"),
                "refresh_token": tokens.get("refresh_token"),
                "expires_in": tokens.get("expires_in"),
                "token_type": tokens.get("token_type"),
                "scope": tokens.get("scope"),
            }
        )
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Token exchange failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=9090)
