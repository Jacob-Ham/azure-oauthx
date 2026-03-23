# azure-oauthx

A web-based tool for generating and exchanging Microsoft OAuth tokens using standard OAuth2 flows.
This tool was buit because these OAuth2 authorization codes lasts 1 - 5 minutes, making speed crucial.

## Overview

This application provides a simple interface for generating OAuth authorization URLs and exchanging authorization codes for access tokens. It supports multiple predefined Azure authentication profiles and implements PKCE (Proof Key for Code Exchange) for secure token acquisition.

## Features

- **Multiple Authentication Profiles**: Pre-configured profiles for Azure CLI, Azure PowerShell, and Device Registration
- **PKCE Support**: Implements PKCE for secure authorization flow
- **MFA Support**: Option to require multi-factor authentication (to get a token with the mfa amr)
- **Token Exchange**: Exchange authorization codes for access and refresh tokens
- **JWT Decoding**: Built-in JWT token inspection

## Authentication Profiles

- **Device Registration**: Client ID for Azure device registration service
- **Azure CLI (localhost)**: Client ID for Azure CLI using localhost redirect
- **Azure PowerShell (localhost)**: Client ID for Azure PowerShell using localhost redirect

## Requirements

- Python 3.7+
- Flask
- requests

## Installation

```bash
pip install flask requests
```

## Usage

Start the application:

```bash
python app.py
```

The web interface will be available at `http://localhost:9090`.

### Workflow

1. Select an authentication profile
2. Optionally enable "Force re-auth" or "Require MFA" (again, to strengthen your auth claim so you're less likely to get blocked)
3. Click "Generate Auth URL" to create an authorization URL
4. Visit the URL and complete the sign-in process
5. Copy the callback URL from your browser
6. Paste the URL into the exchange field
7. Click "Exchange for Tokens" to receive access and refresh tokens

Generate URL based on chosen profile:
<img width="826" height="727" alt="image" src="https://github.com/user-attachments/assets/3258569e-8469-4228-aa24-42196de10737" />

Copy URL, auth, copy url.
<img width="1170" height="512" alt="image" src="https://github.com/user-attachments/assets/4b672b41-0e6c-42ee-87a5-a5848f9ddf67" />

Paste url, exchange for tokens.
<img width="894" height="809" alt="image" src="https://github.com/user-attachments/assets/5aa25c50-f484-4823-ac43-a3c2f047beba" />

## Security Notes

- This tool is intended for development and testing purposes
- Tokens are stored in memory only (session-based)
