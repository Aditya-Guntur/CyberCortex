#!/usr/bin/env python3
"""
Fetch.ai Wallet Creation Script for CyberCortex

This script creates a Fetch.ai wallet and generates the credentials
needed for your CyberCortex project.
"""

import os
import json
from pathlib import Path
from uagents.crypto import Identity
from uagents.setup import fund_agent_if_low, get_ledger
import asyncio

def create_wallet():
    """Create a new Fetch.ai wallet and save credentials"""
    
    print("🔐 Creating Fetch.ai wallet for CyberCortex...")
    
    # Create a new identity (wallet)
    identity = Identity.generate()
    
    # Get wallet details
    wallet_address = str(identity.address)
    private_key = identity.private_key  # Already a hex string
    
    print(f"\n✅ Wallet created successfully!")
    print(f"📧 Wallet Address: {wallet_address}")
    print(f"🔑 Private Key: {private_key}")
    
    # Create credentials directory
    creds_dir = Path("credentials")
    creds_dir.mkdir(exist_ok=True)
    
    # Save credentials to file
    credentials = {
        "wallet_address": wallet_address,
        "private_key": private_key,
        "network": "testnet"  # Start with testnet for development
    }
    
    creds_file = creds_dir / "fetchai_credentials.json"
    with open(creds_file, 'w') as f:
        json.dump(credentials, f, indent=2)
    
    print(f"\n💾 Credentials saved to: {creds_file}")
    
    # Create .env file content
    env_content = f"""# Fetch.ai Configuration\nFETCHAI_AGENT_ADDRESS={wallet_address}\nFETCHAI_PRIVATE_KEY={private_key}\nFETCHAI_NETWORK=testnet\n"""
    
    env_file = Path(".env")
    if env_file.exists():
        # Append to existing .env file
        with open(env_file, 'a') as f:
            f.write(f"\n# Fetch.ai Configuration\n")
            f.write(f"FETCHAI_AGENT_ADDRESS={wallet_address}\n")
            f.write(f"FETCHAI_PRIVATE_KEY={private_key}\n")
            f.write(f"FETCHAI_NETWORK=testnet\n")
        print(f"📝 Added Fetch.ai credentials to existing .env file")
    else:
        # Create new .env file
        with open(env_file, 'w') as f:
            f.write(env_content)
        print(f"📝 Created new .env file with Fetch.ai credentials")
    
    return credentials

async def fund_wallet(wallet_address):
    """Fund the wallet with testnet tokens"""
    try:
        print(f"\n💰 Funding wallet with testnet tokens...")
        
        # Get testnet ledger
        ledger = get_ledger("testnet")
        
        # Fund the wallet
        await fund_agent_if_low(wallet_address)
        
        print("✅ Wallet funded successfully!")
        
    except Exception as e:
        print(f"⚠️  Could not fund wallet automatically: {e}")
        print("💡 You can manually fund your wallet at: https://faucet.fetch.ai/")

def main():
    """Main function to create wallet and fund it"""
    
    print("🚀 Fetch.ai Wallet Setup for CyberCortex")
    print("=" * 50)
    
    # Create wallet
    credentials = create_wallet()
    
    # Fund wallet
    asyncio.run(fund_wallet(credentials["wallet_address"]))
    
    print("\n" + "=" * 50)
    print("🎉 Setup Complete!")
    print("\n📋 Next Steps:")
    print("1. Your credentials are saved in credentials/fetchai_credentials.json")
    print("2. Environment variables are added to .env file")
    print("3. You can now run your CyberCortex agents with Fetch.ai integration")
    print("\n🔒 Security Notes:")
    print("- Keep your private key secure")
    print("- Never commit credentials to version control")
    print("- Start with testnet for development")
    print("\n🌐 Useful Links:")
    print("- Fetch.ai Testnet Faucet: https://faucet.fetch.ai/")
    print("- Fetch.ai Documentation: https://docs.fetch.ai/")
    print("- uAgents Documentation: https://docs.uagents.org/")

if __name__ == "__main__":
    main() 