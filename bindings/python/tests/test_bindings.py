"""Tests for ows Python bindings."""

import tempfile
import json
from pathlib import Path
import pytest
import ows

STELLAR_FIXTURE = json.loads(
    Path(__file__).resolve().parents[3]
    .joinpath("testdata/stellar/auth_entry_external_ed25519.json")
    .read_text()
)
STELLAR_TX_FIXTURE = json.loads(
    Path(__file__).resolve().parents[3]
    .joinpath("testdata/stellar/transaction_v1_ed25519.json")
    .read_text()
)


@pytest.fixture
def vault_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_mnemonic_12():
    phrase = ows.generate_mnemonic(12)
    assert len(phrase.split()) == 12


def test_generate_mnemonic_24():
    phrase = ows.generate_mnemonic(24)
    assert len(phrase.split()) == 24


def test_derive_address_evm():
    phrase = ows.generate_mnemonic(12)
    # "evm" still works via backward compat
    address = ows.derive_address(phrase, "evm")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_ethereum():
    phrase = ows.generate_mnemonic(12)
    address = ows.derive_address(phrase, "ethereum")
    assert address.startswith("0x")
    assert len(address) == 42


def test_create_and_list_wallets(vault_dir):
    wallet = ows.create_wallet("test-wallet", vault_path_opt=vault_dir)
    assert wallet["name"] == "test-wallet"
    assert isinstance(wallet["accounts"], list)
    assert len(wallet["accounts"]) == 9

    # Verify each chain family is present
    chain_ids = [a["chain_id"] for a in wallet["accounts"]]
    assert any(c.startswith("eip155:") for c in chain_ids)
    assert any(c.startswith("solana:") for c in chain_ids)
    assert any(c.startswith("stellar:") for c in chain_ids)
    assert any(c.startswith("sui:") for c in chain_ids)
    assert any(c.startswith("bip122:") for c in chain_ids)
    assert any(c.startswith("cosmos:") for c in chain_ids)
    assert any(c.startswith("tron:") for c in chain_ids)
    assert any(c.startswith("ton:") for c in chain_ids)
    assert any(c.startswith("fil:") for c in chain_ids)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 1
    assert wallets[0]["id"] == wallet["id"]

def test_get_wallet(vault_dir):
    wallet = ows.create_wallet("lookup", vault_path_opt=vault_dir)

    found = ows.get_wallet("lookup", vault_path_opt=vault_dir)
    assert found["id"] == wallet["id"]

    found = ows.get_wallet(wallet["id"], vault_path_opt=vault_dir)
    assert found["name"] == "lookup"


def test_rename_wallet(vault_dir):
    ows.create_wallet("old-name", vault_path_opt=vault_dir)
    ows.rename_wallet("old-name", "new-name", vault_path_opt=vault_dir)

    found = ows.get_wallet("new-name", vault_path_opt=vault_dir)
    assert found["name"] == "new-name"


def test_export_wallet(vault_dir):
    ows.create_wallet("exportable", vault_path_opt=vault_dir)
    secret = ows.export_wallet("exportable", vault_path_opt=vault_dir)
    assert len(secret.split()) == 12


def test_delete_wallet(vault_dir):
    wallet = ows.create_wallet("deletable", vault_path_opt=vault_dir)
    ows.delete_wallet("deletable", vault_path_opt=vault_dir)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 0


def test_import_wallet_mnemonic(vault_dir):
    phrase = ows.generate_mnemonic(12)
    expected_addr = ows.derive_address(phrase, "ethereum")

    wallet = ows.import_wallet_mnemonic(
        "imported", phrase, vault_path_opt=vault_dir
    )
    assert wallet["name"] == "imported"
    assert len(wallet["accounts"]) == 9

    # EVM account should match derived address
    evm_account = next(a for a in wallet["accounts"] if a["chain_id"].startswith("eip155:"))
    assert evm_account["address"] == expected_addr


def test_sign_transaction(vault_dir):
    ows.create_wallet("signer", vault_path_opt=vault_dir)

    tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    result = ows.sign_transaction(
        "signer", "evm", tx_hex, vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None


def test_sign_transaction_stellar(vault_dir):
    ows.import_wallet_private_key(
        "stellar-signer",
        STELLAR_TX_FIXTURE["private_key_hex"],
        chain="stellar",
        vault_path_opt=vault_dir,
    )

    result = ows.sign_transaction(
        "stellar-signer",
        STELLAR_TX_FIXTURE["chain_id"],
        STELLAR_TX_FIXTURE["envelope_xdr_hex"],
        vault_path_opt=vault_dir,
    )
    assert result["signature"] == STELLAR_TX_FIXTURE["signature_hex"]
    assert result["recovery_id"] is None


def test_sign_message(vault_dir):
    ows.create_wallet("msg-signer", vault_path_opt=vault_dir)

    result = ows.sign_message(
        "msg-signer", "evm", "hello world", vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0


def test_sign_auth_entry(vault_dir):
    ows.import_wallet_private_key(
        "stellar-auth",
        STELLAR_FIXTURE["private_key_hex"],
        chain="stellar",
        vault_path_opt=vault_dir,
    )

    result = ows.sign_auth_entry(
        "stellar-auth",
        "stellar:testnet",
        STELLAR_FIXTURE["preimage_xdr_base64"],
        vault_path_opt=vault_dir,
    )
    assert result["address"] == STELLAR_FIXTURE["signer_g_address"]
    assert result["public_key"] == STELLAR_FIXTURE["public_key_hex"]
    assert result["payload_hash"] == STELLAR_FIXTURE["payload_hash_hex"]
    assert result["signature"] == STELLAR_FIXTURE["signature_hex"]


def test_sign_auth_entry_rejects_chain_mismatch(vault_dir):
    ows.import_wallet_private_key(
        "stellar-auth-mismatch",
        STELLAR_FIXTURE["private_key_hex"],
        chain="stellar",
        vault_path_opt=vault_dir,
    )

    with pytest.raises(Exception, match="network_id does not match requested Stellar chain"):
        ows.sign_auth_entry(
            "stellar-auth-mismatch",
            "stellar:pubnet",
            STELLAR_FIXTURE["preimage_xdr_base64"],
            vault_path_opt=vault_dir,
        )


def test_sign_auth_entry_with_api_key(vault_dir):
    wallet = ows.create_wallet("stellar-auth-token", vault_path_opt=vault_dir)

    ows.create_policy(
        json.dumps(
            {
                "id": "test-stellar-auth-only",
                "name": "Stellar Auth Only",
                "version": 1,
                "created_at": "2026-03-24T00:00:00Z",
                "rules": [
                    {
                        "type": "allowed_chains",
                        "chain_ids": ["stellar:pubnet", "stellar:testnet"],
                    }
                ],
                "action": "deny",
            }
        ),
        vault_path_opt=vault_dir,
    )

    key = ows.create_api_key(
        "stellar-auth-agent",
        [wallet["id"]],
        ["test-stellar-auth-only"],
        "",
        vault_path_opt=vault_dir,
    )

    result = ows.sign_auth_entry(
        wallet["id"],
        "stellar:testnet",
        STELLAR_FIXTURE["preimage_xdr_base64"],
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )

    owner_result = ows.sign_auth_entry(
        wallet["id"],
        "stellar:testnet",
        STELLAR_FIXTURE["preimage_xdr_base64"],
        vault_path_opt=vault_dir,
    )

    assert result["address"] == owner_result["address"]
    assert result["public_key"] == owner_result["public_key"]
    assert result["payload_hash"] == owner_result["payload_hash"]
    assert result["signature"] == owner_result["signature"]

    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("test-stellar-auth-only", vault_path_opt=vault_dir)


def test_sign_transaction_stellar_with_api_key(vault_dir):
    wallet = ows.create_wallet("stellar-tx-token", vault_path_opt=vault_dir)

    ows.create_policy(
        json.dumps(
            {
                "id": "test-stellar-tx-only",
                "name": "Stellar Tx Only",
                "version": 1,
                "created_at": "2026-03-25T00:00:00Z",
                "rules": [
                    {
                        "type": "allowed_chains",
                        "chain_ids": ["stellar:testnet"],
                    }
                ],
                "action": "deny",
            }
        ),
        vault_path_opt=vault_dir,
    )

    key = ows.create_api_key(
        "stellar-tx-agent",
        [wallet["id"]],
        ["test-stellar-tx-only"],
        "",
        vault_path_opt=vault_dir,
    )

    owner_result = ows.sign_transaction(
        wallet["id"],
        STELLAR_TX_FIXTURE["chain_id"],
        STELLAR_TX_FIXTURE["envelope_xdr_hex"],
        vault_path_opt=vault_dir,
    )

    token_result = ows.sign_transaction(
        wallet["id"],
        STELLAR_TX_FIXTURE["chain_id"],
        STELLAR_TX_FIXTURE["envelope_xdr_hex"],
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )

    assert token_result["signature"] == owner_result["signature"]
    assert token_result["recovery_id"] == owner_result["recovery_id"]

    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("test-stellar-tx-only", vault_path_opt=vault_dir)
