/**
 * scan_wallets.h:
 * Header file for the cryptocurrency wallet-address scanner.
 *
 * Each validator takes the full candidate token text and returns whether
 * it is a structurally and, where possible, cryptographically valid
 * address (checksum verified). Where a format doesn't uniquely name a
 * single coin, the matched variant is written to type_out. These are
 * exposed here so they can be unit tested directly.
 */

#ifndef SCAN_WALLETS_H
#define SCAN_WALLETS_H

#include <cstddef>
#include <string>

// Bitcoin-family Base58Check addresses: Bitcoin, Litecoin, Dogecoin, Dash,
// Tron, and Zcash transparent addresses. All use SHA256d checksums.
bool valid_base58check_wallet(const char *buf, size_t len, std::string &type_out);

// Ripple (XRP) classic addresses: Base58Check with Ripple's own alphabet.
bool valid_ripple_address(const char *buf, size_t len);

// Ethereum and other EVM-compatible chain addresses: "0x" + 40 hex chars.
// checksum_verified is set when the mixed-case EIP-55 checksum matches;
// a uniformly-cased address is still format-valid but unverified.
bool valid_evm_address(const char *buf, size_t len, bool &checksum_verified);

// Monero standard/integrated/subaddresses: CryptoNote block-based Base58
// with a Keccak-256 checksum.
bool valid_monero_address(const char *buf, size_t len, std::string &type_out);

// Bitcoin/Litecoin native SegWit (Bech32) and Taproot (Bech32m) addresses.
bool valid_segwit_address(const char *buf, size_t len, std::string &type_out);

// Other Bech32-based chain addresses (Cosmos SDK chains, Cardano Shelley),
// validated by checksum only since they have no witness-version structure.
bool valid_generic_bech32_address(const char *buf, size_t len, std::string &type_out);

#endif // SCAN_WALLETS_H
