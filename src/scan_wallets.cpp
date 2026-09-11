/**
 * scan_wallets:
 * Scanner for cryptocurrency wallet addresses.
 *
 * Supports, with full checksum/structure validation rather than bare
 * pattern matching:
 *   - Bitcoin, Litecoin, Dogecoin, Dash, Tron, Zcash (t-addr): Base58Check
 *     addresses (SHA256d checksum).
 *   - Ripple (XRP) classic addresses: Base58Check with Ripple's own
 *     base58 alphabet.
 *   - Bitcoin/Litecoin native SegWit (Bech32) and Taproot (Bech32m).
 *   - Cosmos-SDK chains and Cardano Shelley addresses: Bech32 (checksum
 *     only; these formats have no witness-version structure to check).
 *   - Ethereum and other EVM-compatible chains: "0x" + 40 hex chars,
 *     with EIP-55 mixed-case checksum verification via Keccak-256.
 *   - Monero standard/integrated/subaddresses: CryptoNote block-based
 *     Base58 with a Keccak-256 checksum.
 *
 * Base58-alphabet formats have no fixed prefix marker, so this scanner
 * finds maximal runs of address-alphabet characters anchored at a word
 * boundary and tries each format's decoder/checksum at the lengths that
 * format can produce. Ethereum-style and Bech32 addresses have literal
 * markers ("0x", "bc1", ...) that are located directly.
 */

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#include "config.h"
#include "scan_wallets.h"

#include "dfxml_cpp/src/hash_t.h"
#include "be20_api/scanner_params.h"

namespace {

/* ---------------------------------------------------------------------
 * Shared character-class helpers
 * ------------------------------------------------------------------- */

bool is_alnum_c(uint8_t c) { return std::isalnum(c) != 0; }
bool is_hex_c(uint8_t c) { return std::isxdigit(c) != 0; }

/* The Bitcoin/Ripple/Monero base58 alphabets are all permutations of the
 * same 58-character SET (digits and letters minus 0, O, I, l), so a
 * single predicate identifies candidate runs for all three. */
bool is_base58_c(uint8_t c) {
    if (c == '0' || c == 'O' || c == 'I' || c == 'l') return false;
    return is_alnum_c(c);
}

bool is_bech32_data_c(uint8_t c) {
    // Case-sensitive: the scanner only searches for lowercase HRP prefixes
    // (see scan_bech32_family), and bech32_decode() rejects mixed case anyway.
    return std::strchr("qpzry9x8gf2tvdw0s3jn54khce6mua7l", static_cast<char>(c)) != nullptr;
}

bool word_boundary_before(const sbuf_t &sbuf, size_t start) {
    if (start == 0) return true;
    uint8_t c = sbuf[start - 1];
    return !(is_alnum_c(c) || c == '_' || c == '-');
}

size_t run_length(const sbuf_t &sbuf, size_t start, bool (*pred)(uint8_t), size_t max_len) {
    size_t n = 0;
    while (n < max_len && start + n < sbuf.bufsize && pred(sbuf[start + n])) n++;
    return n;
}

/* ---------------------------------------------------------------------
 * Generic base58 (big-integer style, as used by Bitcoin-family coins
 * and Ripple; Monero uses a different, block-based scheme below).
 * ------------------------------------------------------------------- */

bool base58_decode(const char *alphabet, const char *s, size_t len, uint8_t *out, size_t outlen) {
    int vals[256];
    std::memset(vals, -1, sizeof(vals));
    for (size_t i = 0; alphabet[i]; i++) vals[static_cast<unsigned char>(alphabet[i])] = static_cast<int>(i);
    std::memset(out, 0, outlen);
    for (size_t i = 0; i < len; i++) {
        int c = vals[static_cast<unsigned char>(s[i])];
        if (c == -1) return false;
        for (size_t j = outlen; j-- > 0;) {
            c += 58 * out[j];
            out[j] = static_cast<uint8_t>(c % 256);
            c /= 256;
        }
        if (c != 0) return false; // decoded value too large for outlen
    }
    return true;
}

const char *BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char *RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

bool sha256d_matches(const uint8_t *payload, size_t payload_len, const uint8_t *checksum4) {
    dfxml::sha256_t d1 = dfxml::sha256_generator::hash_buf(payload, payload_len);
    dfxml::sha256_t d2 = dfxml::sha256_generator::hash_buf(d1.digest, d1.size());
    return std::memcmp(checksum4, d2.digest, 4) == 0;
}

/* ---------------------------------------------------------------------
 * Keccak-256 (the "original" Keccak used by Ethereum and Monero; this
 * differs from NIST SHA3-256 only in the padding domain-separator
 * byte). Verified against the NIST SHA3-256 known-answer test (with
 * domain 0x06) and all four EIP-55 worked examples (with domain 0x01).
 * ------------------------------------------------------------------- */

const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
const int keccakf_rotc[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                               27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
const int keccakf_piln[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

uint64_t rotl64(uint64_t x, int y) { return (x << y) | (x >> (64 - y)); }

void keccakf(uint64_t st[25]) {
    uint64_t bc[5], t;
    for (int round = 0; round < 24; round++) {
        for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = rotl64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= keccakf_rndc[round];
    }
}

uint64_t load64_le(const uint8_t *b) {
    uint64_t r = 0;
    for (int i = 7; i >= 0; i--) r = (r << 8) | b[i];
    return r;
}
void store64_le(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) { b[i] = static_cast<uint8_t>(v & 0xff); v >>= 8; }
}

void keccak256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint64_t st[25];
    std::memset(st, 0, sizeof(st));
    const size_t rate = 136; // 1088-bit rate for a 256-bit capacity/output
    std::vector<uint8_t> temp(rate);
    while (len >= rate) {
        for (size_t i = 0; i < rate / 8; i++) st[i] ^= load64_le(data + i * 8);
        keccakf(st);
        data += rate;
        len -= rate;
    }
    std::fill(temp.begin(), temp.end(), 0);
    std::memcpy(temp.data(), data, len);
    temp[len] = 0x01; // original-Keccak domain separator (SHA3 uses 0x06)
    temp[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate / 8; i++) st[i] ^= load64_le(temp.data() + i * 8);
    keccakf(st);
    for (size_t i = 0; i < 4; i++) store64_le(out + i * 8, st[i]);
}

/* ---------------------------------------------------------------------
 * Bech32 / Bech32m (BIP-173 / BIP-350). Verified by round-tripping
 * encode/decode across many HRPs, payload lengths and both encodings,
 * confirming 100% single-character-corruption detection, and by
 * decoding real Bitcoin SegWit v0 and Taproot address structures.
 * ------------------------------------------------------------------- */

const char *BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const uint32_t BECH32M_CONST = 0x2bc830a3;

uint32_t bech32_polymod(const std::vector<uint8_t> &values) {
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t b = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; i++)
            if ((b >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

std::vector<uint8_t> bech32_hrp_expand(const std::string &hrp) {
    std::vector<uint8_t> ret;
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) >> 5);
    ret.push_back(0);
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) & 31);
    return ret;
}

enum bech_encoding_t { BECH_NONE, BECH_32, BECH_32M };

struct bech32_decoded_t {
    bool ok;
    std::string hrp;
    std::vector<uint8_t> data; // 5-bit groups, checksum stripped
    bech_encoding_t encoding;
};

bech32_decoded_t bech32_decode(const std::string &s, size_t max_len) {
    bech32_decoded_t r{false, std::string(), std::vector<uint8_t>(), BECH_NONE};
    if (s.size() < 8 || s.size() > max_len) return r;
    bool has_lower = false, has_upper = false;
    for (unsigned char c : s) {
        if (c < 33 || c > 126) return r;
        if (std::islower(c)) has_lower = true;
        if (std::isupper(c)) has_upper = true;
    }
    if (has_lower && has_upper) return r; // mixed case is invalid
    std::string lower = s;
    for (auto &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    size_t pos = lower.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > lower.size()) return r;
    std::string hrp = lower.substr(0, pos);
    std::string data_part = lower.substr(pos + 1);
    std::vector<uint8_t> data;
    for (char c : data_part) {
        const char *p = std::strchr(BECH32_CHARSET, c);
        if (!p) return r;
        data.push_back(static_cast<uint8_t>(p - BECH32_CHARSET));
    }
    std::vector<uint8_t> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t polymod = bech32_polymod(values);
    std::vector<uint8_t> payload(data.begin(), data.end() - 6);
    if (polymod == 1) { r = {true, hrp, payload, BECH_32}; return r; }
    if (polymod == BECH32M_CONST) { r = {true, hrp, payload, BECH_32M}; return r; }
    return r;
}

/* Repack 5-bit groups into 8-bit bytes, as used to recover a SegWit
 * witness program. Returns false if the padding bits are non-zero or
 * too wide (per BIP-173). */
bool convertbits_5to8(const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
    int acc = 0, bits = 0;
    for (uint8_t v : in) {
        if (v >> 5) return false;
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) return false;
    return true;
}

/* ---------------------------------------------------------------------
 * Monero's CryptoNote base58: data is encoded in 8-byte blocks (each
 * producing 11 base58 characters), with a final short block for any
 * remainder. Uses the same 58-character alphabet as Bitcoin, but not
 * the same encoding scheme. Verified against the well-known Monero
 * project donation address (69-byte payload, network byte 18,
 * Keccak-256 checksum matches exactly).
 * ------------------------------------------------------------------- */

const int MONERO_FULL_BLOCK_SIZE = 8;
const int MONERO_FULL_ENCODED_BLOCK_SIZE = 11;
const int monero_encoded_block_sizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
const uint64_t monero_block_upper_bound[9] = {
    0ULL, 0xFFULL, 0xFFFFULL, 0xFFFFFFULL, 0xFFFFFFFFULL,
    0xFFFFFFFFFFULL, 0xFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

int monero_b58_val(char c) {
    const char *p = std::strchr(BTC_ALPHABET, c);
    return p ? static_cast<int>(p - BTC_ALPHABET) : -1;
}

bool monero_decode_block(const char *enc, int enc_len, uint8_t *out, int raw_len) {
    uint64_t value = 0;
    uint64_t order = 1;
    for (int i = enc_len - 1; i >= 0; i--) {
        int digit = monero_b58_val(enc[i]);
        if (digit < 0) return false;
        __uint128_t v = static_cast<__uint128_t>(value) + static_cast<__uint128_t>(digit) * order;
        if (v > monero_block_upper_bound[raw_len]) return false;
        value = static_cast<uint64_t>(v);
        if (i > 0) order *= 58;
    }
    for (int i = raw_len - 1; i >= 0; i--) {
        out[i] = value & 0xff;
        value >>= 8;
    }
    return true;
}

bool monero_base58_decode(const char *s, size_t len, std::vector<uint8_t> &out) {
    size_t full_blocks = len / MONERO_FULL_ENCODED_BLOCK_SIZE;
    size_t last_enc_len = len % MONERO_FULL_ENCODED_BLOCK_SIZE;
    int last_raw_len = -1;
    for (int i = 0; i < 9; i++)
        if (monero_encoded_block_sizes[i] == static_cast<int>(last_enc_len)) { last_raw_len = i; break; }
    if (last_raw_len < 0) return false;
    out.assign(full_blocks * MONERO_FULL_BLOCK_SIZE + last_raw_len, 0);
    for (size_t i = 0; i < full_blocks; i++) {
        if (!monero_decode_block(s + i * MONERO_FULL_ENCODED_BLOCK_SIZE, MONERO_FULL_ENCODED_BLOCK_SIZE,
                                  out.data() + i * MONERO_FULL_BLOCK_SIZE, MONERO_FULL_BLOCK_SIZE))
            return false;
    }
    if (last_enc_len > 0) {
        if (!monero_decode_block(s + full_blocks * MONERO_FULL_ENCODED_BLOCK_SIZE,
                                  static_cast<int>(last_enc_len),
                                  out.data() + full_blocks * MONERO_FULL_BLOCK_SIZE, last_raw_len))
            return false;
    }
    return true;
}

} // namespace

/* ---------------------------------------------------------------------
 * Public validators
 * ------------------------------------------------------------------- */

bool valid_base58check_wallet(const char *buf, size_t len, std::string &type_out) {
    // Group 1: 1-byte version + 20-byte hash160 + 4-byte checksum.
    if (len >= 25 && len <= 35) {
        uint8_t dec[25];
        if (base58_decode(BTC_ALPHABET, buf, len, dec, 25) && sha256d_matches(dec, 21, dec + 21)) {
            switch (dec[0]) {
                case 0x00: type_out = "bitcoin_p2pkh"; return true;
                case 0x05: type_out = "bitcoin_p2sh"; return true;
                case 0x30: type_out = "litecoin_p2pkh"; return true;
                case 0x32: type_out = "litecoin_p2sh"; return true;
                case 0x1E: type_out = "dogecoin_p2pkh"; return true;
                case 0x16: type_out = "dogecoin_p2sh"; return true;
                case 0x4C: type_out = "dash_p2pkh"; return true;
                case 0x10: type_out = "dash_p2sh"; return true;
                case 0x41: type_out = "tron"; return true;
                default: break;
            }
        }
    }
    // Group 2: Zcash transparent addresses use a 2-byte version prefix.
    if (len >= 33 && len <= 37) {
        uint8_t dec[26];
        if (base58_decode(BTC_ALPHABET, buf, len, dec, 26) && sha256d_matches(dec, 22, dec + 22)) {
            if (dec[0] == 0x1C && dec[1] == 0xB8) { type_out = "zcash_t1"; return true; }
            if (dec[0] == 0x1C && dec[1] == 0xBD) { type_out = "zcash_t3"; return true; }
        }
    }
    return false;
}

bool valid_ripple_address(const char *buf, size_t len) {
    if (len < 25 || len > 35) return false;
    if (buf[0] != 'r') return false; // Ripple's version byte 0 always encodes to a leading 'r'
    uint8_t dec[25];
    if (!base58_decode(RIPPLE_ALPHABET, buf, len, dec, 25)) return false;
    if (dec[0] != 0x00) return false;
    return sha256d_matches(dec, 21, dec + 21);
}

bool valid_evm_address(const char *buf, size_t len, bool &checksum_verified) {
    checksum_verified = false;
    if (len != 42 || buf[0] != '0' || buf[1] != 'x') return false;
    bool has_lower = false, has_upper = false;
    for (size_t i = 2; i < 42; i++) {
        uint8_t c = static_cast<uint8_t>(buf[i]);
        if (!is_hex_c(c)) return false;
        if (std::isupper(c)) has_upper = true;
        if (std::islower(c)) has_lower = true;
    }
    if (!(has_lower && has_upper)) return true; // uniformly-cased: valid format, unverified
    std::string lower(buf + 2, 40);
    for (auto &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    uint8_t hash[32];
    keccak256(reinterpret_cast<const uint8_t *>(lower.data()), lower.size(), hash);
    for (size_t i = 0; i < 40; i++) {
        char c = lower[i];
        if (!std::isalpha(static_cast<unsigned char>(c))) continue;
        uint8_t nibble = (i % 2 == 0) ? (hash[i / 2] >> 4) : (hash[i / 2] & 0xf);
        bool should_upper = nibble >= 8;
        bool is_upper = std::isupper(static_cast<unsigned char>(buf[2 + i])) != 0;
        if (should_upper != is_upper) return false; // checksum mismatch
    }
    checksum_verified = true;
    return true;
}

bool valid_monero_address(const char *buf, size_t len, std::string &type_out) {
    if (len != 95 && len != 106) return false;
    std::vector<uint8_t> dec;
    if (!monero_base58_decode(buf, len, dec)) return false;
    if (dec.size() < 5) return false;
    size_t payload_len = dec.size() - 4;
    uint8_t hash[32];
    keccak256(dec.data(), payload_len, hash);
    if (std::memcmp(dec.data() + payload_len, hash, 4) != 0) return false;
    if (dec.size() == 69) {
        if (dec[0] == 18) { type_out = "monero_standard"; return true; }
        if (dec[0] == 42) { type_out = "monero_subaddress"; return true; }
    } else if (dec.size() == 77) {
        if (dec[0] == 19) { type_out = "monero_integrated"; return true; }
    }
    return false;
}

bool valid_segwit_address(const char *buf, size_t len, std::string &type_out) {
    std::string s(buf, len);
    auto r = bech32_decode(s, 90); // BIP-173 caps the total length at 90
    if (!r.ok) return false;
    std::string coin;
    if (r.hrp == "bc") coin = "bitcoin";
    else if (r.hrp == "ltc") coin = "litecoin";
    else return false;
    if (r.data.empty()) return false;
    uint8_t witness_version = r.data[0];
    if (witness_version > 16) return false;
    std::vector<uint8_t> program;
    std::vector<uint8_t> rest;
    rest.reserve(r.data.size() - 1);
    for (size_t i = 1; i < r.data.size(); i++) rest.push_back(r.data[i]);
    if (!convertbits_5to8(rest, program)) return false;
    if (program.size() < 2 || program.size() > 40) return false;
    if (witness_version == 0) {
        if (r.encoding != BECH_32) return false;
        if (program.size() != 20 && program.size() != 32) return false;
        type_out = coin + "_segwit";
    } else {
        if (r.encoding != BECH_32M) return false;
        type_out = coin + "_taproot";
    }
    return true;
}

bool valid_generic_bech32_address(const char *buf, size_t len, std::string &type_out) {
    std::string s(buf, len);
    auto r = bech32_decode(s, 150); // some chains (e.g. Cardano Shelley) exceed BIP-173's 90-char cap
    if (!r.ok || r.encoding != BECH_32) return false;
    if (r.data.size() < 6) return false; // implausibly short payload
    if (r.hrp == "cosmos") { type_out = "cosmos"; return true; }
    if (r.hrp == "osmo") { type_out = "osmosis"; return true; }
    if (r.hrp == "terra") { type_out = "terra"; return true; }
    if (r.hrp == "bnb") { type_out = "binance_chain"; return true; }
    if (r.hrp == "addr") { type_out = "cardano_shelley"; return true; }
    return false;
}

/* ---------------------------------------------------------------------
 * Scanner
 * ------------------------------------------------------------------- */

namespace {

/* Keywords that suggest nearby text is actually discussing a crypto
 * wallet/address, used to gate unverified (uniformly-cased) EVM
 * addresses: "0x" + 40 hex chars alone is far too common in source
 * code, memory dumps, and hex output to report without this. */
bool has_wallet_context(const sbuf_t &sbuf, size_t pos, size_t range = 80) {
    static const char *keywords[] = {
        "eth", "ethereum", "wallet", "address", "metamask", "erc20", "erc-20",
        "bsc", "bnb chain", "polygon", "matic", "avalanche", "arbitrum",
        "optimism", "wei", "gwei", nullptr};
    size_t start = (pos > range) ? pos - range : 0;
    size_t end = std::min(pos + range, sbuf.bufsize);
    std::string context = sbuf.substr(start, end - start);
    std::transform(context.begin(), context.end(), context.begin(), ::tolower);
    for (int i = 0; keywords[i]; i++) {
        if (context.find(keywords[i]) != std::string::npos) return true;
    }
    return false;
}

void scan_base58_family(const sbuf_t &sbuf, feature_recorder &wallets_recorder) {
    size_t i = 0;
    while (i < sbuf.bufsize) {
        if (!is_base58_c(sbuf[i]) || !word_boundary_before(sbuf, i)) { i++; continue; }
        size_t run = run_length(sbuf, i, is_base58_c, 120);

        for (size_t l = 25; l <= std::min<size_t>(35, run); l++) {
            std::string cand = sbuf.substr(i, l);
            std::string type;
            if (valid_base58check_wallet(cand.data(), cand.size(), type)) {
                bool after_ok = (i + l >= sbuf.bufsize) || !is_base58_c(sbuf[i + l]);
                if (after_ok) wallets_recorder.write(sbuf.pos0 + i, cand, type);
            }
            if (sbuf[i] == 'r' && valid_ripple_address(cand.data(), cand.size())) {
                bool after_ok = (i + l >= sbuf.bufsize) || !is_base58_c(sbuf[i + l]);
                if (after_ok) wallets_recorder.write(sbuf.pos0 + i, cand, "ripple");
            }
        }
        for (size_t l = 33; l <= std::min<size_t>(37, run); l++) {
            std::string cand = sbuf.substr(i, l);
            std::string type;
            if (valid_base58check_wallet(cand.data(), cand.size(), type)) {
                bool after_ok = (i + l >= sbuf.bufsize) || !is_base58_c(sbuf[i + l]);
                if (after_ok) wallets_recorder.write(sbuf.pos0 + i, cand, type);
            }
        }
        for (size_t l : {95UL, 106UL}) {
            if (l > run) continue;
            std::string cand = sbuf.substr(i, l);
            std::string type;
            if (valid_monero_address(cand.data(), cand.size(), type)) {
                bool after_ok = (i + l >= sbuf.bufsize) || !is_base58_c(sbuf[i + l]);
                if (after_ok) wallets_recorder.write(sbuf.pos0 + i, cand, type);
            }
        }
        i += (run > 0) ? run : 1;
    }
}

void scan_evm(const sbuf_t &sbuf, feature_recorder &wallets_recorder) {
    ssize_t pos = 0;
    while ((pos = sbuf.find("0x", pos)) >= 0) {
        size_t start = static_cast<size_t>(pos);
        if (start + 42 > sbuf.bufsize) { pos = start + 1; continue; }
        std::string cand = sbuf.substr(start, 42);
        bool checksum_verified = false;
        bool after_ok = (start + 42 >= sbuf.bufsize) || !is_hex_c(sbuf[start + 42]);
        if (after_ok && word_boundary_before(sbuf, start) &&
            valid_evm_address(cand.data(), cand.size(), checksum_verified)) {
            if (checksum_verified || has_wallet_context(sbuf, start)) {
                wallets_recorder.write(sbuf.pos0 + start, cand,
                                        checksum_verified ? "evm_checksummed" : "evm_address");
            }
        }
        pos = start + 1;
    }
}

void scan_bech32_family(const sbuf_t &sbuf, feature_recorder &wallets_recorder) {
    static const char *prefixes[] = {"bc1", "ltc1", "cosmos1", "osmo1", "terra1", "bnb1", "addr1", nullptr};
    for (int p = 0; prefixes[p]; p++) {
        const char *prefix = prefixes[p];
        size_t prefix_len = std::strlen(prefix);
        ssize_t pos = 0;
        while ((pos = sbuf.find(prefix, pos)) >= 0) {
            size_t start = static_cast<size_t>(pos);
            size_t data_len = run_length(sbuf, start + prefix_len, is_bech32_data_c, 140);
            size_t total_len = prefix_len + data_len;
            if (word_boundary_before(sbuf, start)) {
                std::string cand = sbuf.substr(start, total_len);
                std::string type;
                if (valid_segwit_address(cand.data(), cand.size(), type) ||
                    valid_generic_bech32_address(cand.data(), cand.size(), type)) {
                    wallets_recorder.write(sbuf.pos0 + start, cand, type);
                }
            }
            pos = start + 1;
        }
    }
}

} // namespace

extern "C"
void scan_wallets(scanner_params &sp)
{
    sp.check_version();
    if (sp.phase == scanner_params::PHASE_INIT) {
        sp.info->set_name("wallets");
        sp.info->author = "bulk_extractor contributors";
        sp.info->description = "Scans for cryptocurrency wallet addresses (Bitcoin-family, "
                                "Ethereum/EVM, Ripple, Monero, and Bech32-based chains)";
        sp.info->scanner_version = "1.0";
        sp.info->feature_defs.push_back(feature_recorder_def("wallets"));

        histogram_def::flags_t nf;
        sp.info->histogram_defs.push_back(histogram_def("wallets", "wallets", "", "", "histogram", nf));
        return;
    }

    if (sp.phase == scanner_params::PHASE_SCAN) {
        const sbuf_t &sbuf = *sp.sbuf;
        feature_recorder &wallets_recorder = sp.named_feature_recorder("wallets");

        scan_base58_family(sbuf, wallets_recorder);
        scan_evm(sbuf, wallets_recorder);
        scan_bech32_family(sbuf, wallets_recorder);
    }
}
