/**
 * scan_secrets:
 * Scanner for leaked API keys, access tokens, private key headers, and JWTs.
 *
 * Each credential format has a distinctive fixed prefix (e.g. "AKIA",
 * "ghp_", "-----BEGIN ... PRIVATE KEY-----"), so this scanner locates
 * candidate matches with sbuf_t::find() and then validates the shape of
 * the token that follows (length and character set, and for JWTs the
 * base64url-decoded header) before recording it.
 */

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#include "config.h"
#include "scan_secrets.h"

#include "base64_forensic.h"
#include "be20_api/scanner_params.h"

namespace {

bool is_alnum_c(uint8_t c) { return std::isalnum(c) != 0; }
bool is_upper_alnum_c(uint8_t c) { return std::isupper(c) || std::isdigit(c); }
bool is_base64url_c(uint8_t c) { return std::isalnum(c) || c == '-' || c == '_'; }
bool is_slack_c(uint8_t c) { return std::isalnum(c) || c == '-'; }
bool is_ghfg_c(uint8_t c) { return std::isalnum(c) || c == '_'; }

/* A candidate is only reported if it is not embedded in a longer run of
 * identifier-like characters; this avoids matching a fixed prefix that
 * happens to appear in the middle of some longer token. */
bool word_boundary_before(const sbuf_t &sbuf, size_t start) {
    if (start == 0) return true;
    uint8_t c = sbuf[start - 1];
    return !(is_alnum_c(c) || c == '_' || c == '-');
}

std::string decode_base64url(const std::string &s) {
    std::string std_b64 = s;
    for (auto &c : std_b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (std_b64.size() % 4 != 0) std_b64.push_back('=');
    std::vector<unsigned char> out(std_b64.size() + 4);
    int n = b64_pton_forensic(std_b64.c_str(), std_b64.size(), out.data(), out.size());
    if (n <= 0) return std::string();
    return std::string(reinterpret_cast<char *>(out.data()), n);
}

} // namespace

bool valid_aws_access_key_id(const char *buf, size_t len) {
    static const char *prefixes[] = {"AKIA", "ABIA", "ACCA", "ASIA", "AGPA", "AIDA",
                                      "AROA", "AIPA", "ANPA", "ANVA", "APKA", "ASCA", nullptr};
    if (len != 20) return false;
    bool prefix_ok = false;
    for (int i = 0; prefixes[i]; i++) {
        if (std::memcmp(buf, prefixes[i], 4) == 0) {
            prefix_ok = true;
            break;
        }
    }
    if (!prefix_ok) return false;
    for (size_t i = 4; i < 20; i++) {
        if (!is_upper_alnum_c(static_cast<uint8_t>(buf[i]))) return false;
    }
    return true;
}

bool valid_github_classic_token(const char *buf, size_t len) {
    static const char *prefixes[] = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", nullptr};
    if (len != 40) return false;
    bool prefix_ok = false;
    for (int i = 0; prefixes[i]; i++) {
        if (std::memcmp(buf, prefixes[i], 4) == 0) {
            prefix_ok = true;
            break;
        }
    }
    if (!prefix_ok) return false;
    for (size_t i = 4; i < 40; i++) {
        if (!is_alnum_c(static_cast<uint8_t>(buf[i]))) return false;
    }
    return true;
}

bool valid_github_fine_grained_token(const char *buf, size_t len) {
    static const char prefix[] = "github_pat_";
    static const size_t prefix_len = 11;
    if (len != 93) return false;
    if (std::memcmp(buf, prefix, prefix_len) != 0) return false;
    for (size_t i = prefix_len; i < len; i++) {
        if (!is_ghfg_c(static_cast<uint8_t>(buf[i]))) return false;
    }
    return true;
}

bool valid_google_api_key(const char *buf, size_t len) {
    if (len != 39) return false;
    if (std::memcmp(buf, "AIza", 4) != 0) return false;
    for (size_t i = 4; i < 39; i++) {
        uint8_t c = static_cast<uint8_t>(buf[i]);
        if (!(is_alnum_c(c) || c == '-' || c == '_')) return false;
    }
    return true;
}

bool valid_stripe_key(const char *buf, size_t len) {
    static const char *prefixes[] = {"sk_live_", "sk_test_", "pk_live_",
                                      "pk_test_", "rk_live_", nullptr};
    static const size_t prefix_len = 8;
    if (len < prefix_len + 24) return false;
    bool prefix_ok = false;
    for (int i = 0; prefixes[i]; i++) {
        if (std::memcmp(buf, prefixes[i], prefix_len) == 0) {
            prefix_ok = true;
            break;
        }
    }
    if (!prefix_ok) return false;
    for (size_t i = prefix_len; i < len; i++) {
        if (!is_alnum_c(static_cast<uint8_t>(buf[i]))) return false;
    }
    return true;
}

bool valid_slack_token(const char *buf, size_t len) {
    static const char *prefixes[] = {"xoxb-", "xoxa-", "xoxp-", "xoxr-",
                                      "xoxs-", "xoxo-", "xoxe-", nullptr};
    static const size_t prefix_len = 5;
    if (len < prefix_len + 15) return false;
    bool prefix_ok = false;
    for (int i = 0; prefixes[i]; i++) {
        if (std::memcmp(buf, prefixes[i], prefix_len) == 0) {
            prefix_ok = true;
            break;
        }
    }
    if (!prefix_ok) return false;
    int hyphens = 0;
    for (size_t i = prefix_len; i < len; i++) {
        uint8_t c = static_cast<uint8_t>(buf[i]);
        if (!is_slack_c(c)) return false;
        if (c == '-') hyphens++;
    }
    return hyphens >= 2; // Slack tokens are dash-delimited into several fields
}

bool valid_jwt(const char *buf, size_t len) {
    std::string token(buf, len);
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return false;
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    if (token.find('.', dot2 + 1) != std::string::npos) return false; // exactly 3 segments

    std::string header = token.substr(0, dot1);
    std::string payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string signature = token.substr(dot2 + 1);

    if (header.size() < 10 || payload.size() < 4) return false;

    auto all_b64url = [](const std::string &s) {
        return std::all_of(s.begin(), s.end(), [](char c) { return is_base64url_c(static_cast<uint8_t>(c)); });
    };
    if (!all_b64url(header) || !all_b64url(payload) || !all_b64url(signature)) return false;

    std::string header_json = decode_base64url(header);
    std::string payload_json = decode_base64url(payload);
    if (header_json.empty() || header_json[0] != '{') return false;
    if (payload_json.empty() || payload_json[0] != '{') return false;
    if (header_json.find("\"alg\"") == std::string::npos) return false;

    return true;
}

namespace {

size_t run_length(const sbuf_t &sbuf, size_t start, bool (*pred)(uint8_t), size_t max_len) {
    size_t n = 0;
    while (n < max_len && start + n < sbuf.bufsize && pred(sbuf[start + n])) n++;
    return n;
}

/* Search for every occurrence of a fixed-length credential format: a literal
 * prefix immediately followed by a fixed number of additional characters. */
void scan_fixed_length(const sbuf_t &sbuf, feature_recorder &secrets_recorder, const char *prefix,
                        size_t total_len, bool (*validator)(const char *, size_t), const char *type) {
    ssize_t pos = 0;
    while ((pos = sbuf.find(prefix, pos)) >= 0) {
        size_t start = static_cast<size_t>(pos);
        if (start + total_len > sbuf.bufsize) {
            pos = start + 1;
            continue;
        }
        std::string candidate = sbuf.substr(start, total_len);
        bool after_ok = (start + total_len >= sbuf.bufsize) || !is_alnum_c(sbuf[start + total_len]);
        if (after_ok && word_boundary_before(sbuf, start) && validator(candidate.data(), candidate.size())) {
            secrets_recorder.write(sbuf.pos0 + start, candidate, type);
        }
        pos = start + 1;
    }
}

/* Search for every occurrence of a variable-length credential format: a
 * literal prefix followed by a maximal run of characters from a charset. */
void scan_variable_length(const sbuf_t &sbuf, feature_recorder &secrets_recorder, const char *prefix,
                           bool (*pred)(uint8_t), size_t max_body, bool (*validator)(const char *, size_t),
                           const char *type) {
    const size_t prefix_len = std::strlen(prefix);
    ssize_t pos = 0;
    while ((pos = sbuf.find(prefix, pos)) >= 0) {
        size_t start = static_cast<size_t>(pos);
        size_t body_len = run_length(sbuf, start + prefix_len, pred, max_body);
        size_t total_len = prefix_len + body_len;
        std::string candidate = sbuf.substr(start, total_len);
        if (word_boundary_before(sbuf, start) && validator(candidate.data(), candidate.size())) {
            secrets_recorder.write(sbuf.pos0 + start, candidate, type);
        }
        pos = start + 1;
    }
}

void scan_jwt(const sbuf_t &sbuf, feature_recorder &secrets_recorder) {
    const size_t max_segment = 4096;
    ssize_t pos = 0;
    while ((pos = sbuf.find("eyJ", pos)) >= 0) {
        size_t start = static_cast<size_t>(pos);
        size_t header_len = run_length(sbuf, start, is_base64url_c, max_segment);
        size_t off = start + header_len;
        if (off >= sbuf.bufsize || sbuf[off] != '.') { pos = start + 1; continue; }
        off++;
        size_t payload_len = run_length(sbuf, off, is_base64url_c, max_segment);
        off += payload_len;
        if (off >= sbuf.bufsize || sbuf[off] != '.') { pos = start + 1; continue; }
        off++;
        size_t sig_len = run_length(sbuf, off, is_base64url_c, max_segment);
        off += sig_len;

        size_t total_len = off - start;
        std::string candidate = sbuf.substr(start, total_len);
        if (word_boundary_before(sbuf, start) && valid_jwt(candidate.data(), candidate.size())) {
            secrets_recorder.write(sbuf.pos0 + start, candidate, "jwt");
        }
        pos = start + 1;
    }
}

void scan_pem_headers(const sbuf_t &sbuf, feature_recorder &secrets_recorder) {
    static const char *headers[] = {"-----BEGIN RSA PRIVATE KEY-----",
                                     "-----BEGIN DSA PRIVATE KEY-----",
                                     "-----BEGIN EC PRIVATE KEY-----",
                                     "-----BEGIN OPENSSH PRIVATE KEY-----",
                                     "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                                     "-----BEGIN PRIVATE KEY-----",
                                     nullptr};
    for (int i = 0; headers[i]; i++) {
        ssize_t pos = 0;
        while ((pos = sbuf.find(headers[i], pos)) >= 0) {
            size_t start = static_cast<size_t>(pos);
            secrets_recorder.write(sbuf.pos0 + start, headers[i], "private_key_header");
            pos = start + 1;
        }
    }
}

} // namespace

extern "C"
void scan_secrets(scanner_params &sp)
{
    sp.check_version();
    if (sp.phase == scanner_params::PHASE_INIT) {
        sp.info->set_name("secrets");
        sp.info->author = "bulk_extractor contributors";
        sp.info->description = "Scans for leaked API keys, access tokens, private key headers, and JWTs";
        sp.info->scanner_version = "1.0";
        sp.info->feature_defs.push_back(feature_recorder_def("secrets"));

        histogram_def::flags_t nf;
        sp.info->histogram_defs.push_back(histogram_def("secrets", "secrets", "", "", "histogram", nf));
        return;
    }

    if (sp.phase == scanner_params::PHASE_SCAN) {
        const sbuf_t &sbuf = *sp.sbuf;
        feature_recorder &secrets_recorder = sp.named_feature_recorder("secrets");

        scan_fixed_length(sbuf, secrets_recorder, "AKIA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ABIA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ACCA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ASIA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "AGPA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "AIDA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "AROA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "AIPA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ANPA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ANVA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "APKA", 20, valid_aws_access_key_id, "aws_access_key_id");
        scan_fixed_length(sbuf, secrets_recorder, "ASCA", 20, valid_aws_access_key_id, "aws_access_key_id");

        scan_fixed_length(sbuf, secrets_recorder, "ghp_", 40, valid_github_classic_token, "github_token");
        scan_fixed_length(sbuf, secrets_recorder, "gho_", 40, valid_github_classic_token, "github_token");
        scan_fixed_length(sbuf, secrets_recorder, "ghu_", 40, valid_github_classic_token, "github_token");
        scan_fixed_length(sbuf, secrets_recorder, "ghs_", 40, valid_github_classic_token, "github_token");
        scan_fixed_length(sbuf, secrets_recorder, "ghr_", 40, valid_github_classic_token, "github_token");
        scan_fixed_length(sbuf, secrets_recorder, "github_pat_", 93, valid_github_fine_grained_token,
                           "github_token");

        scan_fixed_length(sbuf, secrets_recorder, "AIza", 39, valid_google_api_key, "google_api_key");

        scan_variable_length(sbuf, secrets_recorder, "sk_live_", is_alnum_c, 128, valid_stripe_key, "stripe_key");
        scan_variable_length(sbuf, secrets_recorder, "sk_test_", is_alnum_c, 128, valid_stripe_key, "stripe_key");
        scan_variable_length(sbuf, secrets_recorder, "pk_live_", is_alnum_c, 128, valid_stripe_key, "stripe_key");
        scan_variable_length(sbuf, secrets_recorder, "pk_test_", is_alnum_c, 128, valid_stripe_key, "stripe_key");
        scan_variable_length(sbuf, secrets_recorder, "rk_live_", is_alnum_c, 128, valid_stripe_key, "stripe_key");

        scan_variable_length(sbuf, secrets_recorder, "xoxb-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxa-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxp-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxr-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxs-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxo-", is_slack_c, 256, valid_slack_token, "slack_token");
        scan_variable_length(sbuf, secrets_recorder, "xoxe-", is_slack_c, 256, valid_slack_token, "slack_token");

        scan_jwt(sbuf, secrets_recorder);
        scan_pem_headers(sbuf, secrets_recorder);
    }
}
