/**
 * scan_secrets.h:
 * Header file for the secrets/credentials scanner.
 *
 * Each validator takes the full candidate token text (including any
 * fixed prefix, e.g. "AKIA...") and returns whether it matches the
 * shape of a real credential closely enough to be worth reporting.
 * These are exposed here so they can be unit tested directly.
 */

#ifndef SCAN_SECRETS_H
#define SCAN_SECRETS_H

#include <cstddef>

bool valid_aws_access_key_id(const char *buf, size_t len);
bool valid_github_classic_token(const char *buf, size_t len);
bool valid_github_fine_grained_token(const char *buf, size_t len);
bool valid_google_api_key(const char *buf, size_t len);
bool valid_stripe_key(const char *buf, size_t len);
bool valid_slack_token(const char *buf, size_t len);
bool valid_jwt(const char *buf, size_t len);

#endif // SCAN_SECRETS_H
