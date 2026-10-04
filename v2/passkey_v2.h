// WebAuthn assertion checks for the v2 firewall.
//
// The hook recomputes a 53-byte payment payload and requires the WebAuthn
// challenge to be those exact bytes. It then verifies the assertion signature
// over SHA-256(authenticatorData || SHA-256(clientDataJSON)). This header is
// the part that does not call the Hook API, so a host test can compile it.

#ifndef PASSKEY_V2_H
#define PASSKEY_V2_H

#include <stdint.h>

#ifndef GUARD
#error "include hookapi.h first, or define GUARD for a host test"
#endif

#define V2_OK 1
#define V2_ERR_JSON (-1)
#define V2_ERR_CHALLENGE_COUNT (-2)
#define V2_ERR_CHALLENGE (-3)
#define V2_ERR_TYPE (-4)
#define V2_ERR_ORIGIN (-5)
#define V2_ERR_B64 (-6)

#define V2_MAX_AUTH 128
#define V2_MAX_JSON 220
#define V2_MAX_ORIGIN 64
#define V2_MIN_AUTH 37
#define V2_SIG_LEN 64
#define V2_PAYLOAD_LEN 53
#define V2_CHAL_B64 71
#define V2_MAX_BODY (2 + V2_MAX_AUTH + 2 + V2_MAX_JSON + V2_SIG_LEN)
#define V2_SLOT_LEN (2 + V2_MAX_BODY)

#include "passkey_v2_dfa.h"

// "origin":"  — ten bytes, then the stored origin, then a closing quote.
static const uint8_t V2_ORIGIN_PRE[10] = {
    '"', 'o', 'r', 'i', 'g', 'i', 'n', '"', ':', '"'};

static const int8_t V2_B64[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};

static inline __attribute__((always_inline)) int32_t
b64_digit(uint8_t c)
{
    if (c >= 128)
        return -1;
    return V2_B64[c];
}

// 1 and writes prefix length and payload length.
// The buffer must be exactly the XRPL VL encoding of one blob.
static inline __attribute__((always_inline)) int32_t
vl_split(const uint8_t* buf, int32_t buflen, int32_t* prefix, int32_t* plen)
{
    if (buf == 0 || buflen < 1)
        return 0;
    uint8_t b0 = buf[0];
    if (b0 <= 192) {
        if (buflen != 1 + (int32_t)b0)
            return 0;
        *prefix = 1;
        *plen = (int32_t)b0;
        return 1;
    }
    if (b0 <= 240) {
        if (buflen < 2)
            return 0;
        int32_t len = 193 + (((int32_t)b0 - 193) << 8) + (int32_t)buf[1];
        if (len < 0 || buflen != 2 + len)
            return 0;
        *prefix = 2;
        *plen = len;
        return 1;
    }
    return 0;
}

typedef struct v2_view {
    const uint8_t* auth;
    int32_t auth_len;
    const uint8_t* json;
    int32_t json_len;
    const uint8_t* sig;
} v2_view;

// Memo body, after the XRPL length prefix:
//   uint16 BE authenticatorData length
//   authenticatorData (37..128)
//   uint16 BE clientDataJSON length
//   clientDataJSON (1..220)
//   r || s (64)
static inline __attribute__((always_inline)) int32_t
v2_unpack(const uint8_t* raw, int32_t raw_len, v2_view* out)
{
    if (raw == 0 || out == 0 || raw_len < 2 + V2_MIN_AUTH + 2 + 1 + V2_SIG_LEN)
        return 0;
    int32_t auth_len = ((int32_t)raw[0] << 8) | (int32_t)raw[1];
    if (auth_len < V2_MIN_AUTH || auth_len > V2_MAX_AUTH)
        return 0;
    if (raw_len < 2 + auth_len + 2 + V2_SIG_LEN)
        return 0;
    int32_t json_len = ((int32_t)raw[2 + auth_len] << 8) | (int32_t)raw[3 + auth_len];
    if (json_len < 1 || json_len > V2_MAX_JSON)
        return 0;
    if (raw_len != 2 + auth_len + 2 + json_len + V2_SIG_LEN)
        return 0;
    out->auth = raw + 2;
    out->auth_len = auth_len;
    out->json = raw + 2 + auth_len + 2;
    out->json_len = json_len;
    out->sig = out->json + json_len;
    return 1;
}

// Accept compact clientDataJSON, the form browsers emit:
//   exactly one "type":"webauthn.get"
//   exactly one "challenge":"<71 base64url chars>"
//   exactly one "origin":"<origin>" when origin_len > 0
// No spaces and no backslashes. The scan is a byte table so the guarded
// loop stays under the hook instruction ceiling.
static inline __attribute__((always_inline)) int32_t
v2_client_data_ok(
    const uint8_t* json,
    int32_t json_len,
    const uint8_t payload[V2_PAYLOAD_LEN],
    const uint8_t* origin,
    int32_t origin_len)
{
    if (json == 0 || payload == 0 || json_len < 1 || json_len > V2_MAX_JSON)
        return V2_ERR_JSON;
    if (origin_len < 0 || origin_len > V2_MAX_ORIGIN)
        return V2_ERR_ORIGIN;
    if (origin_len > 0 && origin == 0)
        return V2_ERR_ORIGIN;

    uint8_t chal_b64[V2_CHAL_B64];
    uint8_t chal_state = 0;
    uint8_t type_state = 0;
    int32_t origin_state = 0;
    int32_t chal_count = 0;
    int32_t type_count = 0;
    int32_t origin_count = 0;

    for (int32_t i = 0; GUARDM(V2_MAX_JSON, 1), i < json_len; ++i) {
        uint8_t c = json[i];
        if (c < 0x20 || c > 0x7e || c == '\\')
            return V2_ERR_JSON;

        uint32_t tnext = V2_TYPE_DFA[((uint32_t)type_state << 7) + c];
        if (tnext == 21) {
            type_count++;
            tnext = 1;
        }
        type_state = (uint8_t)tnext;

        uint32_t cnext = V2_CHAL_DFA[((uint32_t)chal_state << 7) + c];
        if ((uint32_t)(chal_state - 13) < 71u &&
            cnext == (uint32_t)chal_state + 1u && chal_count == 0)
            chal_b64[chal_state - 13] = c;
        if (cnext == 85) {
            chal_count++;
            cnext = 1;
        }
        chal_state = (uint8_t)cnext;

        if (origin_len > 0) {
            int32_t done = 10 + origin_len;
            int32_t nos = (c == '"');
            if (origin_state < 10) {
                if (c == V2_ORIGIN_PRE[origin_state])
                    nos = origin_state + 1;
            } else if (origin_state < done) {
                if (c == origin[origin_state - 10])
                    nos = origin_state + 1;
            } else if (c == '"') {
                origin_count++;
                nos = 1;
            }
            origin_state = nos;
        }
    }

    if (type_count != 1)
        return V2_ERR_TYPE;
    if (origin_len > 0 && origin_count != 1)
        return V2_ERR_ORIGIN;
    if (chal_count != 1)
        return V2_ERR_CHALLENGE_COUNT;

    uint8_t decoded[V2_PAYLOAD_LEN];
    uint32_t acc = 0;
    int32_t bits = 0;
    int32_t out_i = 0;
    for (int32_t i = 0; GUARDM(V2_CHAL_B64, 2), i < V2_CHAL_B64; ++i) {
        int32_t v = b64_digit(chal_b64[i]);
        if (v < 0)
            return V2_ERR_B64;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_i >= V2_PAYLOAD_LEN)
                return V2_ERR_B64;
            decoded[out_i++] = (uint8_t)((acc >> bits) & 0xFFu);
        }
    }
    if (out_i != V2_PAYLOAD_LEN || bits != 2 || (acc & 0x3u) != 0)
        return V2_ERR_B64;

    for (int32_t i = 0; GUARDM(V2_PAYLOAD_LEN, 3), i < V2_PAYLOAD_LEN; ++i) {
        if (decoded[i] != payload[i])
            return V2_ERR_CHALLENGE;
    }
    return V2_OK;
}

#endif
