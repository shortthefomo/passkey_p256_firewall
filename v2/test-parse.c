// Host checks for passkey_v2.h. build.sh compiles and runs this before the wasm.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GUARD(n) 0
#define GUARDM(n, id) 0
#include "passkey_v2.h"

static int failed = 0;

static void expect_int(const char* name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s got %d want %d\n", name, got, want);
        failed++;
    } else {
        printf("PASS %s\n", name);
    }
}

static int b64url_encode(const uint8_t* in, int n, char* out)
{
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int o = 0;
    int i = 0;
    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = alphabet[(v >> 18) & 63];
        out[o++] = alphabet[(v >> 12) & 63];
        out[o++] = alphabet[(v >> 6) & 63];
        out[o++] = alphabet[v & 63];
        i += 3;
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n)
            v |= (uint32_t)in[i + 1] << 8;
        out[o++] = alphabet[(v >> 18) & 63];
        out[o++] = alphabet[(v >> 12) & 63];
        out[o++] = alphabet[(v >> 6) & 63];
    }
    out[o] = 0;
    return o;
}

static int build_json(
    char* out,
    int cap,
    const uint8_t* payload,
    const char* type,
    const char* origin,
    const char* extra,
    int spaces)
{
    char b64[80];
    if (b64url_encode(payload, V2_PAYLOAD_LEN, b64) != V2_CHAL_B64)
        return -1;
    const char* fmt = spaces
        ? "{\"type\" : \"%s\", \"challenge\" : \"%s\", \"origin\" : \"%s\"%s}"
        : "{\"type\":\"%s\",\"challenge\":\"%s\",\"origin\":\"%s\"%s}";
    int n = snprintf(out, (size_t)cap, fmt, type, b64, origin, extra);
    if (n < 0 || n >= cap)
        return -1;
    return n;
}

int main(void)
{
    uint8_t payload[V2_PAYLOAD_LEN];
    for (int i = 0; i < V2_PAYLOAD_LEN; i++)
        payload[i] = (uint8_t)(i * 3 + 1);
    const char* origin = "https://passkey.xahau-dev.net";
    int origin_len = (int)strlen(origin);
    char json[700];
    int n = build_json(json, (int)sizeof json, payload, "webauthn.get", origin, "", 0);
    expect_int("compact json builds", n > 0, 1);
    expect_int(
        "compact clientData accepted",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_OK);

    int spaced = build_json(json, (int)sizeof json, payload, "webauthn.get", origin, "", 1);
    expect_int(
        "spaces around colons rejected",
        v2_client_data_ok((uint8_t*)json, spaced, payload, (uint8_t*)origin, origin_len),
        V2_ERR_TYPE);

    n = build_json(
        json, (int)sizeof json, payload, "webauthn.get", origin, ",\"crossOrigin\":false", 0);
    expect_int(
        "crossOrigin field accepted",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_OK);

    uint8_t other[V2_PAYLOAD_LEN];
    memcpy(other, payload, sizeof other);
    other[50] ^= 0xff;
    n = build_json(json, (int)sizeof json, payload, "webauthn.get", origin, "", 0);
    expect_int(
        "different payload rejected",
        v2_client_data_ok((uint8_t*)json, n, other, (uint8_t*)origin, origin_len),
        V2_ERR_CHALLENGE);

    n = build_json(json, (int)sizeof json, payload, "webauthn.create", origin, "", 0);
    expect_int(
        "registration type rejected",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_ERR_TYPE);

    n = build_json(json, (int)sizeof json, payload, "webauthn.get", "https://evil.example", "", 0);
    expect_int(
        "wrong origin rejected",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_ERR_ORIGIN);

    n = build_json(
        json, (int)sizeof json, payload, "webauthn.get", "https://passkey.xahau-dev.net.evil", "", 0);
    expect_int(
        "origin prefix rejected",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_ERR_ORIGIN);

    n = build_json(
        json,
        (int)sizeof json,
        payload,
        "webauthn.get",
        origin,
        ",\"topOrigin\":\"https://passkey.xahau-dev.net\"",
        0);
    expect_int(
        "topOrigin does not count as origin",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_OK);

    n = build_json(json, (int)sizeof json, payload, "webauthn.get", origin, ",\"x\":\"a\\\\b\"", 0);
    expect_int(
        "backslash rejected",
        v2_client_data_ok((uint8_t*)json, n, payload, (uint8_t*)origin, origin_len),
        V2_ERR_JSON);

    n = build_json(json, (int)sizeof json, payload, "webauthn.get", origin, "", 0);
    json[n] = (char)0x80;
    expect_int(
        "non-ascii rejected",
        v2_client_data_ok((uint8_t*)json, n + 1, payload, (uint8_t*)origin, origin_len),
        V2_ERR_JSON);

    char b64[80];
    b64url_encode(payload, V2_PAYLOAD_LEN, b64);
    char dup[800];
    const char* short_origin = "https://a.co";
    int dn = snprintf(
        dup,
        sizeof dup,
        "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"challenge\":\"%s\",\"origin\":\"%s\"}",
        b64,
        b64,
        short_origin);
    expect_int(
        "duplicate challenge rejected",
        v2_client_data_ok(
            (uint8_t*)dup, dn, payload, (uint8_t*)short_origin, (int)strlen(short_origin)),
        V2_ERR_CHALLENGE_COUNT);

    b64[70] = 0;
    int shortn = snprintf(
        dup,
        sizeof dup,
        "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"%s\"}",
        b64,
        origin);
    expect_int(
        "short challenge rejected",
        v2_client_data_ok((uint8_t*)dup, shortn, payload, (uint8_t*)origin, origin_len),
        V2_ERR_CHALLENGE_COUNT);

    b64url_encode(payload, V2_PAYLOAD_LEN, b64);
    b64[70] = 'B';
    int badb64 = snprintf(
        dup,
        sizeof dup,
        "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"%s\"}",
        b64,
        origin);
    expect_int(
        "non-canonical base64url rejected",
        v2_client_data_ok((uint8_t*)dup, badb64, payload, (uint8_t*)origin, origin_len),
        V2_ERR_B64);

    uint8_t raw[128];
    memset(raw, 0, sizeof raw);
    raw[0] = 0;
    raw[1] = 37;
    memset(raw + 2, 0xab, 37);
    raw[39] = 0;
    raw[40] = 20;
    memset(raw + 41, 'x', 20);
    memset(raw + 61, 0xcd, 64);
    v2_view view;
    int body_len = 2 + 37 + 2 + 20 + 64;
    expect_int("unpack 37-byte authData", v2_unpack(raw, body_len, &view), 1);
    expect_int("auth length", view.auth_len, 37);
    expect_int("json length", view.json_len, 20);
    expect_int("sig starts after json", view.sig[0], 0xcd);
    expect_int("trailing byte rejected", v2_unpack(raw, body_len + 1, &view), 0);
    raw[1] = 36;
    expect_int("short authenticatorData rejected", v2_unpack(raw, body_len, &view), 0);

    uint8_t blob[302];
    memset(blob, 0x11, sizeof blob);
    blob[0] = 193;
    blob[1] = 107;
    int32_t prefix = 0;
    int32_t plen = 0;
    expect_int("vl 300 splits", vl_split(blob, 302, &prefix, &plen), 1);
    expect_int("vl 300 prefix", prefix, 2);
    expect_int("vl 300 length", plen, 300);

    uint8_t small[65];
    memset(small, 0, sizeof small);
    small[0] = 64;
    expect_int("vl 64 splits", vl_split(small, 65, &prefix, &plen), 1);
    expect_int("vl 64 prefix", prefix, 1);
    expect_int("vl 64 length", plen, 64);
    expect_int("vl length mismatch rejected", vl_split(small, 64, &prefix, &plen), 0);

    if (failed) {
        printf("%d failed\n", failed);
        return 1;
    }
    printf("all parser checks passed\n");
    return 0;
}
