// P-256 passkey firewall, v2.
//
// A gated native payment must carry a WebAuthn assertion from the enrolled
// P-256 key. The hook rebuilds a 53-byte payload from the transaction and
// requires that payload to be the WebAuthn challenge. Signing stays inside
// WebAuthn: the authenticator signs authenticatorData || SHA-256(clientDataJSON),
// and the hook verifies SHA-256 of that concatenation.
//
// Requires util_sha256 and util_verify_p256 (HooksUpdate2, xahaud PR 511).
//
// Challenge payload, 53 bytes (this is the WebAuthn challenge, not the signed digest):
//   0  magic[16]      "xahau.passkey.v2"
//  16  direction      0 outgoing, 1 incoming
//  17  sequence[8]    tx Sequence as uint64 big-endian (high 4 bytes 0)
//  25  counterparty   20-byte account id of the other party
//  45  drops[8]       native amount in drops, uint64 big-endian
//
// MemoType = "xahau.passkey.v2"
// MemoData =
//   uint16 BE authenticatorData length || authenticatorData ||
//   uint16 BE clientDataJSON length    || clientDataJSON    ||
//   r || s, each 32 bytes big-endian
//
// State:
//   "PX"   32  public key X
//   "PY"   32  public key Y
//   "RP"   32  SHA-256(relying party id)
//   "OR"   8..64   exact origin string, for example "https://example.com"
//   "MODE"  1  0 outgoing, 1 incoming, 2 both (default 0)
//
// Invoke parameters (hook owner only) use those same names.
// v1 memos are not accepted. See ../v1 for plain ECDSA.

#include "hookapi.h"
#include "passkey_v2.h"

extern int64_t
util_sha256(
    uint32_t write_ptr,
    uint32_t write_len,
    uint32_t read_ptr,
    uint32_t read_len);

extern int64_t
util_verify_p256(
    uint32_t hread_ptr,
    uint32_t hread_len,
    uint32_t rread_ptr,
    uint32_t rread_len,
    uint32_t sread_ptr,
    uint32_t sread_len,
    uint32_t xread_ptr,
    uint32_t xread_len,
    uint32_t yread_ptr,
    uint32_t yread_len);

#define FAIL(msg) return rollback((uint32_t)(msg), sizeof(msg) - 1, __LINE__)
#define OK(msg) return accept((uint32_t)(msg), sizeof(msg) - 1, __LINE__)

#define MAX_MEMOS 8
#define AUTH_UP 0x01u
#define AUTH_UV 0x04u

static const uint8_t PASSKEY_MAGIC[16] = {
    'x', 'a', 'h', 'a', 'u', '.', 'p', 'a',
    's', 's', 'k', 'e', 'y', '.', 'v', '2'};

static inline __attribute__((always_inline)) int32_t
memo_type_is_v2(uint8_t* buf, int64_t len)
{
    if (len != 17 || buf[0] != 16)
        return 0;
    return buf[1] == PASSKEY_MAGIC[0] && buf[2] == PASSKEY_MAGIC[1] &&
        buf[3] == PASSKEY_MAGIC[2] && buf[4] == PASSKEY_MAGIC[3] &&
        buf[5] == PASSKEY_MAGIC[4] && buf[6] == PASSKEY_MAGIC[5] &&
        buf[7] == PASSKEY_MAGIC[6] && buf[8] == PASSKEY_MAGIC[7] &&
        buf[9] == PASSKEY_MAGIC[8] && buf[10] == PASSKEY_MAGIC[9] &&
        buf[11] == PASSKEY_MAGIC[10] && buf[12] == PASSKEY_MAGIC[11] &&
        buf[13] == PASSKEY_MAGIC[12] && buf[14] == PASSKEY_MAGIC[13] &&
        buf[15] == PASSKEY_MAGIC[14] && buf[16] == PASSKEY_MAGIC[15];
}

//   1  one v2 memo, body points into slotbuf
//   0  no v2 memo
//  -1  v2 memo is missing MemoData
//  -3  MemoData is not one well-formed blob
//  -4  more than one v2 memo
//  -5  MemoData does not fit
static inline __attribute__((always_inline)) int32_t
load_v2_memo(
    uint8_t* slotbuf,
    int32_t slotcap,
    const uint8_t** body,
    int32_t* body_len)
{
    *body = 0;
    *body_len = 0;

    int64_t tx_slot = otxn_slot(1);
    if (tx_slot < 0)
        return 0;

    int64_t memos_slot = slot_subfield(tx_slot, sfMemos, 2);
    if (memos_slot < 0)
        return 0;

    int64_t count = slot_count(memos_slot);
    if (count < 0)
        return 0;
    if (count > MAX_MEMOS)
        count = MAX_MEMOS;

    int32_t found = 0;
    for (int32_t i = 0; GUARD(MAX_MEMOS), i < count; ++i) {
        int64_t memo_slot = slot_subarray(memos_slot, (uint32_t)i, 3);
        if (memo_slot < 0)
            continue;

        int64_t type_slot = slot_subfield(memo_slot, sfMemoType, 4);
        if (type_slot < 0)
            continue;

        uint8_t type_buf[24];
        int64_t type_len = slot((uint32_t)type_buf, (uint32_t)sizeof(type_buf), type_slot);
        if (type_len < 0 || !memo_type_is_v2(type_buf, type_len))
            continue;
        if (found)
            return -4;

        int64_t data_slot = slot_subfield(memo_slot, sfMemoData, 5);
        if (data_slot < 0)
            return -1;

        int64_t data_len = slot((uint32_t)slotbuf, (uint32_t)slotcap, data_slot);
        if (data_len == TOO_SMALL)
            return -5;
        if (data_len < 0)
            return -1;

        int32_t prefix = 0;
        int32_t plen = 0;
        if (!vl_split(slotbuf, (int32_t)data_len, &prefix, &plen))
            return -3;

        *body = slotbuf + prefix;
        *body_len = plen;
        found = 1;
    }
    return found;
}

static inline __attribute__((always_inline)) int64_t
admin(uint8_t hook_acc[20], uint8_t otxn_acc[20])
{
    if (!BUFFER_EQUAL_20(hook_acc, otxn_acc))
        FAIL("passkey: only the hook owner can configure");

    int32_t changed = 0;

    uint8_t px[32];
    uint8_t k_px[2] = {'P', 'X'};
    int64_t px_len = otxn_param(SBUF(px), SBUF(k_px));
    if (px_len == 32) {
        if (state_set(SBUF(px), SBUF(k_px)) < 0)
            FAIL("passkey: could not store PX");
        changed = 1;
    } else if (px_len != DOESNT_EXIST) {
        FAIL("passkey: PX must be 32 bytes");
    }

    uint8_t py[32];
    uint8_t k_py[2] = {'P', 'Y'};
    int64_t py_len = otxn_param(SBUF(py), SBUF(k_py));
    if (py_len == 32) {
        if (state_set(SBUF(py), SBUF(k_py)) < 0)
            FAIL("passkey: could not store PY");
        changed = 1;
    } else if (py_len != DOESNT_EXIST) {
        FAIL("passkey: PY must be 32 bytes");
    }

    uint8_t rp[32];
    uint8_t k_rp[2] = {'R', 'P'};
    int64_t rp_len = otxn_param(SBUF(rp), SBUF(k_rp));
    if (rp_len == 32) {
        if (state_set(SBUF(rp), SBUF(k_rp)) < 0)
            FAIL("passkey: could not store RP");
        changed = 1;
    } else if (rp_len != DOESNT_EXIST) {
        FAIL("passkey: RP must be 32 bytes");
    }

    uint8_t origin[V2_MAX_ORIGIN];
    uint8_t k_or[2] = {'O', 'R'};
    int64_t origin_len = otxn_param(SBUF(origin), SBUF(k_or));
    if (origin_len >= 8 && origin_len <= V2_MAX_ORIGIN) {
        for (int32_t i = 0; GUARD(V2_MAX_ORIGIN), i < origin_len; ++i) {
            uint8_t c = origin[i];
            if (c < 0x21 || c > 0x7e || c == '"' || c == '\\')
                FAIL("passkey: OR has a forbidden character");
        }
        if (state_set((uint32_t)origin, (uint32_t)origin_len, SBUF(k_or)) < 0)
            FAIL("passkey: could not store OR");
        changed = 1;
    } else if (origin_len != DOESNT_EXIST) {
        FAIL("passkey: OR must be 8 to 64 bytes");
    }

    uint8_t mode[1];
    uint8_t k_mode[4] = {'M', 'O', 'D', 'E'};
    int64_t mode_len = otxn_param(SBUF(mode), SBUF(k_mode));
    if (mode_len == 1) {
        if (mode[0] > 2)
            FAIL("passkey: MODE must be 0, 1, or 2");
        if (state_set(SBUF(mode), SBUF(k_mode)) < 0)
            FAIL("passkey: could not store MODE");
        changed = 1;
    } else if (mode_len != DOESNT_EXIST) {
        FAIL("passkey: MODE must be 1 byte");
    }

    if (!changed)
        FAIL("passkey: Invoke needs PX, PY, RP, OR, and/or MODE");

    OK("passkey: configuration stored");
}

static inline __attribute__((always_inline)) int64_t
payment(uint8_t hook_acc[20], uint8_t otxn_acc[20])
{
    int32_t outgoing = BUFFER_EQUAL_20(hook_acc, otxn_acc);

    uint8_t counterparty[20];
    if (outgoing) {
        if (otxn_field(SBUF(counterparty), sfDestination) != 20)
            FAIL("passkey: payment is missing Destination");
    } else {
        uint8_t destination[20];
        if (otxn_field(SBUF(destination), sfDestination) != 20)
            FAIL("passkey: payment is missing Destination");
        if (!BUFFER_EQUAL_20(destination, hook_acc))
            OK("passkey: payment does not involve this account");
        for (int32_t i = 0; GUARD(20), i < 20; ++i)
            counterparty[i] = otxn_acc[i];
    }

    uint8_t mode[1];
    uint8_t k_mode[4] = {'M', 'O', 'D', 'E'};
    int64_t mode_len = state(SBUF(mode), SBUF(k_mode));
    uint8_t mode_byte = 0;
    if (mode_len == 1)
        mode_byte = mode[0];
    else if (mode_len != DOESNT_EXIST)
        FAIL("passkey: stored MODE is invalid");
    if (mode_byte > 2)
        FAIL("passkey: stored MODE is invalid");

    int32_t gated = mode_byte == 2 || (mode_byte == 0 && outgoing) ||
        (mode_byte == 1 && !outgoing);
    if (!gated)
        OK("passkey: direction is not gated");

    uint8_t flag_buf[4];
    int64_t flag_len = otxn_field(SBUF(flag_buf), sfFlags);
    if (flag_len == 4 && (UINT32_FROM_BUF(flag_buf) & tfPartialPayment))
        FAIL("passkey: partial payments are not allowed");

    uint8_t amount[48];
    int64_t amount_len = otxn_field(SBUF(amount), sfAmount);
    if (amount_len != 8 || (amount[0] & 0x80U) != 0)
        FAIL("passkey: only native payments are supported");
    if ((amount[0] & 0x40U) == 0)
        FAIL("passkey: amount must be positive");

    int64_t drops = AMOUNT_TO_DROPS(amount);
    if (drops < 0)
        FAIL("passkey: only native payments are supported");

    uint8_t px[32];
    uint8_t py[32];
    uint8_t k_px[2] = {'P', 'X'};
    uint8_t k_py[2] = {'P', 'Y'};
    if (state(SBUF(px), SBUF(k_px)) != 32 || state(SBUF(py), SBUF(k_py)) != 32)
        FAIL("passkey: PX/PY are not set");

    uint8_t rp[32];
    uint8_t k_rp[2] = {'R', 'P'};
    if (state(SBUF(rp), SBUF(k_rp)) != 32)
        FAIL("passkey: RP is not set");

    uint8_t origin[V2_MAX_ORIGIN];
    uint8_t k_or[2] = {'O', 'R'};
    int64_t origin_len64 = state(SBUF(origin), SBUF(k_or));
    if (origin_len64 == DOESNT_EXIST)
        FAIL("passkey: OR is not set");
    if (origin_len64 < 8 || origin_len64 > V2_MAX_ORIGIN)
        FAIL("passkey: stored OR is invalid");

    uint8_t seq[4];
    if (otxn_field(SBUF(seq), sfSequence) != 4)
        FAIL("passkey: missing Sequence");

    uint8_t slotbuf[V2_SLOT_LEN];
    const uint8_t* body = 0;
    int32_t body_len = 0;
    int32_t found = load_v2_memo(slotbuf, V2_SLOT_LEN, &body, &body_len);
    if (found == 0)
        FAIL("passkey: no valid passkey memo found");
    if (found == -1)
        FAIL("passkey: memo is missing MemoData");
    if (found == -4)
        FAIL("passkey: two passkey memos");
    if (found == -5)
        FAIL("passkey: v2 memo is too large");
    if (found != 1)
        FAIL("passkey: v2 memo is malformed");

    v2_view view;
    if (!v2_unpack(body, body_len, &view))
        FAIL("passkey: v2 memo is malformed");

    for (int32_t i = 0; GUARD(32), i < 32; ++i) {
        if (view.auth[i] != rp[i])
            FAIL("passkey: rpIdHash does not match RP");
    }
    if ((view.auth[32] & AUTH_UP) == 0 || (view.auth[32] & AUTH_UV) == 0)
        FAIL("passkey: user presence and verification required");

    uint8_t payload[V2_PAYLOAD_LEN];
    for (int32_t i = 0; GUARD(16), i < 16; ++i)
        payload[i] = PASSKEY_MAGIC[i];
    payload[16] = outgoing ? 0 : 1;
    payload[17] = 0;
    payload[18] = 0;
    payload[19] = 0;
    payload[20] = 0;
    payload[21] = seq[0];
    payload[22] = seq[1];
    payload[23] = seq[2];
    payload[24] = seq[3];
    for (int32_t i = 0; GUARD(20), i < 20; ++i)
        payload[25 + i] = counterparty[i];
    UINT64_TO_BUF(payload + 45, (uint64_t)drops);

    int32_t json_rc = v2_client_data_ok(
        view.json, view.json_len, payload, origin, (int32_t)origin_len64);
    if (json_rc == V2_ERR_JSON)
        FAIL("passkey: clientDataJSON is not plain ASCII");
    if (json_rc == V2_ERR_CHALLENGE_COUNT || json_rc == V2_ERR_CHALLENGE)
        FAIL("passkey: challenge does not match this payment");
    if (json_rc == V2_ERR_TYPE)
        FAIL("passkey: clientData type must be webauthn.get");
    if (json_rc == V2_ERR_ORIGIN)
        FAIL("passkey: origin does not match OR");
    if (json_rc == V2_ERR_B64)
        FAIL("passkey: clientDataJSON challenge is not canonical");
    if (json_rc != V2_OK)
        FAIL("passkey: clientDataJSON was rejected");

    uint8_t client_hash[32];
    if (util_sha256(
            SBUF(client_hash), (uint32_t)view.json, (uint32_t)view.json_len) != 32)
        FAIL("passkey: sha256 failed");

    uint8_t message[V2_MAX_AUTH + 32];
    for (int32_t i = 0; GUARD(V2_MAX_AUTH), i < view.auth_len; ++i)
        message[i] = view.auth[i];
    for (int32_t i = 0; GUARD(32), i < 32; ++i)
        message[view.auth_len + i] = client_hash[i];

    uint8_t digest[32];
    if (util_sha256(
            SBUF(digest), (uint32_t)message, (uint32_t)(view.auth_len + 32)) != 32)
        FAIL("passkey: sha256 failed");

    int64_t verified = util_verify_p256(
        SBUF(digest),
        (uint32_t)view.sig,
        32,
        (uint32_t)(view.sig + 32),
        32,
        SBUF(px),
        SBUF(py));
    if (verified != 1)
        FAIL("passkey: invalid P-256 passkey signature");

    OK("passkey: signature accepted");
}

int64_t
hook(uint32_t reserved)
{
    (void)reserved;

    uint8_t hook_acc[20];
    if (hook_account(SBUF(hook_acc)) != 20)
        FAIL("passkey: could not read hook account");

    uint8_t otxn_acc[20];
    if (otxn_field(SBUF(otxn_acc), sfAccount) != 20)
        FAIL("passkey: could not read origin account");

    int64_t tt = otxn_type();
    if (tt == ttINVOKE)
        return admin(hook_acc, otxn_acc);
    if (tt != ttPAYMENT)
        OK("passkey: passthrough");
    return payment(hook_acc, otxn_acc);
}
