// Shared level table for the v1 and v2 passkey firewalls.
// The hooks stay separate. This header is only the gate policy.

#ifndef PASSKEY_FIREWALL_LEVEL_H
#define PASSKEY_FIREWALL_LEVEL_H

#include <stdint.h>

// LV state is one byte. Unset means level 1.
//
// 1  Native payments only. MODE picks the direction. Every other type passes.
// 2  Level 1, plus outgoing value and account-control transactions. Invoke is
//    included, so replacing the key or the level requires a passkey. SetHook
//    is not, so the account key can still remove the hook.
// 3  Every outgoing transaction type, including SetHook. A lost passkey cannot
//    remove the hook. Incoming non-payments still pass.
#define FW_LEVEL_MAX 3

// Kind byte in the 53-byte non-payment payload. Payment payloads use 0 and 1.
#define FW_TX_KIND 2

// The whole serialized transaction, memos included, must fit. Larger gated
// transactions roll back. A SetHook that deletes the hook is small enough.
#define FW_TX_MAX 2048

// Minimum level that gates an outgoing transaction.
// 0 never gates. 1 is the payment path (the table value is not consulted).
// 2 is value and account control. 3 is everything else, including SetHook.
// ttCRON (92) stays at 3 so a scheduled execution is not blocked at level 2.
// ttCRON_SET (93) is level 2.
static const uint8_t FW_GATE[128] = {
    1,2,2,2,2,2,3,2,2,3,2,3,2,2,2,2, /*   0..15  */
    2,2,2,2,2,2,3,3,3,2,2,2,2,2,2,2, /*  16..31  */
    3,3,3,2,2,2,2,2,2,3,3,3,3,2,2,2, /*  32..47  */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /*  48..63  */
    2,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3, /*  64..79  */
    3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2, /*  80..95  */
    0,2,2,2,0,0,0,0,0,3,3,3,3,3,3,3, /*  96..111 */
    3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3, /* 112..127 */
};

static inline __attribute__((always_inline)) uint8_t
fw_gate_level(int64_t tt)
{
    if (tt < 0 || tt >= 128)
        return 3;
    return FW_GATE[tt];
}

#endif
