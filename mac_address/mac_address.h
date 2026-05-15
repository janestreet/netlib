#ifndef _MAC_ADDRESS_H
#define _MAC_ADDRESS_H

#include <stdint.h>
#include <caml/mlvalues.h>

/* [val_mac_address_bytes] and [mac_address_bytes_val] are tested using
   [Test_mac_address_stubs] to ensure they remain consistent with [Mac_address]'s
   representation. */

#define MAC_ADDRESS_VAL_NONE     Val_long(Min_long) /* (INT64_MIN / 2) */

static inline int mac_address_is_some(value v_mac)
{
  return (v_mac != MAC_ADDRESS_VAL_NONE);
}

static inline int mac_address_is_none(value v_mac)
{
  return !mac_address_is_some(v_mac);
}

/* The following two functions convert between the OCaml and C representations.

   The conversion fills [addr] with the given address in transmission order (network byte
   order, or big-endian), and builds OCaml [Mac_address] values from an array in the same
   order.

   Here is an example of how the binary and string formats relate:

   addr[0]
   |  addr[1]
   |  |  addr[2]
   |  |  |  addr[3]
   |  |  |  |  addr[4]
   |  |  |  |  |  addr[5]
   |  |  |  |  |  |
   v  v  v  v  v  v
   00:0f:53:5a:d4:61
*/
static value val_mac_address_bytes(const uint8_t * addr)
{
  uint64_t raw =
    ((int64_t)addr[0] << 40) |
    ((int64_t)addr[1] << 32) |
    ((int64_t)addr[2] << 24) |
    ((int64_t)addr[3] << 16) |
    ((int64_t)addr[4] <<  8) |
    ((int64_t)addr[5] <<  0);

  return Val_long(raw);
}

static void mac_address_bytes_val(value v_mac, uint8_t * dst)
{
  uint64_t raw_src_addr = Long_val(v_mac);
  dst[0] = (raw_src_addr >> 40) & 0xff;
  dst[1] = (raw_src_addr >> 32) & 0xff;
  dst[2] = (raw_src_addr >> 24) & 0xff;
  dst[3] = (raw_src_addr >> 16) & 0xff;
  dst[4] = (raw_src_addr >>  8) & 0xff;
  dst[5] = (raw_src_addr >>  0) & 0xff;
}

#endif /* _MAC_ADDRESS_H */
