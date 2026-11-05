#ifndef NN_CKSUM_INCLUDED
#define NN_CKSUM_INCLUDED
/**
 * @file nn_cksum.h
 * The Internet checksum (RFC 1071): one's complement sum of 16 bit big endian words.
 * Accumulate with nn_cksumAdd over any number of pieces, then nn_cksumFinish. A header
 * whose checksum field is included sums to 0 when it is correct.
 */

#include "nn_types.h"

/** Add \a len bytes at \a p to the running sum. An odd trailing byte is the high half
    of a final word, as the RFC says, so pieces must be even sized except the last. */
uint32_t nn_cksumAdd(uint32_t sum, const uint8_t *p, uint16_t len);

/** Fold and complement: the value to store with nn_put16. */
uint16_t nn_cksumFinish(uint32_t sum);

/** The IPv4 pseudo header of UDP and TCP, as a partial sum. */
uint32_t nn_cksumPseudo(nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint16_t len);

/** Checksum of one contiguous block; 0 when it includes a correct checksum field. */
static inline uint16_t nn_cksum(const uint8_t *p, uint16_t len)
{
    return nn_cksumFinish(nn_cksumAdd(0, p, len));
}

#endif  /* NN_CKSUM_INCLUDED */
