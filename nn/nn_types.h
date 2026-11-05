#ifndef NN_TYPES_INCLUDED
#define NN_TYPES_INCLUDED
/**
 * @file nn_types.h
 * Basic types of nornNET: error codes, addresses and byte order helpers. Everything on the
 * wire is big endian; the helpers are written byte-wise so they are correct on any host
 * without knowing its endianness.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/** Result of most calls: 0 on success, a negative code otherwise. */
typedef int8_t nn_err_t;

#define NN_OK               0
#define NN_ERR_NOMEM        (-1)    /**< No packet buffer or table entry free. */
#define NN_ERR_INVAL        (-2)    /**< Bad argument. */
#define NN_ERR_FULL         (-3)    /**< Queue or table full. */
#define NN_ERR_NODEV        (-4)    /**< No device or interface for this operation. */
#define NN_ERR_TIMEOUT      (-5)
#define NN_ERR_UNSUPPORTED  (-6)
#define NN_ERR_DOWN         (-7)    /**< Device is not up. */
#define NN_ERR_IO           (-8)    /**< Driver reported a transmit error. */
#define NN_ERR_EXIST        (-9)    /**< Already registered. */
#define NN_ERR_PENDING      (-10)   /**< Not finished yet (non-blocking call accepted). */
#define NN_ERR_RESET        (-11)   /**< Connection reset by the peer. */
#define NN_ERR_REFUSED      (-12)   /**< Connection refused (RST to our SYN). */
#define NN_ERR_CLOSED       (-13)   /**< Socket or connection is closed. */

#define NN_ETH_ALEN         6u

/** An IPv4 address in network byte order, kept as 4 bytes so it is never misaligned. */
typedef struct nn_ip4 { uint8_t b[4]; } nn_ip4_t;

/** Milliseconds; wraps after 49 days, compare with nn_msBefore. */
typedef uint32_t nn_ms_t;

#define NN_FOREVER          0xFFFFFFFFu

/** True if time stamp \a a is before \a b, modulo wrap. */
static inline bool nn_msBefore(nn_ms_t a, nn_ms_t b)
{
    return (int32_t)(a - b) < 0;
}

static inline uint16_t nn_get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t nn_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline void nn_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void nn_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline bool nn_macEqual(const uint8_t *a, const uint8_t *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
        && a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static inline bool nn_macIsBroadcast(const uint8_t *a)
{
    return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xFFu;
}

static inline void nn_macCopy(uint8_t *dst, const uint8_t *src)
{
    dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2];
    dst[3] = src[3]; dst[4] = src[4]; dst[5] = src[5];
}

#endif  /* NN_TYPES_INCLUDED */
