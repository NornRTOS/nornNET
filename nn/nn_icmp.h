#ifndef NN_ICMP_INCLUDED
#define NN_ICMP_INCLUDED
/**
 * @file nn_icmp.h
 * ICMP: echo reply to requests, echo requests for the application (ping), destination
 * unreachable for the transport layers, and nothing else.
 */

#include "nn_types.h"
#include "nn_buf.h"
#include "nn_ip.h"

#define NN_ICMP_ECHO_REPLY      0u
#define NN_ICMP_UNREACHABLE     3u
#define NN_ICMP_ECHO_REQUEST    8u
#define NN_ICMP_TIME_EXCEEDED   11u

#define NN_ICMP_UNREACH_NET     0u
#define NN_ICMP_UNREACH_HOST    1u
#define NN_ICMP_UNREACH_PROTO   2u
#define NN_ICMP_UNREACH_PORT    3u

typedef struct nn_icmpStats
{
    uint32_t rx, rxBad, rxEchoRequests, rxEchoReplies, rxErrors, rxOther, txEchoReplies, txEchoRequests, txErrors;
} nn_icmpStats_t;

/** Called in the net task for every echo reply received; \a p is the ICMP payload. */
typedef void (*nn_icmpEchoReplyFunc_t)(nn_ip4_t from, uint16_t id, uint16_t seq,
                                        const uint8_t *p, uint16_t len, void *arg);

void nn_icmp_init(void);

/** Send an echo request (ping) with \a n payload bytes from \a payload (NULL: a byte
    pattern). With the stack lock. */
nn_err_t nn_icmpEchoRequest(nn_ip4_t dst, uint16_t id, uint16_t seq, const uint8_t *payload, uint16_t n);

/** Register the echo reply handler (one). */
void nn_icmpOnEchoReply(nn_icmpEchoReplyFunc_t fn, void *arg);

/** Send an ICMP error about the packet in \a pOrig (pData at its IP header). Not sent
    for broadcasts or for ICMP errors. The original buffer is left alone. */
nn_err_t nn_icmp_sendError(const nn_buf_t *pOrig, uint8_t type, uint8_t code);

void nn_icmpGetStats(nn_icmpStats_t *pStats);

#endif  /* NN_ICMP_INCLUDED */
