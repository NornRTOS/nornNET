#ifndef NN_UDP_INCLUDED
#define NN_UDP_INCLUDED
/**
 * @file nn_udp.h
 * UDP sockets. A socket is a caller owned struct; received datagrams queue up in it as
 * packet buffers until the application takes them, so nothing is copied until the
 * application asks for a copy (nn_udpRecvFrom) or takes the buffer itself
 * (nn_udpRecvBuf). One task may block in receive per socket. A readable callback runs in
 * the net task with the stack lock held, for event driven code.
 *
 * Every call except the receive functions returns at once. The receive functions sleep
 * on the caller's task notification, so they must be called from a task.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"
#include "nn_ip.h"
#include "nn_os.h"

#define NN_UDP_HDR_LEN  8u

typedef struct nn_udp nn_udp_t;
typedef void (*nn_udpReadableFunc_t)(nn_udp_t *pSock, void *arg);

struct nn_udp
{
    nn_udp_t *pNext;
    nn_ip4_t localAddr;         /**< 0.0.0.0: any of ours. */
    uint16_t localPort;         /**< 0: not bound. */
    nn_ip4_t remoteAddr;        /**< Filter and default destination after connect; 0.0.0.0: any. */
    uint16_t remotePort;
    nn_iface_t *pIf;            /**< Send through this interface instead of routing (DHCP). */
    nn_buf_t *pRxHead, *pRxTail; /**< Queued datagrams: pData at the payload, aux = source address. */
    uint8_t rxCount;
    uint8_t rxMax;              /**< Queue limit; NN_CFG_UDP_RXQ by default. */
    bool open;
    bool waiting;
    nn_os_taskId_t waiter;
    nn_udpReadableFunc_t onReadable;
    void *cbArg;
    uint32_t rxDatagrams, rxDropped, txDatagrams;
};

typedef struct nn_udpStats
{
    uint32_t rx, rxBad, rxBadChecksum, rxNoSocket, rxQueueFull, tx, txErrors;
} nn_udpStats_t;

void nn_udp_init(void);

/** Prepare a socket. */
nn_err_t nn_udpOpen(nn_udp_t *pSock);

/** Bind to a local address (0.0.0.0 for any) and port (0 for an ephemeral one). */
nn_err_t nn_udpBind(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port);

/** Restrict receiving to one peer and make it the default destination of nn_udpSend. */
nn_err_t nn_udpConnect(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port);

/** Send \a n bytes from \a p to \a to:\a port. Binds to an ephemeral port if needed. */
nn_err_t nn_udpSendTo(nn_udp_t *pSock, const void *p, size_t n, nn_ip4_t to, uint16_t port);

/** Send to the connected peer. */
nn_err_t nn_udpSend(nn_udp_t *pSock, const void *p, size_t n);

/** Zero copy send: \a pB was allocated with nn_bufAlloc(NN_CFG_TX_HEADROOM) and holds
    the payload. Takes the buffer. */
nn_err_t nn_udpSendBuf(nn_udp_t *pSock, nn_buf_t *pB, nn_ip4_t to, uint16_t port);

/** Receive one datagram into \a p (at most \a n bytes; a longer datagram is truncated,
    the full length is still returned). Returns the datagram length, or a negative
    nn_err_t: NN_ERR_TIMEOUT when nothing arrived within \a timeout ms. */
int32_t nn_udpRecvFrom(nn_udp_t *pSock, void *p, size_t n, nn_ip4_t *pFrom, uint16_t *pPort, nn_ms_t timeout);

/** Zero copy receive: the datagram's buffer with pData at the payload; the caller frees
    it. NULL on timeout. */
nn_buf_t *nn_udpRecvBuf(nn_udp_t *pSock, nn_ip4_t *pFrom, uint16_t *pPort, nn_ms_t timeout);

/** Datagrams waiting. */
uint8_t nn_udpAvailable(const nn_udp_t *pSock);

/** Called in the net task whenever a datagram is queued; NULL to clear. */
void nn_udpOnReadable(nn_udp_t *pSock, nn_udpReadableFunc_t fn, void *arg);

/** Unbind, drop queued datagrams, wake a blocked reader (it returns NN_ERR_INVAL). */
nn_err_t nn_udpClose(nn_udp_t *pSock);

void nn_udpGetStats(nn_udpStats_t *pStats);

/* --- For protocol modules running inside the net task (stack lock already held) ------- */

nn_err_t nn_udp_bind(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port);
nn_err_t nn_udp_sendBuf(nn_udp_t *pSock, nn_buf_t *pB, nn_ip4_t to, uint16_t port);
/** Take the next queued datagram, NULL if none. */
nn_buf_t *nn_udp_dequeue(nn_udp_t *pSock);

/** Source address and port of a received buffer (as stored by the input path). */
static inline nn_ip4_t nn_udpBufFrom(const nn_buf_t *pB)
{
    nn_ip4_t a;
    a.b[0] = (uint8_t)(pB->aux >> 24); a.b[1] = (uint8_t)(pB->aux >> 16);
    a.b[2] = (uint8_t)(pB->aux >> 8);  a.b[3] = (uint8_t)pB->aux;
    return a;
}
static inline uint16_t nn_udpBufPort(const nn_buf_t *pB)
{
    return nn_get16(pB->pData - NN_UDP_HDR_LEN);    /* the header is still in the buffer */
}

#endif  /* NN_UDP_INCLUDED */
