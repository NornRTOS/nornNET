#ifndef NN_TCP_INCLUDED
#define NN_TCP_INCLUDED
/**
 * @file nn_tcp.h
 * TCP (RFC 9293) with the congestion control of RFC 5681 and the timer of RFC 6298.
 * A socket is a caller owned struct with caller owned send and receive rings, so the
 * application decides how much memory each connection gets and where it lives. The
 * stack copies application data into the send ring and out of the receive ring; those
 * are the only copies, segments are built straight into packet buffers.
 *
 * Blocking calls (connect, accept, send, recv) sleep on the caller's task notification,
 * one task per direction per socket. With timeout 0 connect and accept return
 * NN_ERR_PENDING and the result arrives as an event in the net task.
 *
 * Only one option is used: MSS. No window scaling, SACK or time stamps, so a receive
 * ring is at most 65535 bytes. Out of order data is kept when it fits (one contiguous
 * range), so a single lost segment costs one retransmission, not a window.
 *
 * After nn_tcpClose the socket stays in use until its state is NN_TCP_CLOSED: the FIN
 * must be acknowledged and the peer's FIN received. The TIME_WAIT state lives in a small
 * table instead of the socket, so a closed socket can be reused as soon as it reaches
 * CLOSED. nn_tcpAbort (RST) gets there at once.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"
#include "nn_ip.h"
#include "nn_timer.h"
#include "nn_os.h"

#define NN_TCP_HDR_LEN      20u

/* Header flags. */
#define NN_TCP_FIN          0x01u
#define NN_TCP_SYN          0x02u
#define NN_TCP_RST          0x04u
#define NN_TCP_PSH          0x08u
#define NN_TCP_ACK          0x10u

/* States, numbered as in the RFC diagram. TIME_WAIT is never a socket state here. */
#define NN_TCP_CLOSED       0u
#define NN_TCP_LISTEN       1u
#define NN_TCP_SYN_SENT     2u
#define NN_TCP_SYN_RCVD     3u
#define NN_TCP_ESTABLISHED  4u
#define NN_TCP_FIN_WAIT_1   5u
#define NN_TCP_FIN_WAIT_2   6u
#define NN_TCP_CLOSE_WAIT   7u
#define NN_TCP_CLOSING      8u
#define NN_TCP_LAST_ACK     9u
#define NN_TCP_TIME_WAIT    10u

/* Events delivered to the socket callback, in the net task with the lock held. */
#define NN_TCP_EV_CONNECTED 1u  /**< Handshake done (connect or accept). */
#define NN_TCP_EV_READABLE  2u  /**< Data arrived, or the peer closed (recv returns 0). */
#define NN_TCP_EV_WRITABLE  3u  /**< Send ring space was freed by an ACK. */
#define NN_TCP_EV_CLOSED    4u  /**< Reached CLOSED; pSock->err says why. */

/* Socket flags (internal, read only for the application). */
#define NN_TCPF_NODELAY     0x01u   /**< Nagle off. */
#define NN_TCPF_RXEOF       0x02u   /**< The peer's FIN was received. */
#define NN_TCPF_RXWAIT      0x04u
#define NN_TCPF_TXWAIT      0x08u
#define NN_TCPF_DELACK      0x10u   /**< An ACK is owed and the delay timer runs. */
#define NN_TCPF_PERSIST     0x20u   /**< The timer is the zero window probe timer. */
#define NN_TCPF_RTT         0x40u   /**< A round trip is being timed. */
#define NN_TCPF_FINSENT     0x80u   /**< Our FIN is on the wire (sndNxt includes it). */
#define NN_TCPF_FASTREC     0x100u  /**< In fast recovery. */

typedef struct nn_tcp nn_tcp_t;
typedef void (*nn_tcpEventFunc_t)(nn_tcp_t *pSock, uint8_t event, void *arg);

struct nn_tcp
{
    nn_tcp_t *pNext;
    uint8_t state;              /**< NN_TCP_* */
    nn_err_t err;               /**< Why the connection ended (NN_OK: orderly). */
    uint16_t flags;             /**< NN_TCPF_* */
    nn_ip4_t localAddr, remoteAddr;
    uint16_t localPort, remotePort;

    /* Receive ring: in order data at [rxHead, rxHead + rxLen); one out of order range
       oooLen bytes long starting oooOff bytes after rcvNxt, stored in place. */
    uint8_t *pRx;
    uint16_t rxSize, rxHead, rxLen, oooOff, oooLen;
    /* Send ring: [txHead, txHead + txLen) holds sndUna onwards, unacknowledged first. */
    uint8_t *pTx;
    uint16_t txSize, txHead, txLen;

    uint32_t iss, irs;
    uint32_t sndUna, sndNxt, sndMax, sndWnd, sndWndMax, sndWl1, sndWl2;
    uint32_t rcvNxt, rcvAdv;    /**< rcvAdv: right edge of the last advertised window. */
    uint16_t mss;               /**< Largest segment we send to this peer. */
    uint32_t cwnd, ssthresh, recover;
    uint8_t dupAcks, rexmits;
    int32_t srtt, rttvar;       /**< Scaled by 8 and 4 (RFC 6298 with integer ms). */
    nn_ms_t rto, rttStart;
    uint32_t rttSeq;
    nn_timer_t timer;           /**< Retransmission, SYN, persist. */
    nn_timer_t delAck;

    nn_tcp_t *pAcceptQ;         /**< Listener: sockets offered by nn_tcpAccept. */
    nn_tcp_t *pListener;        /**< Accepting socket: where it was offered. */
    nn_os_taskId_t rxWaiter, txWaiter;
    nn_tcpEventFunc_t onEvent;
    void *cbArg;
    uint32_t rxBytes, txBytes, rexmitCount;
};

typedef struct nn_tcpStats
{
    uint32_t rx, rxBad, rxBadChecksum, rxNoSocket, rxResets, rxOoo, rxOooDropped, rxDup, rxAcceptDropped;
    uint32_t tx, txNoBuf, txResets, rexmits, fastRexmits, timeouts, delAcks;
    uint32_t activeOpens, passiveOpens, established, timeWaits;
} nn_tcpStats_t;

void nn_tcp_init(void);

/** The interface address \a addr is gone (DHCP lost or changed it): every connection
    bound to it ends with NN_ERR_DOWN, without a RST since nothing can be sent. Called by
    nn_ifaceSetAddr with the stack lock. */
void nn_tcp_addrLost(nn_ip4_t addr);

/** Prepare a socket. The rings are needed for a connection (both non NULL, 1 to 65535
    bytes each); a socket that will only listen may pass NULL and 0. */
nn_err_t nn_tcpOpen(nn_tcp_t *pSock, void *pRxRing, uint16_t rxSize, void *pTxRing, uint16_t txSize);

/** Bind to a local address (0.0.0.0 for any) and port (0 for an ephemeral one). */
nn_err_t nn_tcpBind(nn_tcp_t *pSock, nn_ip4_t addr, uint16_t port);

/** Turn a bound socket into a listener. */
nn_err_t nn_tcpListen(nn_tcp_t *pSock);

/** Offer \a pNew (opened with rings, not bound) to accept the next connection arriving
    at the listener, and wait until it is established. Timeout 0: return NN_ERR_PENDING
    and signal NN_TCP_EV_CONNECTED on \a pNew later. Several sockets may be offered; they
    are used in order. On NN_ERR_TIMEOUT the offer is withdrawn when the handshake has
    not started. */
nn_err_t nn_tcpAccept(nn_tcp_t *pListen, nn_tcp_t *pNew, nn_ms_t timeout);

/** Active open: send a SYN and wait for the handshake. Timeout 0: NN_ERR_PENDING and
    an event later; otherwise NN_ERR_TIMEOUT aborts the attempt. NN_ERR_REFUSED on RST. */
nn_err_t nn_tcpConnect(nn_tcp_t *pSock, nn_ip4_t addr, uint16_t port, nn_ms_t timeout);

/** Queue \a n bytes for sending, waiting up to \a timeout ms for ring space. Returns the
    number of bytes queued (less than \a n only on timeout) or a negative error. */
int32_t nn_tcpSend(nn_tcp_t *pSock, const void *p, size_t n, nn_ms_t timeout);

/** Receive up to \a n bytes: returns the count (at least 1), 0 when the peer has closed
    and everything was read, NN_ERR_TIMEOUT or another negative error. */
int32_t nn_tcpRecv(nn_tcp_t *pSock, void *p, size_t n, nn_ms_t timeout);

uint16_t nn_tcpAvailable(const nn_tcp_t *pSock);     /**< Bytes readable now. */
uint16_t nn_tcpSendSpace(const nn_tcp_t *pSock);     /**< Bytes nn_tcpSend takes now. */

/** Orderly close: the queued data and a FIN are sent, the socket stays in use until
    CLOSED. Unread received data makes it a reset, as the RFC asks. */
nn_err_t nn_tcpClose(nn_tcp_t *pSock);

/** Send a RST and go to CLOSED at once. */
nn_err_t nn_tcpAbort(nn_tcp_t *pSock);

uint8_t nn_tcpState(const nn_tcp_t *pSock);
const char *nn_tcpStateName(uint8_t state);

/** Nagle's algorithm is on by default; off sends every write at once. */
void nn_tcpSetNoDelay(nn_tcp_t *pSock, bool noDelay);

/** Event callback, run in the net task with the lock held; NULL to clear. */
void nn_tcpOnEvent(nn_tcp_t *pSock, nn_tcpEventFunc_t fn, void *arg);

void nn_tcpGetStats(nn_tcpStats_t *pStats);

#endif  /* NN_TCP_INCLUDED */
