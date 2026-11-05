/**
 * @file nn_cksum.c
 * Portable checksum: big endian words assembled from bytes, four bytes per iteration.
 * Correct on any alignment and endianness. A word-wide variant for aligned data is a
 * later optimisation; at 160 MHz this one does a full frame in about 10 us.
 */

#include "nn_cksum.h"

uint32_t nn_cksumAdd(uint32_t sum, const uint8_t *p, uint16_t len)
{
    while(len >= 4)
    {
        sum += ((uint32_t)p[0] << 8) | p[1];
        sum += ((uint32_t)p[2] << 8) | p[3];
        p += 4;
        len = (uint16_t)(len - 4);
    }
    if(len >= 2)
    {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len = (uint16_t)(len - 2);
    }
    if(len != 0)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

uint16_t nn_cksumFinish(uint32_t sum)
{
    while(sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint32_t nn_cksumPseudo(nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint16_t len)
{
    uint32_t sum = 0;
    sum = nn_cksumAdd(sum, src.b, 4);
    sum = nn_cksumAdd(sum, dst.b, 4);
    sum += proto;
    sum += len;
    return sum;
}
