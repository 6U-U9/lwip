/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

/*
   -------------------------------------
   ---------- gazelle options ----------
   -------------------------------------
*/
#define LWIP_PERF 1
#define LWIP_RECORD_PERF 0

#define LWIP_DEBUG 1
#define GAZELLE_USE_DPDK_LOG 1

#define GAZELLE_ENABLE 1
#define PER_THREAD __thread

#define FRAME_MTU 1500

#define GAZELLE_TCP_PCB_HASH 1

#define GAZELLE_TCP_MAX_DATA_ACK_NUM 256

#define GAZELLE_TCP_MAX_PBUF_CHAIN_LEN 40

#define GAZELLE_TCP_MIN_TSO_SEG_LEN 256


#define GAZELLE_UDP_ENABLE 1


/*
   ----------------------------------
   ---------- NIC offloads ----------
   ----------------------------------
*/
#define LWIP_CHECKSUM_CTRL_PER_NETIF 1 /* checksum ability check before checksum*/

// rx cksum
#define CHECKSUM_CHECK_IP     1 /*  master switch */
#define CHECKSUM_CHECK_TCP    1 /*  master switch */
#define CHECKSUM_CHECK_UDP    1 /*  master switch */
// tx cksum
#define CHECKSUM_GEN_IP       1 /*  master switch */
#define CHECKSUM_GEN_TCP      1 /*  master switch */
#define CHECKSUM_GEN_UDP      1 /*  master switch */

// rx offload cksum
#define CHECKSUM_CHECK_IP_HW  (1 && CHECKSUM_CHECK_IP) /*  hardware switch */
#define CHECKSUM_CHECK_TCP_HW (1 && CHECKSUM_CHECK_TCP) /*  hardware switch */
#define CHECKSUM_CHECK_UDP_HW (1 && CHECKSUM_CHECK_UDP) /*  hardware switch */
// tx offload cksum
#define CHECKSUM_GEN_IP_HW    (1 && CHECKSUM_GEN_IP) /* hardware switch */
#define CHECKSUM_GEN_TCP_HW   (1 && CHECKSUM_GEN_TCP) /*  hardware switch */
#define CHECKSUM_GEN_UDP_HW   (1 && CHECKSUM_GEN_UDP) /*  hardware switch */

#define CHECKSUM_OFFLOAD_ALL (CHECKSUM_GEN_IP_HW || CHECKSUM_GEN_TCP_HW || CHECKSUM_CHECK_IP_HW || CHECKSUM_CHECK_TCP_HW || CHECKSUM_CHECK_UDP_HW || CHECKSUM_GEN_UDP_HW)


/*
   ---------------------------------------
   ---------- lwIP APIs options ----------
   ---------------------------------------
*/
#define LWIP_TCPIP_CORE_LOCKING 1

#define LWIP_TCPIP_TIMEOUT 0

#define TCPIP_MBOX_SIZE (MEMP_NUM_TCPIP_MSG_API)

#define LWIP_NETCONN 1

#define LWIP_NETCONN_SEM_PER_THREAD 0

#define LWIP_STATS 1

#define LWIP_STATS_DISPLAY 1

#define LWIP_TIMERS 1

#define LWIP_TIMEVAL_PRIVATE 0


/*
   ------------------------------------------------
   ---------- Internal Memory Pool Sizes ----------
   ------------------------------------------------
*/
#define GAZELLE_MAX_CLIENTS (20000)
#define GAZELLE_RESERVED_CLIENTS (2000)

#define LWIP_SUPPORT_CUSTOM_PBUF 1

#define MEMP_MEM_MALLOC 0
#define MEM_LIBC_MALLOC 0
#define MEM_USE_POOLS 0
#define MEMP_USE_CUSTOM_POOLS 0

#define MEMP_NUM_TCP_PCB_LISTEN 3000

#define MEMP_NUM_TCP_PCB (GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS)

#define MEMP_NUM_NETCONN (GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS)

#define MEMP_NUM_SYS_SEM (GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS)

#define MEMP_NUM_SYS_MBOX (GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS)

#define PBUF_POOL_SIZE (GAZELLE_MAX_CLIENTS * 2)

/* we use PBUF_POOL instead of PBUF_RAM in tcp_write, so reduce PBUF_RAM size,
 * and do NOT let PBUF_POOL_BUFSIZE less then TCP_MSS
*/
#define MEMP_NUM_TCP_SEG (128 * 128 * 2)
#define PER_TCP_PCB_BUFFER (16 * 128)
#define MEM_SIZE (((PER_TCP_PCB_BUFFER + 128) * MEMP_NUM_TCP_SEG) >> 2)


/*
   ---------------------------------
   ---------- ARP options ----------
   ---------------------------------
*/
#define LWIP_ARP 1

#define ARP_TABLE_SIZE 512

#define ARP_QUEUEING 1

#define ARP_QUEUE_LEN 32

#define ETHARP_SUPPORT_STATIC_ENTRIES 1


/*
   ---------------------------------
   ---------- IP options ----------
   ---------------------------------
*/
#define LWIP_IPV4 1

#define IP_FORWARD 0

#define IP_REASSEMBLY 1

#define IP_HLEN 20


/*
   ---------------------------------
   ---------- UDP options ----------
   ---------------------------------
*/
#define LWIP_UDP 1

#define UDP_HLEN 8

#define MEMP_NUM_UDP_PCB 16
#define MEMP_NUM_IGMP_GROUP 16

#define DEFAULT_UDP_RECVMBOX_SIZE 4096


/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/
#define LWIP_TCP 1

#define TCP_HLEN 20

#define DEFAULT_ACCEPTMBOX_SIZE 1024
#define DEFAULT_TCP_RECVMBOX_SIZE 4096

#define TCP_LISTEN_BACKLOG 1
#define TCP_DEFAULT_LISTEN_BACKLOG 0xff

#define TCP_OVERSIZE 0
#define LWIP_NETIF_TX_SINGLE_PBUF 0

#define TCP_MSS (FRAME_MTU - IP_HLEN - TCP_HLEN)

#define TCP_WND (2500 * TCP_MSS)

#define TCP_SND_BUF (2500 * TCP_MSS)

#define TCP_SND_QUEUELEN (8191)

#define TCP_SNDLOWAT (TCP_SND_BUF / 5)

#define TCP_SNDQUEUELOWAT (TCP_SND_QUEUELEN / 5)

#define LWIP_TCP_KEEPALIVE 1

#define GAZELLE_TCP_MAX_CONN_PER_THREAD 65535
#define GAZELLE_TCP_REUSE_IPPORT 1


/*
   ------------------------------------
   ---------- Socket options ----------
   ------------------------------------
*/
#define LWIP_SOCKET 1

#define LWIP_SOCKET_POLL   0

#define LWIP_SO_SNDTIMEO 0

#define LWIP_SO_LINGER 0

#define SO_REUSE 1

#define FIONBIO 0x5421 /* same as define in asm-generic/ioctls.h */

#define O_NONBLOCK 04000 /* same as define in bits/fcntl-linux.h */

#define SIOCSHIWAT 1

/*
   ------------------------------------
   ---------- Netif options ----------
   ------------------------------------
*/
#define LWIP_NETIF_LOOPBACK 1

#endif /* __LWIPOPTS_H__ */
