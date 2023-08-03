#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"

/* struct tcp_congestion_ops const tcp_ca_lists[] = {};

void tcp_init_congestion_control(struct tcp_pcb *pcb)
{
    if(pcb->cong_ops->init)
	    pcb->cong_ops->init(pcb);
} */

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
void tcp_cong_avoid_ai(struct tcp_pcb *pcb, u32_t w, u32_t acked)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (pcb->bytes_acked >= w) {
		pcb->bytes_acked = 0;
    TCP_WND_INC(pcb->cwnd, pcb->mss);
	}

	TCP_WND_INC(pcb->bytes_acked, acked);
	if (pcb->bytes_acked >= w) {
		u32_t delta = pcb->bytes_acked / w;
		pcb->bytes_acked -= delta * w;
		TCP_WND_INC(pcb->cwnd, delta * pcb->mss);
	}
  LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: congestion avoidance cwnd %"TCPWNDSIZE_F"\n", pcb->cwnd));
}
