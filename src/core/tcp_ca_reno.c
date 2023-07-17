#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
u32_t tcp_reno_slow_start(struct tcp_pcb *pcb, u32_t acked)
{
	/* u32_t delta = LWIP_MIN(acked, (u32_t)pcb->ssthresh - pcb->cwnd);

	acked -= delta; */
	u32_t num_seg = (pcb->flags & TF_RTO) ? 1 : 2;
  acked = LWIP_MIN(acked, num_seg * pcb->mss);
	TCP_WND_INC(pcb->cwnd, acked);
  LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %"TCPWNDSIZE_F"\n", pcb->cwnd));

	/* return acked; */
	return 0;
}

void tcp_reno_cong_avoid(struct tcp_pcb *pcb, u32_t acked)
{
	/* In "safe" area, increase. */
	if (tcp_in_slow_start(pcb)) {
		tcp_reno_slow_start(pcb, acked);
		return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(pcb, pcb->cwnd, acked);
}

/* Slow start threshold is half the congestion window (min 2) */
tcpwnd_size_t tcp_reno_ssthresh(struct tcp_pcb *pcb)
{
	return LWIP_MAX(pcb->cwnd >> 1U, 2 * pcb->mss);
}

struct tcp_congestion_ops tcp_ca_reno = {
	tcp_reno_ssthresh,
	tcp_reno_cong_avoid,
  NULL,
  NULL,
	NULL,
  "reno",
  NULL
};
