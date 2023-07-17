#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include <string.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define HZ 1000 /* sys_now() time unit, ms */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	LWIP_MIN(LWIP_MAX(x, HYSTART_DELAY_MIN), HYSTART_DELAY_MAX)

static u32_t fast_convergence = 1;
static u32_t beta = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static u32_t bic_scale = 41;
static u32_t tcp_friendliness = 1;

static u32_t hystart = 1;
static u32_t hystart_detect = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static u32_t hystart_low_window = 16;
static u32_t hystart_ack_delta_ms = 2000;

static u32_t cube_rtt_scale;
static u32_t beta_scale;
static u64_t cube_factor;


/* BIC TCP Parameters */
struct bictcp {
	u32_t	cnt;		/* increase cwnd by 1 after ACKs */
	u32_t	last_max_cwnd;	/* last maximum snd_cwnd */
	u32_t	last_cwnd;	/* the last snd_cwnd */
	u32_t	last_time;	/* time when updated last_cwnd */
	u32_t	bic_origin_point;/* origin point of bic function */
	u32_t	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32_t	delay_min;	/* min delay (msec) */
	u32_t	epoch_start;	/* beginning of an epoch */
	u32_t	ack_cnt;	/* number of acks */
	u32_t	tcp_cwnd;	/* estimated tcp cwnd */
	u32_t mss;

  /* for hystart*/
	u16_t	unused;
	u8_t	sample_cnt;	/* number of samples to decide curr_rtt */
	u8_t	found;		/* the exit point is found? */
	u32_t	round_start;	/* beginning of each round */
	u32_t	end_seq;	/* end_seq of the round */
	u32_t	last_ack;	/* last time when the ACK spacing is close */
	u32_t	curr_rtt;	/* the minimum rtt of current round */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	memset(ca, 0, offsetof(struct bictcp, unused));
	ca->found = 0;
}

static inline void bictcp_hystart_reset(struct tcp_pcb *pcb)
{
	struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;

	ca->round_start = ca->last_ack = pcb->lacktime;
	ca->end_seq = pcb->snd_nxt;
	ca->curr_rtt = ~0U;
	ca->sample_cnt = 0;
}

static void tcp_cubic_init(struct tcp_pcb *pcb)
{
  struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;

	bictcp_reset(ca);

	cube_rtt_scale = bic_scale * 10;
	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3 / (BICTCP_BETA_SCALE - beta);
	cube_factor = (((u64_t)1) << (10+3*BICTCP_HZ)) / cube_rtt_scale;

  if (hystart)
		bictcp_hystart_reset(pcb);

}

static void tcp_cubic_cwnd_event(struct tcp_pcb *pcb, u8_t event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;
		u32_t now = sys_now();
		s32_t delta;

		delta = now - pcb->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (TCP_SEQ_GT(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

static u32_t fls64(uint64_t v)
{
	static const u64_t debruijn_multiplicator = 0x6c04f118e9966f6bUL;
	static const u8_t debruijn_bit_position[128] = {
		0, /* change to 1 if you want bitSize(0) = 1 */
		48, -1, -1, 31, -1, 15, 51, -1, 63, 5, -1, -1, -1, 19, -1,
		23, 28, -1, -1, -1, 40, 36, 46, -1, 13, -1, -1, -1, 34, -1, 58,
		-1, 60, 2, 43, 55, -1, -1, -1, 50, 62, 4, -1, 18, 27, -1, 39,
		45, -1, -1, 33, 57, -1, 1, 54, -1, 49, -1, 17, -1, -1, 32, -1,
		53, -1, 16, -1, -1, 52, -1, -1, -1, 64, 6, 7, 8, -1, 9, -1,
		-1, -1, 20, 10, -1, -1, 24, -1, 29, -1, -1, 21, -1, 11, -1, -1,
		41, -1, 25, 37, -1, 47, -1, 30, 14, -1, -1, -1, -1, 22, -1, -1,
		35, 12, -1, -1, -1, 59, 42, -1, -1, 61, 3, 26, 38, 44, -1, 56
	};

	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;
	return debruijn_bit_position[(u64_t)(v * debruijn_multiplicator) >> 57];
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32_t cubic_root(u64_t a)
{
	u32_t x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8_t v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32_t)v[(u32_t)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32_t)(((u32_t)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32_t)(a / ((u64_t)x * (u64_t)(x - 1))));
	x = ((x * 341) >> 10);
	return x;
}

static inline void tcp_cubic_update(struct bictcp *ca, u32_t cwnd, u32_t acked)
{
	u32_t delta, bic_target, max_cnt;
	u64_t offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */
  cwnd /= ca->mss; /* convert cwnd in byte to cwnd in segment*/

	if (ca->last_cwnd == cwnd &&
	    (s32_t)(sys_now() - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && sys_now() == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = sys_now();

	if (ca->epoch_start == 0) {
		ca->epoch_start = sys_now();	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32_t)(sys_now() - ca->epoch_start);
	t += ca->delay_min;
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	t /= HZ;

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32_t scale = beta_scale;

		delta = ((cwnd * scale) >> 3) * ca->mss;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = LWIP_MAX(ca->cnt, 2U);
}

static u32_t tcp_cubic_slow_start(struct tcp_pcb *pcb, u32_t acked)
{
	u32_t delta = LWIP_MIN(acked, (u32_t)pcb->ssthresh - pcb->cwnd);

	acked -= delta;

	TCP_WND_INC(pcb->cwnd, acked);
  LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %"TCPWNDSIZE_F"\n", pcb->cwnd));

	return acked;
}

static void tcp_cubic_cong_avoid(struct tcp_pcb *pcb, u32_t acked)
{
	struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;
	ca->mss = pcb->mss;

	 if (!pcb->is_cwnd_limited)
		return;

	if (tcp_in_slow_start(pcb)) {
		acked = tcp_cubic_slow_start(pcb, acked);
		if (!acked)
			return;
	}
	tcp_cubic_update(ca, pcb->cwnd, acked);
	tcp_cong_avoid_ai(pcb, ca->cnt * pcb->mss, acked);
}

/* Slow start threshold is half the congestion window (min 2) */
static tcpwnd_size_t tcp_cubic_ssthresh(struct tcp_pcb *pcb)
{
  struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;
	u32_t cwnd = pcb->cwnd / pcb->mss; /* convert cwnd in byte to cwnd in segment*/

  ca->epoch_start = 0;	/* end of epoch */

  if (cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = cwnd;

	return LWIP_MAX((cwnd * beta) / BICTCP_BETA_SCALE, 2) * pcb->mss;
}

static void tcp_cubic_state_update(struct tcp_pcb *pcb, u8_t new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset((struct bictcp *)pcb->tcp_congestion_priv);
		bictcp_hystart_reset(pcb);
	}
}

static void hystart_update(struct tcp_pcb *pcb, u32_t delay)
{
	struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;
	u32_t threshold;

	if (TCP_SEQ_GT(pcb->lastack + 1, ca->end_seq))
		bictcp_hystart_reset(pcb);

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32_t now = pcb->lacktime;

		/* first detection parameter - ack-train detection */
		if ((s32_t)(now - ca->last_ack) <= (s32_t)hystart_ack_delta_ms) {
			ca->last_ack = now;

			threshold = ca->delay_min;

			if ((s32_t)(now - ca->round_start) > (s32_t)threshold) {
				ca->found = 1;
				pcb->ssthresh = pcb->cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->curr_rtt > delay)
			ca->curr_rtt = delay;
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found = 1;
				pcb->ssthresh = pcb->cwnd;
			}
		}
	}
}

static void tcp_cubic_acked(struct tcp_pcb *pcb, u32_t rtt_ms)
{
	struct bictcp *ca = (struct bictcp *)pcb->tcp_congestion_priv;
	u32_t delay;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (pcb->flags & TF_RTO))
		return;

	delay = rtt_ms;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (!ca->found && tcp_in_slow_start(pcb) && hystart &&
	    pcb->cwnd >= hystart_low_window * pcb->mss)
		hystart_update(pcb, delay);
}

struct tcp_congestion_ops tcp_ca_cubic = {
	tcp_cubic_ssthresh,
	tcp_cubic_cong_avoid,
  tcp_cubic_state_update,
  tcp_cubic_cwnd_event,
	tcp_cubic_acked,
  "cubic",
  tcp_cubic_init
};
