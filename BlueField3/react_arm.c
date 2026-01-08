
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>  // for usleep()

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <signal.h>


#include <doca_log.h>
#include <doca_flow.h>

#include "flow_common.h"
#include "react.h"

#define ETH_LEN 14
#define IP_LEN 20
#define UDP_LEN   8


DOCA_LOG_REGISTER(REACT);


bool force_quit = false;


/**
 * Signal handler for graceful termination.
 *
 * @param signum Signal number received (e.g., SIGINT or SIGTERM)
 */
void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		global_force_quit = true;
	}
}

/**
 * Flush all RX queues for a specific DPDK port.
 *
 * @param port_id [in] The ID of the port whose queues will be flushed.
 */
void
flush_queues(int port_id)
{
	struct rte_mbuf *packets[PACKET_BURST];
        int nb_packets = 0;
        for (int queue_id=0; queue_id < 16; queue_id++) {
        	while(1)
	        {
            		nb_packets = rte_eth_rx_burst(port_id, queue_id, packets, PACKET_BURST);
             		if(nb_packets<=0)
                		break;
		}
        }
}

/**
 * Extract and log key header fields from a raw Ethernet frame for debugging.
 *
 * This function parses an IPv4/UDP packet out of the raw buffer, converts
 * network-order fields into host order, retrieves any attached dynamic flow
 * metadata, and emits a single log line. The output format is:
 *   Packet <num>: <src-ip>:<src-port> → <dst-ip>:<dst-port> proto <ip-proto>, Meta: <metadata>
 *
 * @param raw   Pointer to the start of the Ethernet frame in memory.
 *              Assumed to contain at least an IPv4 header immediately
 *              following the 14-byte Ethernet header.
 * @param num   Index of this packet in the current processing batch (for label).
 * @param pkt   Pointer to the rte_mbuf structure wrapping the packet, used
 *              to fetch any dynamic metadata via RTE_FLOW_DYNF_METADATA().
 */
void print_packet(uint8_t *raw, int num, struct rte_mbuf *pkt)
{

    // --- extract in‐wire (network byte order) fields ---
    uint32_t sip_net   = *(uint32_t *)(raw + ETH_LEN + 12);
    uint32_t dip_net   = *(uint32_t *)(raw + ETH_LEN + 16);
    uint16_t sport_net = *(uint16_t *)(raw + ETH_LEN + IP_LEN + 0);
    uint16_t dport_net = *(uint16_t *)(raw + ETH_LEN + IP_LEN + 2);
    uint8_t  proto     = *(raw + ETH_LEN + 9);  // IP header byte 9 = protocol

    // --- convert to host order ---
    uint32_t sip   = rte_be_to_cpu_32(sip_net);
    uint32_t dip   = rte_be_to_cpu_32(dip_net);
    uint16_t sport = rte_be_to_cpu_16(sport_net);
    uint16_t dport = rte_be_to_cpu_16(dport_net);

    uint32_t meta =  *RTE_FLOW_DYNF_METADATA(pkt);


    // --- log as: Packet i: 10.0.0.1:1234 -> 10.0.0.2:53 proto 17 ---
    DOCA_LOG_INFO("Packet %d: %u.%u.%u.%u:%u → %u.%u.%u.%u:%u proto %u. Meta: %u",
        num,
        (sip >> 24) & 0xFF, (sip >> 16) & 0xFF,
        (sip >>  8) & 0xFF, (sip      ) & 0xFF,
        sport,
        (dip >> 24) & 0xFF, (dip >> 16) & 0xFF,
        (dip >>  8) & 0xFF, (dip      ) & 0xFF,
        dport,
        proto,
        meta);
}

/** *
 * Waits until rx_q[i] changes twice (i.e., sees three distinct values).
 * Assumes port_id is valid and i < RTE_ETHDEV_QUEUE_STAT_CNTRS.
 * 
 * @param port_id [in] The ID of the port to monitor.
 * @param queue_index [in] The index of the RX queue to monitor.
 * @param poll_interval_us [in] The interval in microseconds to wait between polls.
 */
void wait_for_rx_qi_changes(uint16_t port_id, uint16_t queue_index, uint64_t poll_interval_us) {
    struct rte_eth_stats stats;
    uint64_t last = 0, prev = 0;
    int change_count = 0;

    if (rte_eth_stats_get(port_id, &stats) != 0) {
        DOCA_LOG_INFO("Failed to get stats for port %u", port_id);
        return;
    }

    prev = stats.q_ipackets[queue_index];

    while (change_count < 2 && !global_force_quit) {
        usleep(poll_interval_us);

        if (rte_eth_stats_get(port_id, &stats) != 0) {
            DOCA_LOG_INFO("Failed to get stats for port %u", port_id);
            return;
        }

        last = stats.q_ipackets[queue_index];

        if (last != prev) {
            change_count++;
            prev = last;
        }
    }
}

 /**
 * Continuously pull DNS packets from a DPDK RX queues, apply ReAct’s Bloom‐filter
 * logic to record outgoing requests and filter incoming responses, and forward
 * only those responses whose transaction IDs were seen earlier. 
 * 
 * Works for couting bloom filters only. For other types of bloom filter use process_packet() or process_packet_optimized().
 *
 * @param queue_index     DPDK port queue identifier to poll for RX/TX bursts.
 * @param bf_add          The couting bloom filter
 * @param optimized_bloom Whether the bloom filter is a power or two or not.
 * @param within_burst    Output flag set to true if any packets were received in
 *                        the most recent burst; false otherwise.
 * @return                Always returns 0.
 */

 int
process_packets_counting(int queue_index, bloom_filter_t *bf_add,  bool optimized_bloom,  bool *within_burst)
{
    int nb_packets = 0;
 	int i;
    struct rte_mbuf *tx_bufs[TX_BURST];
    uint16_t tx_count = 0;
    uint64_t last_flush_tsc = rte_get_tsc_cycles();
    struct rte_mbuf *packets[PACKET_BURST];    
    enum burst_direction burst_type;

    while(!force_quit)
    {
        *within_burst = false;
        burst_type = OUTGOING_REQUESTS;
        nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
        if(nb_packets<=0) {
            burst_type = INCOMING_RESPONSES;
            nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
            if(nb_packets<=0)  {
                continue;
            }
        }
        *within_burst = true;
        uint64_t now = rte_get_tsc_cycles();

        /* Bloom filters are precomputed for the entire burst */

        
        if (bf_add == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d", rte_lcore_id());
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }
        else if (bf_add->count_array == NULL) {
            DOCA_LOG_ERR("Uninitialized bit array;  lcore %d", rte_lcore_id());
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }


        /* Per Packet Loop we want to optimize */
        for (i = 0; i < nb_packets; i++) {
            struct rte_mbuf *pkt = packets[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
            struct rte_ipv4_hdr *ipv4_hdr;
            uint8_t key[12] = {0};  // 4+4+2+2 = 12 bytes

            // Check if packet is IPv4
            if (RTE_BE16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) 
                continue;
            ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            uint8_t proto = ipv4_hdr->next_proto_id;
            if (proto != IPPROTO_UDP) 
                continue;

            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
            uint8_t *dns_hdr = ((uint8_t *)udp_hdr) + sizeof(struct rte_udp_hdr);        
            memcpy(&key[0], &ipv4_hdr->src_addr, 4);       // source IP
            memcpy(&key[4], &ipv4_hdr->dst_addr, 4);       // destination IP
            memcpy(&key[8], &udp_hdr->dst_port, 2);        // client port (destination UDP port)
            memcpy(&key[10], dns_hdr, 2);                  // DNS transaction ID
            if (burst_type == OUTGOING_REQUESTS) 
            {
                bloom_add(bf_add,key,12);
                rte_pktmbuf_free(pkt);
            }
            else  
            {   
                // INCOMING_RESPONSES
                uint32_t h1, h2;
                if(optimized_bloom)
                {
                    bloom_get_indices_optimized(key,  12, bf_add->size, &h1, &h2);
                } else {
                    bloom_get_indices(key,  12, bf_add->size, &h1, &h2);
                }
                if(bloom_check_with_indices(bf_add,h1,h2)) 
                {
                    tx_bufs[tx_count++] = pkt;

                     if (tx_count == TX_BURST) {
                        rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
                        tx_count = 0;
                        last_flush_tsc = now;
                    }
                }
                else
                {
                    rte_pktmbuf_free(pkt); // dropped, one BF for counting, two for classic/thread-safe
                } 
            }
        }
        if (tx_count > 0 && (now - last_flush_tsc > FLUSH_INTERVAL_CYCLES)) {
            rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
            tx_count = 0;
            last_flush_tsc = now;
        }
    }

	return 0;

}

/**
 * Update an exponential moving average (EMA) in place.
 *
 * This function applies the formula:
 *     ema_new = α * ema_old + (1 – α) * sample
 * where α ∈ [0,1] is the smoothing factor controlling how much weight
 * to give the old EMA versus the new sample:
 *   – α close to 1.0 makes the EMA change more slowly (more inertia)
 *   – α close to 0.0 makes the EMA respond more quickly to recent samples
 *
 * @param ema_ptr  Pointer to the current EMA value; on return it holds the updated EMA.
 * @param sample   The new data point to incorporate into the EMA.
 * @param alpha    The smoothing factor for the old EMA (0 ≤ alpha ≤ 1).
 */
void EMA(double *old, double new, double alpha)
{
    *old = (*old)* alpha + (1-alpha)*new;
}

 /**
 * Continuously pull DNS packets from a DPDK RX queues, apply ReAct’s Bloom‐filter
 * logic to record outgoing requests and filter incoming responses, and forward
 * only those responses whose transaction IDs were seen earlier. 
 * 
 * Throughout its main loop, this function uses an exponential moving average (EMA) to track
 * the CPU cycles spent in four stages: burst initialization, request handling,
 * response filtering, and packet transmission. When the process exits, it logs
 * the per‐stage cycle averages for performance analysis.
 *
 * Assumes bloom filter is a power of two, hash on L3/L4 packet header is computed in the 
 * hardware and is in the packet metadata, checks on packets indivudally are done on in 
 * the hardware. 
 * 
 * @param queue_index    DPDK port queue identifier to poll for RX/TX bursts.
 * @param bfs            Array of three bloom_filter_t pointers: 
 *                       – bfs[phase]       : current filter for inserting requests  
 *                       – bfs[(phase+1)%3] : spare filter  
 *                       – bfs[(phase+2)%3] : previous-phase filter for checking responses
 * @param within_burst   Output flag set to true if any packets were received in
 *                       the most recent burst; false otherwise.
 * @param phase          Pointer to the current “phase” index (0–2), used to
 *                       rotate through the three Bloom filters each epoch.
 * @return               Always returns 0.
 */

int
process_packets_optimized_measure_cycles(int queue_index, bloom_filter_t **bfs,  bool *within_burst, int *phase)
{

    bloom_type_t type = bfs[0]->type;


	int nb_packets = 0;
 	int i;
    struct rte_mbuf *tx_bufs[TX_BURST];
    uint16_t tx_count = 0;
    uint64_t last_flush_tsc = rte_get_tsc_cycles();
    struct rte_mbuf *packets[PACKET_BURST];    
    enum burst_direction burst_type;

    double cycles_init_burst = 0;
    double cycles_requests = 0;
    double cycles_responses = 0;
    double cycles_tx = 0;
    while(!force_quit)
    {
        *within_burst = false;
        burst_type = OUTGOING_REQUESTS;
        nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
        if(nb_packets<=0) {
            burst_type = INCOMING_RESPONSES;
            nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
            if(nb_packets<=0)  {
                continue;
            }
        }

        rte_prefetch0(rte_pktmbuf_mtod(packets[0], void *));

        *within_burst = true;
        uint64_t now = rte_get_tsc_cycles();

        /* Bloom filters are precomputed for the entire burst */
        bloom_filter_t *bf_add = bfs[*phase];
        bloom_filter_t *bf_check = bf_add; 
        uint64_t *bf_check_array, *bf_add_array; 

        if (bf_add == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }

        if (type == BLOOM_THREAD_SAFE) {
            if (bf_add->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                    for (i = 0; i < nb_packets; i++) {
                        rte_pktmbuf_free(packets[i]);
                    }
                    continue;
            } else {
                bf_add_array = (uint64_t *)bf_add->bit_array_ts;
            }
        }
        else { //BLOOM_THREAD_CLASSIC
            if (bf_add->bit_array == NULL) 
            {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_add_array = (uint64_t *)bf_add->bit_array;
            }
        }

        bf_check = bfs[(*phase+2)%3];
        
        if (bf_check == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }
        
        if (type == BLOOM_THREAD_SAFE)
        {
            if( bf_check->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array_ts;
            }
        }
        else //type == BLOOM_CLASSIC
        {   
            if(bf_check->bit_array == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array;
            }
        }

        double now2 = rte_get_tsc_cycles();
        EMA(&cycles_init_burst, now2-now, 0.1);

        /* Per Packet Loop we want to optimize */
        for (i = 0; i < nb_packets; i++) {
            double now3 = rte_get_tsc_cycles();
            if (i + 1 < nb_packets) {
                rte_prefetch0(rte_pktmbuf_mtod(packets[i+1], void *));
            }

            struct rte_mbuf *pkt = packets[i];
            uint8_t *raw = rte_pktmbuf_mtod(pkt, uint8_t *);
            uint16_t *dns_id16 = (uint16_t *)(raw + ETH_LEN + IP_LEN + UDP_LEN);
            uint32_t meta =  *RTE_FLOW_DYNF_METADATA(pkt);

            uint32_t h1, h2;
            bloom_get_indices_optimized_with_seed(meta,  *dns_id16, bf_add->size, &h1, &h2);
  
  
            if (burst_type == OUTGOING_REQUESTS) 
            {
                bloom_add_bit_array(type, bf_add_array, h1, h2);
                rte_pktmbuf_free(pkt);
                double now4 = rte_get_tsc_cycles();
                EMA(&cycles_requests, now4-now3, 0.1);
            }
            else  
            {   
                // INCOMING_RESPONSES
                if(bloom_check_bit_array(bf_add_array,h1,h2) || bloom_check_bit_array(bf_check_array,h1,h2)) 
                {
                    tx_bufs[tx_count++] = pkt;

                     if (tx_count == TX_BURST) {
                        rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
                        tx_count = 0;
                        last_flush_tsc = now;
                    }
                }
                else
                {
                    rte_pktmbuf_free(pkt); // dropped, one BF for counting, two for classic/thread-safe
                } 
                double now5 = rte_get_tsc_cycles();
                EMA(&cycles_responses,now5-now3, 0.1);

            }
        }
        if (tx_count > 0 && (now - last_flush_tsc > FLUSH_INTERVAL_CYCLES)) {
            double now6 = rte_get_tsc_cycles();
                
            rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
            tx_count = 0;
            last_flush_tsc = now;
            double now7 = rte_get_tsc_cycles();
            EMA(&cycles_tx,now7-now6, 0.1);
        }
    }

    DOCA_LOG_INFO("Core %d Cycles to init burst %lf", rte_lcore_id(), cycles_init_burst);
    DOCA_LOG_INFO("Core %d Cycles per request %lf", rte_lcore_id(), cycles_requests);
    DOCA_LOG_INFO("Core %d Cycles per response %lf", rte_lcore_id(), cycles_responses);
    DOCA_LOG_INFO("Core %d Cycles per tx %lf", rte_lcore_id(), cycles_tx);
	return 0;
}

 /**
 * Continuously pull DNS packets from a DPDK RX queues, apply ReAct’s Bloom‐filter
 * logic to record outgoing requests and filter incoming responses, and forward
 * only those responses whose transaction IDs were seen earlier. 
 * 
 * Assumes bloom filter is a power of two, hash on L3/L4 packet header is computed in the 
 * hardware and is in the packet metadata, checks on packets indivudally are done on in 
 * the hardware.
 *
 * @param queue_index    DPDK port queue identifier to poll for RX/TX bursts.
 * @param bfs            Array of three bloom_filter_t pointers: 
 *                       – bfs[phase]       : current filter for inserting requests  
 *                       – bfs[(phase+1)%3] : spare filter  
 *                       – bfs[(phase+2)%3] : previous-phase filter for checking responses
 * @param within_burst   Output flag set to true if any packets were received in
 *                       the most recent burst; false otherwise.
 * @param phase          Pointer to the current “phase” index (0–2), used to
 *                       rotate through the three Bloom filters each epoch.
 * @return               Always returns 0.
 */
int
process_packets_optimized(int queue_index, bloom_filter_t **bfs,  bool *within_burst, int *phase)
{

    bloom_type_t type = bfs[0]->type;


	int nb_packets = 0;
 	int i;
    struct rte_mbuf *tx_bufs[TX_BURST];
    uint16_t tx_count = 0;
    uint64_t last_flush_tsc = rte_get_tsc_cycles();
    struct rte_mbuf *packets[PACKET_BURST];    
    enum burst_direction burst_type;

    while(!force_quit)
    {
        *within_burst = false;
        burst_type = OUTGOING_REQUESTS;
        nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
        if(nb_packets<=0) {
            burst_type = INCOMING_RESPONSES;
            nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
            if(nb_packets<=0)  {
                continue;
            }
        }

        rte_prefetch0(rte_pktmbuf_mtod(packets[0], void *));

        *within_burst = true;
        uint64_t now = rte_get_tsc_cycles();

        /* Bloom filters are precomputed for the entire burst */
        bloom_filter_t *bf_add = bfs[*phase];
        bloom_filter_t *bf_check = bf_add; 
        uint64_t *bf_check_array, *bf_add_array; 

        if (bf_add == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }

        if (type == BLOOM_THREAD_SAFE) {
            if (bf_add->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                    for (i = 0; i < nb_packets; i++) {
                        rte_pktmbuf_free(packets[i]);
                    }
                    continue;
            } else {
                bf_add_array = (uint64_t *)bf_add->bit_array_ts;
            }
        }
        else { //BLOOM_THREAD_CLASSIC
            if (bf_add->bit_array == NULL) 
            {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_add_array = (uint64_t *)bf_add->bit_array;
            }
        }

        bf_check = bfs[(*phase+2)%3];
        
        if (bf_check == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }
        
        if (type == BLOOM_THREAD_SAFE)
        {
            if( bf_check->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array_ts;
            }
        }
        else //type == BLOOM_CLASSIC
        {   
            if(bf_check->bit_array == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array;
            }
        }

        /* Per Packet Loop we want to optimize */
        for (i = 0; i < nb_packets; i++) {
            if (i + 1 < nb_packets) {
                rte_prefetch0(rte_pktmbuf_mtod(packets[i+1], void *));
            }
            struct rte_mbuf *pkt = packets[i];
            uint8_t *raw = rte_pktmbuf_mtod(pkt, uint8_t *);
            uint16_t *dns_id16 = (uint16_t *)(raw + ETH_LEN + IP_LEN + UDP_LEN);
            uint32_t meta =  *RTE_FLOW_DYNF_METADATA(pkt);
            uint32_t h1, h2;
            bloom_get_indices_optimized_with_seed(meta,  *dns_id16, bf_add->size, &h1, &h2);
  
            if (burst_type == OUTGOING_REQUESTS) 
            {
                bloom_add_bit_array(type, bf_add_array, h1, h2);
                rte_pktmbuf_free(pkt);
            }
            else  
            {   
                // INCOMING_RESPONSES
                if(bloom_check_bit_array(bf_add_array,h1,h2) || bloom_check_bit_array(bf_check_array,h1,h2)) 
                {
                    tx_bufs[tx_count++] = pkt;

                     if (tx_count == TX_BURST) {
                        rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
                        tx_count = 0;
                        last_flush_tsc = now;
                    }
                }
                else
                {
                    rte_pktmbuf_free(pkt); // dropped, one BF for counting, two for classic/thread-safe
                } 
            }
        }
        if (tx_count > 0 && (now - last_flush_tsc > FLUSH_INTERVAL_CYCLES)) {
            rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
            tx_count = 0;
            last_flush_tsc = now;
        }
    }

	return 0;
}

/**
 * Dequeue packets from DPDK queues and process DNS keys using ReAct's Bloom filters (non-optimized)
 *
 * @param args [in] A pointer to worker_params struct including queue index, phase, and Bloom filters.
 * @return Always returns 0.
 */
int
process_packets(void *args)
{
    int queue_index =((worker_params *)args)->queue_index;
    int *phase =((worker_params *)args)->phase;
    bloom_filter_t **bfs = ((worker_params *)args)->bfs;
    bool *within_burst = ((worker_params *)args)->within_burst;
    bool optimized_bloom = ((worker_params *) args)->optimized_bloom;

    bloom_type_t type = bfs[0]->type;

    if(type==BLOOM_COUNTING)
    {

        return process_packets_counting(queue_index,bfs[0],optimized_bloom, within_burst);
    }
    if(optimized_bloom)
    {
        return process_packets_optimized(queue_index, bfs,  within_burst, phase);
    }

	int nb_packets = 0;
 	int i;
    struct rte_mbuf *tx_bufs[TX_BURST];
    uint16_t tx_count = 0;
    uint64_t last_flush_tsc = rte_get_tsc_cycles();
    struct rte_mbuf *packets[PACKET_BURST];    
    enum burst_direction burst_type;

    while(!force_quit)
    {
        *within_burst = false;
        burst_type = OUTGOING_REQUESTS;
        nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
        if(nb_packets<=0) {
            burst_type = INCOMING_RESPONSES;
            nb_packets = rte_eth_rx_burst(burst_type, queue_index, packets, PACKET_BURST);
            if(nb_packets<=0)  {
                continue;
            }
        }
        *within_burst = true;
        uint64_t now = rte_get_tsc_cycles();

        /* Bloom filters are precomputed for the entire burst */
        bloom_filter_t *bf_add = bfs[*phase];
        bloom_filter_t *bf_check = bf_add; 
        uint64_t *bf_check_array, *bf_add_array; 

        if (bf_add == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }

        if (type == BLOOM_THREAD_SAFE) {
            if (bf_add->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                    for (i = 0; i < nb_packets; i++) {
                        rte_pktmbuf_free(packets[i]);
                    }
                    continue;
            } else {
                bf_add_array = (uint64_t *)bf_add->bit_array_ts;
            }
        }
        else { //BLOOM_THREAD_CLASSIC
            if (bf_add->bit_array == NULL) 
            {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_add_array = (uint64_t *)bf_add->bit_array;
            }
        }

        bf_check = bfs[(*phase+2)%3];
        
        if (bf_check == NULL) {
            DOCA_LOG_ERR("Uninitialized Bloom filter;  lcore %d, phase %d", rte_lcore_id(), *phase);
            for (i = 0; i < nb_packets; i++) {
                rte_pktmbuf_free(packets[i]);
            }
            continue;
        }
        
        if (type == BLOOM_THREAD_SAFE)
        {
            if( bf_check->bit_array_ts == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array; lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array_ts;
            }
        }
        else //type == BLOOM_CLASSIC
        {   
            if(bf_check->bit_array == NULL) {
                DOCA_LOG_ERR("Uninitialized bit array;  lcore %d, phase %d", rte_lcore_id(), *phase);
                for (i = 0; i < nb_packets; i++) {
                    rte_pktmbuf_free(packets[i]);
                }
                continue;
            }
            else {
                bf_check_array = (uint64_t *)bf_check->bit_array;
            }
        }

        /* Per Packet Loop we want to optimize */
        for (i = 0; i < nb_packets; i++) {
            struct rte_mbuf *pkt = packets[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
            struct rte_ipv4_hdr *ipv4_hdr;
            uint8_t key[12] = {0};  // 4+4+2+2 = 12 bytes

            // Check if packet is IPv4
            if (RTE_BE16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) 
                continue;
            ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            uint8_t proto = ipv4_hdr->next_proto_id;
            if (proto != IPPROTO_UDP) 
                continue;

            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
            uint8_t *dns_hdr = ((uint8_t *)udp_hdr) + sizeof(struct rte_udp_hdr);        
            memcpy(&key[0], &ipv4_hdr->src_addr, 4);       // source IP
            memcpy(&key[4], &ipv4_hdr->dst_addr, 4);       // destination IP
            memcpy(&key[8], &udp_hdr->dst_port, 2);        // client port (destination UDP port)
            memcpy(&key[10], dns_hdr, 2);                  // DNS transaction ID
            if (burst_type == OUTGOING_REQUESTS) 
            {
                bloom_add(bf_add,key,12);
                rte_pktmbuf_free(pkt);
            }
            else  
            {   
                // INCOMING_RESPONSES
                uint32_t h1, h2;
                if(optimized_bloom)
                {
                    bloom_get_indices_optimized(key,  12, bf_add->size, &h1, &h2);
                } else {
                    bloom_get_indices(key,  12, bf_add->size, &h1, &h2);
                }
                if(bloom_check_bit_array(bf_add_array,h1,h2)) 
                {
                    tx_bufs[tx_count++] = pkt;

                     if (tx_count == TX_BURST) {
                        rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
                        tx_count = 0;
                        last_flush_tsc = now;
                    }
                    //rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, &pkt, 1);
                }
                else if(bloom_check_bit_array(bf_check_array,h1,h2))
                {
                    tx_bufs[tx_count++] = pkt;

                     if (tx_count == TX_BURST) {
                        rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
                        tx_count = 0;
                        last_flush_tsc = now;
                    }
                    //rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, &pkt, 1);
                }
                else
                {
                    rte_pktmbuf_free(pkt); // dropped, one BF for counting, two for classic/thread-safe
                } 

            }
        }
        if (tx_count > 0 && (now - last_flush_tsc > FLUSH_INTERVAL_CYCLES)) {
            rte_eth_tx_burst(OUTGOING_REQUESTS, queue_index, tx_bufs, tx_count);
            tx_count = 0;
            last_flush_tsc = now;
        }
    }

	return 0;
}
