#ifndef REACT__H_
#define REACT__H_

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include "flow_common.h"


#define PACKET_BURST 64	/* The number of packets in the rx queue read together */
#define TX_BURST 32 /* The number of packets in the tx queue sent together */
#define FLUSH_INTERVAL_CYCLES (rte_get_timer_hz() / 20000) // 50 µs

//#define HEAD_PACKET_BURST 10
#define MAX_ENTRIES_REACT 50 // for per port memory allocation in DOCA Flow

// --- Bloom filter types ---
typedef enum {
   BLOOM_CLASSIC,
   BLOOM_COUNTING,
   BLOOM_THREAD_SAFE
} bloom_type_t;

// --- Bloom filter struct ---
typedef struct {
   bloom_type_t type;
   size_t size;          // Number of elements (CLASSIC: bits, COUNTING: bytes)
   union {
       uint64_t *bit_array;     // For CLASSIC
       uint8_t *count_array;      // For COUNTING
       _Atomic uint64_t *bit_array_ts;     // For THREAD_SAFE
   };
} bloom_filter_t;

typedef struct {
	 int ingress_port;
	 int queue_index;
    bloom_filter_t **bfs;
    int *phase; /* 0, 1, or 2 */
    int *nb_requests; // not used
    int *nb_responses_fwd; // not used
    int *nb_responses_dropped; // not used
	 double measurment_len; // not used
	 double measurment_freq; // not used
    bool *within_burst;
    bool optimized_bloom; // if true, all bloom filter size will be rounded up to the nearest power of 2
 } worker_params;

 /* ReAct application configuration */
struct react_config {
   struct application_dpdk_config *dpdk_cfg;       /* DPDK configurations */
   size_t bloom_size;                             
   uint16_t bloom_swap_interval;
   bloom_type_t bloom_type; 
   uint16_t nb_cores;
   uint16_t timeout;
   bool optimized_bloom; // if true, all bloom filter size will be rounded up to the nearest power of 2
};

extern bool force_quit;
extern bool global_force_quit;

enum burst_direction { INCOMING_RESPONSES = 0, OUTGOING_REQUESTS = 1 };



/* Signal handler to stop the apps on the arm cores*/
void signal_handler(int signum);

/* Functions that can be run on the arm core */
int process_packets(void *args);

/* Block until we know progress made by the ARM core and it is safe to move on */
void wait_for_rx_qi_changes(uint16_t port_id, uint16_t queue_index, uint64_t poll_interval_us);

/* Pipes and entries paramertized creations */
doca_error_t create_react_pipe(struct doca_flow_port *port, 
                               struct doca_flow_pipe **pipe, 
                               int nb_queues, 
                               enum burst_direction direction); //OUTGOING_REQUESTS or  INCOMING_RESPONSES
                               

doca_error_t create_spraying_pipe(struct doca_flow_port *port, 
                                struct doca_flow_pipe **pipe, 
                                int nb_queues); 
                                
doca_error_t create_copy_to_meta_pipe(struct doca_flow_port *port, 
                                      struct doca_flow_pipe **pipe, 
                                      struct doca_flow_pipe *next_pipe,
                                      int direction); 



/* ReAct's Logic */
doca_error_t flow_react(int dpdk_queues, struct react_config);
                   

/* Bloom Filter methods*/
bloom_filter_t *bloom_init(size_t size_bits, bloom_type_t type, bool optimized_bloom);
void bloom_free(bloom_filter_t *bf);
uint32_t djb2(uint8_t *str, int len);
uint32_t sdbm(uint8_t *str, int len);
void bloom_add(bloom_filter_t *bf,  uint8_t *key, int len);
int bloom_check(bloom_filter_t *bf, uint8_t *key, int len);

int bloom_check_with_indices(bloom_filter_t *bf, uint32_t h1, uint32_t h2);
int bloom_check_bit_array(__uint64_t *bit_array, uint32_t h1, uint32_t h2);
void bloom_add_bit_array(bloom_type_t type, __uint64_t *bit_array, uint32_t h1, uint32_t h2);

/**
 * Get two indices for a Bloom filter based on the key. 
 * 
 * @param key Pointer to the key data.
 * @param len Length of the key data.
 * @param bloom_size Size of the Bloom filter.
 * @param index1 Pointer to store the first index.
 * @param index2 Pointer to store the second index.
 */
static inline void bloom_get_indices(const uint8_t *key, size_t len, uint32_t bloom_size,
   uint32_t *index1, uint32_t *index2) 
{
   uint32_t h1 = 5381;
   uint32_t h2 = 0;

   for (size_t i = 0; i < len; ++i) {
      h1 = ((h1 << 5) + h1) + key[i];                // djb2
      h2 = key[i] + (h2 << 6) + (h2 << 16) - h2;     // sdbm
   }

   *index1 = h1 % bloom_size;
   *index2 = (h1 + h2) % bloom_size;
}

/**
 * Get two indices for a Bloom filter based on the key. 
 * 
 * @param key Pointer to the key data.
 * @param len Length of the key data. 
 * @param bloom_size Size of the Bloom filter.
 * @param index1 Pointer to store the first index.
 * @param index2 Pointer to store the second index.
 */
static inline void bloom_get_indices_optimized(const uint8_t *key, size_t len, uint32_t bloom_size, uint32_t *index1, uint32_t *index2) 
{
   uint32_t h1 = 5381;
   uint32_t h2 = 0;

   for (size_t i = 0; i < len; ++i) {
      h1 = ((h1 << 5) + h1) + key[i];                // djb2
      h2 = key[i] + (h2 << 6) + (h2 << 16) - h2;     // sdbm
   }

   *index1 = h1 & (bloom_size-1);
   *index2 = (h1 + h2) & (bloom_size-1);
}

/**
 * Derive two 32-bit Bloom filter bit positions from a pre-hashed seed and
 * a 16-bit DNS transaction ID, optimized for power-of-two filter sizes.
 *
 * This in-lined function combines:
 *   1. A DJB2-style update of the precomputed hash (`pre_h`) with the two
 *      bytes of the DNS ID to form the first index (h1).
 *   2. A 17-bit rotate of `pre_h`, XOR’d with the DNS ID, to form the
 *      second index (h2).
 * Both indices are then masked down to the Bloom filter’s size (must be
 * a power of two) by AND’ing with (bloom_size − 1).
 *
 * By reusing `pre_h` and a small number of bit operations, this routine
 * avoids full-key hashing and minimizes per-packet computation.
 *
 * @param pre_h        32-bit “seed” hash computed over the first portion of
 *                     the key (e.g., the first 10 bytes of DNS metadata).
 * @param dns_id_net   16-bit DNS transaction ID in network byte order
 *                     (big-endian).
 * @param bloom_size   Size of the Bloom filter in bits; **must** be a
 *                     power of two.
 * @param[out] index1  Receives the first bit position: (DJB2(pre_h, ID) mod bloom_size).
 * @param[out] index2  Receives the second bit position: 
 *                     (ROTL(pre_h,17) ⊕ ID) mod bloom_size.
 */
static inline void
bloom_get_indices_optimized_with_seed(
    uint32_t pre_h,        // 32‐bit hash of first 10 bytes
    uint16_t dns_id_net,   // big‐endian DNS ID (bytes 11–12)
    uint32_t bloom_size,   // power‐of‐two
    uint32_t *index1,
    uint32_t *index2)
{
    // convert DNS ID to host‐order
    uint16_t dns_id = rte_be_to_cpu_16(dns_id_net);

    // --- h1 = djb2(pre_h, dns_id_bytes[0], dns_id_bytes[1]) ---
    // DJB2: h = h*33 + b
    uint32_t h1 = pre_h;
    h1 = ((h1 << 5) + h1) + (uint8_t)(dns_id >> 8);
    h1 = ((h1 << 5) + h1) + (uint8_t)(dns_id & 0xFF);

    // h2: rotate-left pre_h by 17 bits, XOR in dns_id, then mask
    uint32_t h2 = (((pre_h << 17) | (pre_h >> (32 - 17))) ^ (uint32_t)dns_id)
                  & (bloom_size - 1);
    // mask to your bloom‐filter size (power‐of‐two)
    *index1 = h1 & (bloom_size - 1);
    *index2 = h2 & (bloom_size - 1);
}


#endif


