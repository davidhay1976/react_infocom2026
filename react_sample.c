 #include <string.h>
 #include <unistd.h>
 #include <stdlib.h>
 #include <signal.h>

 #include <rte_ethdev.h>
 #include <rte_ip.h>
 #include <rte_tcp.h>
 #include <rte_udp.h>
 #include <rte_malloc.h>
 #include <stdatomic.h>

 #include <doca_flow.h>


 #include <arm_acle.h>

 #include "flow_common.h"
 #include "react.h"

 bool global_force_quit = false;

// Logging registration for the REACT module
 DOCA_LOG_REGISTER(REACT);

 #define META_U32_BIT_OFFSET(idx) \
	(offsetof(struct doca_flow_meta, u32[(idx)]) << 3)
#define NB_ACTION_DESC (4)


/**
 * Compute hash indices for a given key.
 * This function uses CRC32 and FNV-1a hash functions to generate two distinct indices.
 * 
 * @param key Pointer to the key data.
 * @param len Length of the key data.
 * 
 * @notused	
 */
static inline uint32_t crc32_hw(const uint8_t *key, size_t len) {
//	DOCA_LOG_INFO("key: %p", key);
    uint32_t crc = 0;
    for (size_t i = 0; i < len; ++i)
        crc = __crc32b(crc, key[i]);
    return crc;
}

/**
 * Initialize a Bloom filter with a specified size and type.
 *
 * @param size_bits Size in bits for the filter.
 * @param type Type of Bloom filter (classic or counting).
 * @param optimized If true, round the size to the next power of two 
 * @return Pointer to initialized bloom_filter_t or NULL on error.
 * 
 */
bloom_filter_t *bloom_init(size_t size_bits, bloom_type_t type, bool optimized) {
    bloom_filter_t *bf = rte_zmalloc("bloom_filter", sizeof(bloom_filter_t), 0);
    if (!bf) 
	{
		DOCA_LOG_ERR("Failed to allocate memory for Bloom filter");
		return NULL;
	}
    bf->type = type;
    int socket_id = rte_socket_id();
	// Ensure size_bits is at least 1
    if (size_bits < 1 || size_bits > UINT32_MAX) {
	    DOCA_LOG_ERR("Bloom filter size must be at least 1 bit and less than 2^32 bits");
	    rte_free(bf);
	    return NULL;
	}
	 
	if(optimized)
	    size_bits = 1U << (32 - __builtin_clz( (uint32_t)(size_bits - 1))); // round up to nearest power of 2
	size_t byte_size = (size_bits + 7) / 8; // Round up to nearest byte
	size_t word_size = (size_bits + 63) / 64; // Round up to nearest 64-bit word

    if (type == BLOOM_CLASSIC ) {
		bf->size = size_bits;
		bf->bit_array = rte_zmalloc_socket("bloom_array", word_size*sizeof(__uint64_t), RTE_CACHE_LINE_SIZE, socket_id);
        if (!bf->bit_array) {
			DOCA_LOG_ERR("Failed to allocate memory for Bloom filter bit array");
            rte_free(bf);
            return NULL;
        }
    } else if (type == BLOOM_THREAD_SAFE) {
		bf->size = size_bits;
		bf->bit_array_ts = rte_zmalloc_socket("bloom_array", word_size*sizeof(__uint64_t), RTE_CACHE_LINE_SIZE, socket_id);
        if (!bf->bit_array_ts) {
			DOCA_LOG_ERR("Failed to allocate memory for Bloom filter bit array");
            rte_free(bf);
            return NULL;
        }
	} else if (type == BLOOM_COUNTING) {
		bf->size = byte_size;
		bf->count_array = rte_zmalloc_socket("count_array", byte_size, RTE_CACHE_LINE_SIZE, socket_id);
        if (!bf->count_array) {
			DOCA_LOG_ERR("Failed to allocate memory for Bloom filter bit array");
            rte_free(bf);
            return NULL;
        }
    }

    return bf;
}


/**
 * Free memory associated with a Bloom filter.
 *
 * @param bf Pointer to Bloom filter to free.
 */
void bloom_free(bloom_filter_t *bf) {
    if (bf==NULL) 
	{
		return;
	}
		
    if (bf->type == BLOOM_CLASSIC && bf->bit_array !=NULL)
	{
	    rte_free(bf->bit_array);
	}
	else if(bf->type == BLOOM_THREAD_SAFE && bf->bit_array_ts != NULL)
	{
		rte_free(bf->bit_array_ts);
	}
	else if(bf->type == BLOOM_COUNTING && bf->count_array != NULL)
	{
		rte_free(bf->bit_array_ts);
	}
	
	rte_free(bf);
}


/**
 * djb2 hash function used for Bloom filter.
 *
 * @param str Input string to hash.
 * @return 32-bit hash value.
 * 
 * @notused
 */
uint32_t djb2(__uint8_t *str, int len) {
    uint32_t hash = 5381;
	for(int i=0;i<len;i++) 
        hash = ((hash << 5) + hash) + str[i];
    return hash;
}

/**
 * sdbm hash function used for Bloom filter.
 *
 * @param str Input string to hash.
 * @return 32-bit hash value.
 *
 * @notused
 */
uint32_t sdbm(__uint8_t *str, int len) {
    uint32_t hash = 0;
    for(int i=0;i<len;i++) 
        hash = str[i] + (hash << 6) + (hash << 16) - hash;
    return hash;
}

/**
 * This function using FNV-1a hash algorithm to compute a hash index.
 * 
 * @param key Pointer to the key data.
 * @param len Length of the key data.
 * 
 * @notused
 */
static inline uint32_t fnv1a_hash(const uint8_t *key, size_t len) {
//	DOCA_LOG_INFO("key: %p", key);
	uint32_t hash = 2166136261u;  // FNV offset basis
    for (size_t i = 0; i < len; ++i) {
        hash ^= key[i];
        hash *= 16777619u;  // FNV prime
    }
    return hash;
}

/**
 * Add a key to the Bloom filter.
 *
 * @param bf Pointer to the Bloom filter.
 * @param key Key string to add.
 * @param len Length of the key string.
 */
void bloom_add(bloom_filter_t *bf, __uint8_t *key, int len) {
	uint32_t h1, h2;
	bloom_get_indices(key,  len, bf->size, &h1, &h2);

	if (bf->type == BLOOM_CLASSIC) {
		bf->bit_array[h1 / 64] |= (1ULL << (h1 % 64));
    	bf->bit_array[h2 / 64] |= (1ULL << (h2 % 64));
	} else if (bf->type == BLOOM_COUNTING) {
		bf->count_array[h1]++;
        bf->count_array[h2]++;
	} else { 
		// For BLOOM_THREAD_SAFE, we can use atomic operations
        atomic_fetch_or((atomic_uint_fast64_t *)&bf->bit_array_ts[h1/64], 1ULL << (h1 % 64)); 
		atomic_fetch_or((atomic_uint_fast64_t *)&bf->bit_array_ts[h2/64], 1ULL << (h2 % 64)); 
	}

}

/**
 * Set the two Bloom‐filter bits corresponding to the given hash indices.
 *
 * Depending on the filter’s thread‐safety mode, this function either writes
 * directly or uses atomic operations to avoid races when multiple threads
 * insert concurrently.
 *
 * @param type       Which Bloom‐filter implementation to use:
 *                   – BLOOM_CLASSIC      : non‐thread‐safe, direct bit writes
 *                   – BLOOM_THREAD_SAFE  : thread‐safe, atomic bit updates
 * @param bit_array  Pointer to the filter’s bit‐vector (array of 64-bit words).
 *                   Must be large enough to contain bits at positions h1 and h2.
 * @param h1         First bit index (0…filter_size−1) computed by the hash functions.
 * @param h2         Second bit index (0…filter_size−1) computed by the hash functions.
 */
void bloom_add_bit_array(bloom_type_t type, __uint64_t *bit_array, uint32_t h1, uint32_t h2)
{
	if (type == BLOOM_CLASSIC) {
		bit_array[h1 / 64] |= (1ULL << (h1 % 64));
    	bit_array[h2 / 64] |= (1ULL << (h2 % 64));
	}
	else if (type == BLOOM_THREAD_SAFE)
	{
		// For BLOOM_THREAD_SAFE, we can use atomic operations
		atomic_fetch_or((atomic_uint_fast64_t *)&bit_array[h1/64], 1ULL << (h1 % 64)); 
		atomic_fetch_or((atomic_uint_fast64_t *)&bit_array[h2/64], 1ULL << (h2 % 64)); 
	}
}

/**
 * Test whether a key is present in the Bloom filter (and update counts for
 * counting filters).  This routine computes the two hash indices for the
 * key and then:
 *   – For a classic or thread-safe bit filter, checks that both bits are set.
 *   – For a counting filter, verifies both counters are nonzero, then
 *     decrements each counter to “consume” one occurrence.
 *
 * @param bf    Pointer to an initialized bloom_filter_t structure.
 *              - bf->type selects classic, thread-safe, or counting behavior.
 * @param key   Pointer to the byte array (key) whose membership is being tested.
 * @param len   Length of the key in bytes.
 * @return      1 if the key may be in the set (bits/counters both present),
 *              0 if definitely not in the set.
 */
int bloom_check(bloom_filter_t *bf, __uint8_t *key, int len) {
	uint32_t h1, h2;
	bloom_get_indices(key,  len, bf->size, &h1, &h2);

	if (bf->type == BLOOM_CLASSIC) {
	    return (bf->bit_array[h1 / 64] & (1ULL << (h1 % 64))) &&
    	       (bf->bit_array[h2 / 64] & (1ULL << (h2 % 64)));
	} else if(bf->type==BLOOM_THREAD_SAFE) {
		return (bf->bit_array_ts[h1 / 64] & (1ULL << (h1 % 64))) &&
			   (bf->bit_array_ts[h2 / 64] & (1ULL << (h2 % 64)));
	}
	else {
		if (bf->count_array[h1] > 0 && bf->count_array[h2] > 0) {
            bf->count_array[h1]--;
            bf->count_array[h2]--;
            return 1;
        }
        return 0;
    }
}


/**
 * Check if indices exist (computed from a key) in the Bloom filter.
 * For counting filters, decrements the counter on a hit.
 *
 * @param bf Pointer to the Bloom filter.
 * @param h1 first index
 * @param h2 second index 
 * @return 1 if key is possibly in the set, 0 otherwise.
 */
int bloom_check_with_indices(bloom_filter_t *bf, uint32_t h1, uint32_t h2) 
{	
	if (bf->type == BLOOM_CLASSIC) {
		return (bf->bit_array[h1 / 64] & (1ULL << (h1 % 64))) &&
				(bf->bit_array[h2 / 64] & (1ULL << (h2 % 64)));
	} else if(bf->type==BLOOM_THREAD_SAFE) {
		return (bf->bit_array_ts[h1 / 64] & (1ULL << (h1 % 64))) &&
				(bf->bit_array_ts[h2 / 64] & (1ULL << (h2 % 64)));
	}
	else {
		if (bf->count_array[h1] > 0 && bf->count_array[h2] > 0) {
			bf->count_array[h1]--;
			bf->count_array[h2]--;
			return 1;
		}
		return 0;
	}
}

/**
 * Check with precomupted hashes and bit array if a key exists in the Bloom filter.
 *
 * @param bf Pointer to the Bloom filter.
 * @param h1 first index
 * @param h2 second index
*
 * @return 1 if key is possibly in the set, 0 otherwise.
 */
int bloom_check_bit_array(__uint64_t *bit_array, uint32_t h1, uint32_t h2) {
	return (bit_array[h1 / 64] & (1ULL << (h1 % 64))) &&
			(bit_array[h2 / 64] & (1ULL << (h2 % 64)));
}

/**
 * Check with precomupted hashes and bit array if a key exists in a counting Bloom filter.
 * Decrements the counter on a hit.
 *
 * @param bf Pointer to the Bloom filter.
 * @param h1 first index
 * @param h2 second index
 * @return 1 if key is possibly in the set, 0 otherwise.
 */
int bloom_check_count_array(__uint8_t *count_array, uint32_t h1, uint32_t h2) {
	if (count_array[h1] > 0 && count_array[h2] > 0) {
		count_array[h1]--;
		count_array[h2]--;
		return 1;
	}
	return 0;
}

/**
 * Get the value of a specific named xstat (extended statistic) from a DPDK port.
 *
 * @param port_id DPDK port ID.
 * @param name Name of the xstat to retrieve.
 * @return Value of the xstat, or -1 on error.
 */
int
get_port_statistic_by_name(int port_id, const char *name)
{

	struct rte_eth_xstat_name *xstats_names;
	uint64_t *values;
	int len,ret,i;

	// Get number of stats 
	len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
	if (len < 0) {
		DOCA_LOG_ERR("Cannot get xstats count\n");
		return -1;
	}
	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
	if (xstats_names == NULL) {
		 DOCA_LOG_ERR("Cannot allocate memory for xstat names\n");
		 return -1;
   }

   // Retrieve xstats names, passing NULL for IDs to return all statistics 
   ret = rte_eth_xstats_get_names_by_id(port_id, xstats_names, len, NULL);
   if (ret != len) {
		DOCA_LOG_ERR("Cannot get xstat names of Port %d. Recieved only %d out of %d\n",port_id,ret,len);
		return -1;
   }

   values = malloc(sizeof(values) * len);
   if (values == NULL) {
		DOCA_LOG_ERR("Cannot allocate memory for xstats\n");
		return -1;
   }

   // Getting xstats values 
   if (len != rte_eth_xstats_get_by_id(port_id, NULL, values, len)) {
		DOCA_LOG_ERR("Cannot get xstat values\n");
		return -1;
	}

	// Lookup the specific xstats name and return the corresponding integer value
	for (i = 0; i < len; i++) {
	   if (strcmp(xstats_names[i].name, name) == 0) {
			return (int)(values[i]);
	   }
	}
	return -1;
}

/**
 * Print (common) xstat statistics (rx/tx good packets and errors) for a DPDK port.
 *
 * @param port_id DPDK port ID.
 * @param common_only true:  print only common xstats. false: print all xstats. 
 */
void 
get_port_statistics(int port_id, bool common_only)
{
     struct rte_eth_xstat_name *xstats_names;
     uint64_t *values;
     int len,ret,i;
     
	 //Get number of stats 
     len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
     if (len < 0) {
         DOCA_LOG_ERR("Cannot get xstats count\n");
         return;
     }
     xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
     if (xstats_names == NULL) {
          DOCA_LOG_ERR("Cannot allocate memory for xstat names\n");
          return;
    }

    // Retrieve xstats names, passing NULL for IDs to return all statistics 
    ret = rte_eth_xstats_get_names_by_id(port_id, xstats_names, len, NULL);
    if (ret != len) {
         DOCA_LOG_ERR("Cannot get xstat names of Port %d. Recieved only %d out of %d\n",port_id,ret,len);
         return;
    }

    values = malloc(sizeof(values) * len);
    if (values == NULL) {
         DOCA_LOG_ERR("Cannot allocate memory for xstats\n");
         return;;
    }

    // Getting xstats values 
    if (len != rte_eth_xstats_get_by_id(port_id, NULL, values, len)) {
         DOCA_LOG_ERR("Cannot get xstat values\n");
         return;
     }

     // Print rx/tx good packets/errors xstats names and values 
     for (i = 0; i < len; i++) {
		if(!common_only)
		{
			DOCA_LOG_INFO("Port %d, %s: %"PRIu64"", port_id, xstats_names[i].name, values[i]);
			continue;
		}
		if (strcmp(xstats_names[i].name, "rx_good_packets") == 0) {
			DOCA_LOG_INFO("Port %d, rx_good_packets: %"PRIu64"", port_id, values[i]);
			continue;
		}
		if (strcmp(xstats_names[i].name, "tx_good_packets") == 0) {
			DOCA_LOG_INFO("Port %d, tx_good_packets: %"PRIu64"", port_id, values[i]);
			continue;
		}
		if (strcmp(xstats_names[i].name, "rx_errors") == 0) {
			DOCA_LOG_INFO("Port %d, rx_errors: %"PRIu64"", port_id, values[i]);
			continue;
		}
		if (strcmp(xstats_names[i].name, "tx_errors") == 0) {
			DOCA_LOG_INFO("Port %d, tx_errors: %"PRIu64"", port_id, values[i]);
			continue;
		}
	 }     
}

/**
 * Create an egress pipe in the DOCA Flow pipeline.
 *
 * @param port0 DOCA flow port pointer.
 * @param new_pipe Pointer to store the created pipe.
 * @param port_id ID of the port used for forwarding.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t
create_egress_pipe(struct doca_flow_port *port0, struct doca_flow_pipe **new_pipe, int port_id)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[1];
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_pipe_entry *entry;
	struct entries_status *status;
	int num_of_entries = 1;
	doca_error_t result;
	doca_be16_t src_port_53 = rte_cpu_to_be_16(53);


	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
//	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));

	doca_flow_pipe_cfg_create(&pipe_cfg, port0);
	set_flow_pipe_cfg(pipe_cfg, "EGRESS_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	
	actions_arr[0] = &actions;
	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);

	doca_flow_pipe_cfg_set_domain(pipe_cfg,DOCA_FLOW_PIPE_DOMAIN_EGRESS);
	//doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);

	/*result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	*/


	//pipe_cfg.attr.name = "EGRESS_PIPE";
	//pipe_cfg.match = &match;
	//pipe_cfg.actions = actions_arr;
	//pipe_cfg.attr.is_root = true;
	//pipe_cfg.attr.nb_actions = 1;
	//pipe_cfg.port = port0; 
	//pipe_cfg.attr.domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS;

	/* 5 tuple match */
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.src_ip = 0xffffffff;
	match.outer.ip4.dst_ip = 0xffffffff;
	match.outer.tcp.l4_port.src_port = 0xffff;
	match.outer.tcp.l4_port.dst_port = 0xffff;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id;

	actions.outer.udp.l4_port.src_port = src_port_53;
	actions.action_idx = 0;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, new_pipe);
	if (result != DOCA_SUCCESS) {
		free(status);
		return -1;
	}

	result = doca_flow_pipe_add_entry(0, *new_pipe, &match, &actions, NULL, &fwd, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(status);
		return -1;
	}

	result = doca_flow_entries_process(port0, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		return -1;
	}
	if (status->nb_processed != num_of_entries || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, num_of_entries);
		return -1;
	}
	return DOCA_SUCCESS;
}

/**
 * Create a DOCA Flow pipe that send all DNS packets with RSS to the respective ARM core. This is the 
 * last pipeline in the ingress domain.  
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param nb_queues Number of queues to use for RSS.
 * @param direction Whether the pipe is for OUTGOING_REQUESTS or INCOMING_RESPONSES.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t 
create_react_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe, 	int nb_queues, enum burst_direction direction)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	doca_error_t result;
	struct entries_status *status;
	uint16_t *rss_queues;
	struct doca_flow_pipe_entry *entry;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	//memset(&pipe_cfg, 0, sizeof(pipe_cfg));


	doca_flow_pipe_cfg_create(&pipe_cfg, port);
//	set_flow_pipe_cfg(pipe_cfg, "EGRESS_PIPE", DOCA_FLOW_PIPE_BASIC, true);
		
	rss_queues = (__uint16_t *)malloc(sizeof(__uint16_t)*nb_queues);

	if(direction==OUTGOING_REQUESTS)
	{
		set_flow_pipe_cfg(pipe_cfg, "react_PIPE_REQUESTS", DOCA_FLOW_PIPE_BASIC, false);
	}
	if(direction==INCOMING_RESPONSES)
	{
		set_flow_pipe_cfg(pipe_cfg, "react_PIPE_RESPONSES", DOCA_FLOW_PIPE_BASIC, false);
	}
	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	actions_arr[0] = &actions;
	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	
	//pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	//pipe_cfg.port = port;
	//if(direction==OUTGOING_REQUESTS)
	//{
	fwd_miss.type = DOCA_FLOW_FWD_DROP;
	//}
	//else if (direction==INCOMING_RESPONSES)
	//{
	//	fwd_miss.type = DOCA_FLOW_FWD_PORT;
	//	fwd_miss.port_id = 1-direction;
	//	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	//	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	//	match.outer.udp.l4_port.src_port = 53; // for DNS 
	//}	

	for(int i=0;i<nb_queues;i++)
	{ 
		// Core i listen to queue i-i, so queues starts with 0 (and core with 1 and core 0 is the main mgmt core)
		rss_queues[i] = i; 		
	}
	fwd.type = DOCA_FLOW_FWD_RSS;

	fwd.rss_type=DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;    
	fwd.rss.nr_queues = nb_queues;
	fwd.rss.queues_array = rss_queues;
	fwd.rss.outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
//	fwd.num_of_queues = ;
		
	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		free(rss_queues);
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));
	
	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, &fwd, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(rss_queues);
		free(status);
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(rss_queues);
		free(status);
		return result;
	}
	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(rss_queues);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * Add DOCA Flow hash pipe for distribution according to random value.
 *
 * @port [in]: port of the pipe
 * @nb_flows [in]: number of entries for this pipe.
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
create_spraying_pipe(struct doca_flow_port *port,  struct doca_flow_pipe **pipe, int nb_queues)
{
	struct doca_flow_match match_mask;
	struct doca_flow_fwd fwd;
	uint16_t rss_queues = 0;
	uint16_t rss_queues_array[nb_queues];

	struct doca_flow_pipe_cfg *pipe_cfg;
	doca_error_t result;
	struct entries_status *status;

	enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;
	struct doca_flow_pipe_entry *entry;
	uint16_t queue;
	uint16_t i;


	memset(&match_mask, 0, sizeof(match_mask));

	memset(&fwd, 0, sizeof(fwd));
	//memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	/* The distribution is determined by number of entries, we can use full mask */
	match_mask.parser_meta.random = UINT16_MAX;

	uint32_t next_power_of_two = 1U << (32 - __builtin_clz( (uint32_t)nb_queues - 1));

	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	set_flow_pipe_cfg(pipe_cfg, "SPARYING_PIPE", DOCA_FLOW_PIPE_HASH, false);
	doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, next_power_of_two);	
	
	//pipe_cfg.attr.name = "SPARYING_PIPE";
	//pipe_cfg.attr.type = DOCA_FLOW_PIPE_HASH;
	//pipe_cfg.attr.is_root = true;
	//pipe_cfg.attr.nb_flows = next_power_of_two;
	//pipe_cfg.match_mask = &match_mask;
	doca_flow_pipe_cfg_set_match(pipe_cfg, NULL, &match_mask);

	//pipe_cfg.port = port;

	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss.nr_queues = UINT32_MAX;
	fwd.rss.queues_array = &rss_queues;
	//fwd.rss.rss_queues = &rss_queues;
	//fwd.rss.num_of_queues = ;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create spraying pipe:  %s", doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));

	memset(&fwd, 0, sizeof(fwd));

	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss.nr_queues = 1;
	fwd.rss.queues_array = &queue;
	
//	fwd.rss_queues = &queue;
//	fwd.num_of_queues = 1;

	for (i = 0; i < nb_queues; i++) {
		queue = i;

		if (i == nb_queues - 1)
			flags = DOCA_FLOW_NO_WAIT;

		result = doca_flow_pipe_hash_add_entry(0, *pipe, i, NULL, NULL, &fwd, flags, status, &entry);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add hash pipe entry %u: %s", i, doca_error_get_descr(result));
			return result;
		}
	}

	fwd.rss.nr_queues = nb_queues;
	fwd.rss.queues_array = rss_queues_array;
	
	//fwd.rss_queues = rss_queues_array;
	//fwd.num_of_queues = nb_queues;
	for(i=0; i<nb_queues; i++)
	{
		rss_queues_array[i] = i;
	}

	for (i = nb_queues; i < next_power_of_two; i++) {

		if (i == next_power_of_two - 1)
			flags = DOCA_FLOW_NO_WAIT;

		result = doca_flow_pipe_hash_add_entry(0, *pipe, i, NULL, NULL, &fwd, flags, status, &entry);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add hash pipe entry %u: %s", i, doca_error_get_descr(result));
			return result;
		}
	}


	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, next_power_of_two);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	if (status->nb_processed != nb_queues || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}

	return DOCA_SUCCESS;
}



/**
 *
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param next_pipe Next pipe for forwarding.
 * @param direction 0 for copy to meta, 1 for copy from meta.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t create_hash_to_meta(struct doca_flow_port *port, 
	struct doca_flow_pipe **pipe, 
	struct doca_flow_pipe *next_pipe,
    int direction)  // 0 to meta, 1 from meta; 
{ 
	struct doca_flow_match match;
	struct doca_flow_match match_mask;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_arr[1];
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_action_descs descs;
	struct doca_flow_action_descs *descs_arr[1];
	struct doca_flow_action_desc desc_array[NB_ACTION_DESC] = {0};
	doca_error_t result;
	struct entries_status *status;
	struct doca_flow_pipe_entry *entry;
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;
;

	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));

	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	//memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	memset(&descs, 0, sizeof(descs));

	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	
	match_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_mask.outer.ip4.dst_ip = 0xffffffff;
	match_mask.outer.ip4.src_ip = 0xffffffff;
	match_mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match_mask.outer.udp.l4_port.dst_port = 0xffff;
	match_mask.outer.udp.l4_port.src_port = 0xffff;
	
	
	set_flow_pipe_cfg(pipe_cfg, "COPY_HASH_KEY", DOCA_FLOW_PIPE_HASH, false);
	doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);	
	
	//pipe_cfg.attr.name = "SPARYING_PIPE";
	//pipe_cfg.attr.type = DOCA_FLOW_PIPE_HASH;
	//pipe_cfg.attr.is_root = true;
	//pipe_cfg.attr.nb_flows = next_power_of_two;
	//pipe_cfg.match_mask = &match_mask;
	
	
	doca_flow_pipe_cfg_set_match(pipe_cfg, NULL, &match_mask);

	
	actions_arr[0] = &actions;
	//pipe_cfg.actions = actions_arr;
	//actions.meta.pkt_meta = htobe32(10);;
	//actions.action_idx = 0;

	//doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

//	pipe_cfg.attr.name = "COPY_TO_META_PIPE";
//	pipe_cfg.match = &match;
	descs_arr[0] = &descs;
	descs.nb_action_desc = 1;
	descs.desc_array = desc_array;
	//pipe_cfg.action_descs = descs_arr;
	
	//pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	

	desc_array[0].type = DOCA_FLOW_ACTION_COPY;
//	desc_array[0].field_op.src.field_string = "outer.ipv4.src_ip";
	desc_array[0].field_op.src.field_string = "parser_meta.hash.result";
	desc_array[0].field_op.src.bit_offset = 0;
	desc_array[0].field_op.dst.field_string = "meta.data";
	desc_array[0].field_op.dst.bit_offset = 0; // META_U16_BIT_OFFSET(0);
	desc_array[0].field_op.width = 32;

	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, descs_arr, 1);

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));
	result = doca_flow_pipe_hash_add_entry(0, *pipe, 0, NULL, NULL, &fwd, flags, status, &entry);	
//	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, &fwd, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to Pipe: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}

	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;}


/**
 * Create a DOCA Flow pipe to copy 4-tuple fields to/from meta-data using COPY actions.
 *
 * Meta-data will be have 96 bits storing src_ip, dst_ip, src_port, dst_port, copied from 
 * the packet if direction is 0. When direction is 1, src_ip (dst_ip), src_port (dst_port) will be copied to 
 * the header fields of dst_ip (src_ip), dst_port (src_port), thus swapping the "direction" of
 * the packet.   
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param next_pipe Next pipe for forwarding.
 * @param direction 0 for copy to meta, 1 for copy from meta.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t create_copy_to_meta_pipe(struct doca_flow_port *port, 
	struct doca_flow_pipe **pipe, 
	struct doca_flow_pipe *next_pipe,
    int direction)  // 0 to meta, 1 from meta; 
{ 
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_action_descs descs;
	struct doca_flow_action_descs *descs_arr[NB_ACTIONS_ARR];
	struct doca_flow_action_desc desc_array[NB_ACTION_DESC] = {0};
	doca_error_t result;
	struct entries_status *status;
	struct doca_flow_pipe_entry *entry;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	//memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	memset(&descs, 0, sizeof(descs));

	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if(direction == 0) 
	{
		set_flow_pipe_cfg(pipe_cfg, "COPY_TO_META_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	}
	else
	{
		set_flow_pipe_cfg(pipe_cfg, "COPY_FROM_META_PIPE", DOCA_FLOW_PIPE_BASIC, false);

	}

	actions_arr[0] = &actions;
	//pipe_cfg.actions = actions_arr;


	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

//	pipe_cfg.attr.name = "COPY_TO_META_PIPE";
//	pipe_cfg.match = &match;
	descs_arr[0] = &descs;
	descs.nb_action_desc = NB_ACTION_DESC;
	descs.desc_array = desc_array;
	//pipe_cfg.action_descs = descs_arr;
	
	//pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	
	if (direction == 0)  { 
		desc_array[0].type = DOCA_FLOW_ACTION_COPY;
		desc_array[0].field_op.src.field_string = "outer.ipv4.src_ip";
		desc_array[0].field_op.src.bit_offset = 0;
		desc_array[0].field_op.dst.field_string = "meta.data";
		desc_array[0].field_op.dst.bit_offset = META_U32_BIT_OFFSET(0);
		desc_array[0].field_op.width = 32;

		desc_array[1].type = DOCA_FLOW_ACTION_COPY;
		desc_array[1].field_op.src.field_string = "outer.ipv4.dst_ip";
		desc_array[1].field_op.src.bit_offset = 0;
		desc_array[1].field_op.dst.field_string = "meta.data";
		desc_array[1].field_op.dst.bit_offset = META_U32_BIT_OFFSET(1);
		desc_array[1].field_op.width = 32;

		desc_array[2].type = DOCA_FLOW_ACTION_COPY;
		desc_array[2].field_op.src.field_string = "outer.udp.src_port";
		desc_array[2].field_op.src.bit_offset = 0;
		desc_array[2].field_op.dst.field_string = "meta.data";
		desc_array[2].field_op.dst.bit_offset = META_U32_BIT_OFFSET(2);
		desc_array[2].field_op.width = 16;

		desc_array[3].type = DOCA_FLOW_ACTION_COPY;
		desc_array[3].field_op.src.field_string = "outer.udp.dst_port";
		desc_array[3].field_op.src.bit_offset = 0;
		desc_array[3].field_op.dst.field_string = "meta.data";
		desc_array[3].field_op.dst.bit_offset = META_U32_BIT_OFFSET(3);
		desc_array[3].field_op.width = 16;
	}
	else
	{
		desc_array[0].type = DOCA_FLOW_ACTION_COPY;
		desc_array[0].field_op.dst.field_string = "outer.ipv4.src_ip";
		desc_array[0].field_op.dst.bit_offset = 0;
		desc_array[0].field_op.src.field_string = "meta.data";
		desc_array[0].field_op.src.bit_offset = META_U32_BIT_OFFSET(1);
		desc_array[0].field_op.width = 32;

		desc_array[1].type = DOCA_FLOW_ACTION_COPY;
		desc_array[1].field_op.dst.field_string = "outer.ipv4.dst_ip";
		desc_array[1].field_op.dst.bit_offset = 0;
		desc_array[1].field_op.src.field_string = "meta.data";
		desc_array[1].field_op.src.bit_offset = META_U32_BIT_OFFSET(0);
		desc_array[1].field_op.width = 32;

		desc_array[2].type = DOCA_FLOW_ACTION_COPY;
		desc_array[2].field_op.dst.field_string = "outer.udp.src_port";
		desc_array[2].field_op.dst.bit_offset = 0;
		desc_array[2].field_op.src.field_string = "meta.data";
		desc_array[2].field_op.src.bit_offset = META_U32_BIT_OFFSET(3);
		desc_array[2].field_op.width = 16;

		desc_array[3].type = DOCA_FLOW_ACTION_COPY;
		desc_array[3].field_op.dst.field_string = "outer.udp.dst_port";
		desc_array[3].field_op.dst.bit_offset = 0;
		desc_array[3].field_op.src.field_string = "meta.data";
		desc_array[3].field_op.src.bit_offset = META_U32_BIT_OFFSET(2);
		desc_array[3].field_op.width = 16;
	}

	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, descs_arr, NB_ACTIONS_ARR);

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));

	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, &fwd, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;}

/**
 * 
 * 
 */
void getBFStatus(bloom_filter_t **bf_array, char *status_str)
{	
	for(int i=0;i<256;i++)
	{
		(status_str)[i] = '\0'; // clear the string
	}
	size_t len = strlen(status_str);  // current end of the string
	for (int i = 0; i < 3; i++) {
		if (bf_array[i] == NULL) {
			len+=snprintf(status_str+len, 256-len, "%s", "NULL; ");
			continue;
		}
		else{
			len+=snprintf(status_str+len, 256-len, "(%d) %p: %p; ", bf_array[i]->type, bf_array[i], bf_array[i]->bit_array_ts);	
		}
	}
}

/**
 * Create a DOCA Flow pipe that sends all packets to the opposite port (wire)
 *
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param direction INCOMING_REQUESTS or OUTGOING_RE
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t create_to_port_pipe(struct doca_flow_port *port, 
	struct doca_flow_pipe **pipe,
	int direction)   
{ 
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_cfg *pipe_cfg;
	doca_error_t result;
	struct entries_status *status;
	struct doca_flow_pipe_entry *entry;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
//	memset(&fwd_miss, 0, sizeof(fwd_miss));
	//memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	//memset(&descs, 0, sizeof(descs));

	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	set_flow_pipe_cfg(pipe_cfg, "TO_PORT_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	
	actions_arr[0] = &actions;
	
	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

//	pipe_cfg.attr.name = "COPY_TO_META_PIPE";
//	pipe_cfg.match = &match;
	//descs_arr[0] = &descs;
	//descs.nb_action_desc = NB_ACTION_DESC;
	//descs.desc_array = desc_array;
	//pipe_cfg.action_descs = descs_arr;
	
	//pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	
	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = 1-direction;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));
//	match.outer.udp.l4_port.src_port = rte_cpu_to_be_16(53);

	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, NULL, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;
}

/**
 * Create a root pipe for responses: packets that are DNS should be processed, packets that are not are sent to the to-port pipe.
 *
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param next_pipe Next pipe for forwarding.
 * @param direction 0 for copy to meta, 1 for copy from meta.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t create_first_pipe_responses(struct doca_flow_port *port, 
	struct doca_flow_pipe **pipe, 
	struct doca_flow_pipe *next_pipe,
	struct doca_flow_pipe *to_port_pipe,
	int direction)  // 0 to meta, 1 from meta; 
{ 
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	doca_error_t result;
	struct entries_status *status;
	struct doca_flow_pipe_entry *entry;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	set_flow_pipe_cfg(pipe_cfg, "FIRST_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	
	actions_arr[0] = &actions;
	
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.src_port = UINT16_MAX; 

	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	
	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = to_port_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));
	memset(&match, 0, sizeof(match));
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.src_port = RTE_BE16(53);

	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, NULL, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;
}

/**
 * Create a root pipe for requests: packets that are DNS should be processed and mirrored to the to-port pipe, 
 * packets that are not are sent to the to-port pipe.
 *
 * 
 * @param port DOCA flow port pointer.
 * @param pipe Pointer to the created pipe.
 * @param next_pipe Next pipe for forwarding.
 * @param direction 0 for copy to meta, 1 for copy from meta.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t create_first_pipe_requests(struct doca_flow_port *port, 
	struct doca_flow_pipe **pipe, 
	struct doca_flow_pipe *next_pipe,
	struct doca_flow_pipe *to_port_pipe,
	int mirror_id,
	int direction)  // 0 to meta, 1 from meta; 
{ 
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_monitor monitor;
	doca_error_t result;
	struct entries_status *status;
	struct doca_flow_pipe_entry *entry;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	memset(&monitor, 0, sizeof(monitor));

	monitor.shared_mirror_id = mirror_id;
	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;


	doca_flow_pipe_cfg_create(&pipe_cfg, port);
	set_flow_pipe_cfg(pipe_cfg, "FIRST_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	
	actions_arr[0] = &actions;
	
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.dst_port = UINT16_MAX; 

	doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	
	doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);

	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		return result;
	}

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = to_port_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe for direction %d: %s", direction, doca_error_get_descr(result));
		return result;
	}

	status = (struct entries_status *)calloc(1, sizeof(struct entries_status));
	memset(&match, 0, sizeof(match));
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.dst_port = RTE_BE16(53);
	memset(&monitor, 0, sizeof(monitor));

	/* set shared mirror ID */
	monitor.shared_mirror_id = mirror_id;

	result = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, &monitor, NULL, 0, status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Pipe: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS)
	{
		DOCA_LOG_ERR("Failed to Process entries: %s", doca_error_get_descr(result));
		free(status);
		return result;
	}
	if (status->nb_processed != 1 || status->failure)
	{
		DOCA_LOG_ERR("Some entries failed (%d processed out of %d)", status->nb_processed, 1);
		free(status);
		return result;
	}
	return DOCA_SUCCESS;
}

/**
 * Main REACT packet processing function that sets up all DOCA Flow pipes, runs DPDK workers,
 * and runs the main ARM core controller, responsible of bloom filters swapping and graceful 
 * terminiation.
 *
 * @param dpdk_queues Number of DPDK queues to allocate.
 * @param app_cfg Application-level configuration.
 * @return DOCA_SUCCESS on success or error code on failure.
 */
doca_error_t
flow_react(int dpdk_queues, struct react_config app_cfg)
{
	const int nb_ports = 2;
	struct flow_resources resource = {0};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};

	//	struct doca_flow_resources resource = {0};
	//uint32_t nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MAX] = {0};
	struct doca_flow_port *ports[nb_ports];
	struct doca_dev *dev_arr[nb_ports];
	/* Pipe numbers:
	0 - RSS pipe for responses (either w/affinity or random/spraying)
	1 - RSS pipe for requests
	2 - Copy from Meta pipe (for header field swapping)
	3 - Copy to Meta pipe (for header field swapping)
	4 - Root pipe for requests (including mirror)
	5 - Root pipe for responses (send 53 to 0, send rest to 7)
	6 - Pipe for traffic to be TX to port 0. 
	7 - Pipe for non-DNS traffic to be TX to port 1. 
	8 - Pipe to copy hash result to meta-data, responses
	9 - Pipe to copy hash result to meta-data, resquests
	*/
	struct doca_flow_pipe *pipe[10]; // four pipes for port 0
	struct doca_flow_pipe *egress_pipe; // egress pipe for port 1	 
	bloom_filter_t **bf_array;
	int *phase_array;
	int *nb_requests_array; // not used; talying not done to boost performance
	int *nb_responses_dropped_array; // not used; talying not done to boost performance
	int *nb_responses_fwd_array; // not usedd; talying not done to boost performance
	bool *within_burst_array;
	uint32_t actions_mem_size[nb_ports];
	struct doca_flow_mirror_target target = {0};
	struct doca_flow_shared_resource_cfg cfg = {0};
	struct doca_flow_resource_mirror_cfg mirror_cfg = {0};
	uint32_t mirror_id = 1;

	nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MIRROR] = 4;
	resource.nr_counters = 4;

	
	doca_error_t result;
	int lcore;
    worker_params params[nb_ports*app_cfg.nb_cores+1];

	result = init_doca_flow(dpdk_queues, "vnf,hws", &resource, nr_shared_resources);	
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return -1;
	}

	memset(dev_arr, 0, sizeof(struct doca_dev *) * nb_ports);
	ARRAY_INIT(actions_mem_size, ACTIONS_MEM_SIZE(dpdk_queues, MAX_ENTRIES_REACT));
	result = init_doca_flow_ports(nb_ports, ports, true, dev_arr,actions_mem_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
		doca_flow_destroy();
		return result;
	}

	result = create_to_port_pipe(ports[1], &pipe[6], OUTGOING_REQUESTS);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	mirror_cfg.nr_targets = 1;
	target.fwd.type = DOCA_FLOW_FWD_PIPE;
	target.fwd.next_pipe = pipe[6];
	mirror_cfg.target = &target;
	cfg.mirror_cfg = mirror_cfg;

	result = doca_flow_shared_resource_set_cfg(DOCA_FLOW_SHARED_RESOURCE_MIRROR, mirror_id, &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to cfg shared mirror");
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}


	/* bind shared mirror to port */
	result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_MIRROR, &mirror_id, 1, ports[OUTGOING_REQUESTS]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind shared mirror to port");
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	if(app_cfg.bloom_type == BLOOM_CLASSIC || app_cfg.bloom_type == BLOOM_COUNTING)
	{
		result = create_react_pipe(ports[0], &pipe[0], app_cfg.nb_cores, INCOMING_RESPONSES);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}
	}
	else { // THREAD-SAFE, spraying INCOMING RESPONSES to all cores
		result = create_spraying_pipe(ports[0], &pipe[0], app_cfg.nb_cores);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}
	}

	result = create_hash_to_meta(ports[0], &pipe[8], pipe[0], INCOMING_RESPONSES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_to_port_pipe(ports[0], &pipe[7], INCOMING_RESPONSES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_first_pipe_responses(ports[0], &pipe[5], pipe[8], pipe[7], INCOMING_RESPONSES); // filtered, not mirrored.
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_react_pipe(ports[1], &pipe[1], app_cfg.nb_cores, OUTGOING_REQUESTS);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_hash_to_meta(ports[1], &pipe[9], pipe[1], OUTGOING_REQUESTS);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	
	result = create_copy_to_meta_pipe(ports[1], &pipe[2], pipe[9], 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = create_copy_to_meta_pipe(ports[1], &pipe[3], pipe[2], 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_first_pipe_requests(ports[1], &pipe[4], pipe[3], pipe[6], 1, OUTGOING_REQUESTS); // filtered, mirrored.
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
		

	// setting port 1 (egress):
	//egress pipe traffic only on port 1. 
	result = create_egress_pipe(ports[1], &egress_pipe,  1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	// ASAP configuration completed, turning to run dpdk apps on the ARM cores
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	
	if(app_cfg.bloom_type == BLOOM_CLASSIC) // classic and thread-safe bloom filters
	{
		bf_array = (bloom_filter_t **) malloc(sizeof(bloom_filter_t *)*app_cfg.nb_cores*3);
	}
	else if(app_cfg.bloom_type == BLOOM_THREAD_SAFE) { // thread-safe bloom filters
		bf_array = (bloom_filter_t **) malloc(sizeof(bloom_filter_t *)*3);

	} else {  // counting
 		bf_array = (bloom_filter_t **) malloc(sizeof(bloom_filter_t *)*app_cfg.nb_cores);
	}

	phase_array = (int *) calloc(app_cfg.nb_cores+1, sizeof(int));
	nb_requests_array = (int *) calloc(app_cfg.nb_cores+1, sizeof(int));
	nb_responses_fwd_array = (int *) calloc(app_cfg.nb_cores+1, sizeof(int));
	nb_responses_dropped_array = (int *) calloc(app_cfg.nb_cores+1, sizeof(int));
	within_burst_array = (bool *) calloc(app_cfg.nb_cores+1, sizeof(bool));
	

	DOCA_LOG_INFO("Main lcore is %u, number of ports is %d, number of DPDK queues is %d, number of working cores %d", rte_lcore_id(), nb_ports, dpdk_queues, app_cfg.nb_cores);
	if(app_cfg.bloom_type==BLOOM_CLASSIC)
	{
		DOCA_LOG_INFO("Using classic Bloom Filters. Total size: %lu bits, swap interval: %d seconds, timeout: %d seconds", app_cfg.bloom_size, app_cfg.bloom_swap_interval, app_cfg.timeout);
	}
	else if(app_cfg.bloom_type==BLOOM_COUNTING) {
		DOCA_LOG_INFO("Using counting Bloom Filters. Total size: %lu bits, timeout: %d seconds", app_cfg.bloom_size, app_cfg.timeout);
	}
	else if(app_cfg.bloom_type==BLOOM_THREAD_SAFE) {
		DOCA_LOG_INFO("Using Thread-Safe Bloom Filters. Total size: %lu bits, swap interval: %d seconds, timeout: %d seconds", app_cfg.bloom_size, app_cfg.bloom_swap_interval, app_cfg.timeout);
	}

	for (lcore=1; lcore < app_cfg.nb_cores+1; lcore++) {
		if(app_cfg.bloom_type == BLOOM_CLASSIC) 
		{
			bf_array[3*(lcore-1)]=bloom_init(app_cfg.bloom_size/(app_cfg.nb_cores*2), app_cfg.bloom_type, app_cfg.optimized_bloom);
			bf_array[3*(lcore-1)+2]=bloom_init(app_cfg.bloom_size/(app_cfg.nb_cores*2), app_cfg.bloom_type, app_cfg.optimized_bloom);
			bf_array[3*(lcore-1)+1]=NULL;
			params[lcore].bfs = &bf_array[3*(lcore-1)];
		}
		else if (app_cfg.bloom_type == BLOOM_THREAD_SAFE)
		{
			if(lcore==1)
			{
				bf_array[0]=bloom_init(app_cfg.bloom_size/2, app_cfg.bloom_type, app_cfg.optimized_bloom);
				bf_array[2]=bloom_init(app_cfg.bloom_size/2, app_cfg.bloom_type, app_cfg.optimized_bloom);
				bf_array[1]=NULL;
			}
			params[lcore].bfs = &bf_array[0];		
		}
		else
		{ // Only one bloom filter per core for counting bloom filters
			bf_array[lcore-1]=bloom_init(app_cfg.bloom_size/(app_cfg.nb_cores), app_cfg.bloom_type, app_cfg.optimized_bloom);
			params[lcore].bfs = &bf_array[lcore-1];
		}
        params[lcore].queue_index = lcore-1;
		params[lcore].phase = &phase_array[lcore];
		params[lcore].nb_requests = &nb_requests_array[lcore];
		params[lcore].nb_responses_fwd = &nb_responses_fwd_array[lcore];
		params[lcore].nb_responses_dropped = &nb_responses_dropped_array[lcore];
		params[lcore].within_burst = &within_burst_array[lcore];
		params[lcore].optimized_bloom = app_cfg.optimized_bloom;
		
		rte_eal_remote_launch(&process_packets, &params[lcore], lcore);
		
    }
	
	bool first_time = true; 
	int time = 0, global_time = 0;
    while(!global_force_quit)
	{
		time = (time + 1)%app_cfg.bloom_swap_interval;

		if(app_cfg.timeout>0)
		{
			global_time++;	
			if(global_time==app_cfg.timeout) {
				global_force_quit = true;
				break;
			}
		}
		if(time==0 && app_cfg.bloom_type != BLOOM_COUNTING) // swap bloom filters every bloom_swap_interval seconds 
		{ // Counting bloom filters are not swapped
			bloom_filter_t *tmp;
			for (lcore=1; lcore < app_cfg.nb_cores+1; lcore++) {
				/*
				Swapping bloom filters on each core.
				Just before swapping, the current phase is phase_array[lcore]
				BF A @ phase-1 should be deleted
				BF B @ phase+1 should be allocated
				BF C @ phase remains unchanged
				Phase preceeds to phase+1
				So now adds are to B, and checks are on B and C. 
				*/
				if(first_time)
				{	
					if(lcore==app_cfg.nb_cores)
						first_time = false;
					continue; // no swap on first time (for all cores)
				}
				if(app_cfg.bloom_type == BLOOM_CLASSIC) 		
				{
					tmp = bf_array[3*(lcore-1)+(2+phase_array[lcore])%3]; // BF A @ phase-1
					bf_array[3*(lcore-1)+(phase_array[lcore]+1)%3]=bloom_init(app_cfg.bloom_size/(app_cfg.nb_cores*2), app_cfg.bloom_type, app_cfg.optimized_bloom); //BF B @ phase+1
				}
				if(app_cfg.bloom_type == BLOOM_THREAD_SAFE && lcore==1)  
				{
					tmp = bf_array[(phase_array[lcore]+2)%3]; // BF A @ phase-1
					bf_array[(phase_array[lcore]+1)%3] = bloom_init(app_cfg.bloom_size/2, app_cfg.bloom_type, app_cfg.optimized_bloom); // BF B @ phase+1
				}
				
				if(within_burst_array[lcore])
					wait_for_rx_qi_changes(0, lcore-1, 1); 
				
				phase_array[lcore] = (phase_array[lcore]+1)%3;				
				
				if(app_cfg.bloom_type == BLOOM_CLASSIC || app_cfg.bloom_type == BLOOM_THREAD_SAFE) 				
				{ // free old bloom filter(s)
					if(within_burst_array[lcore])
						wait_for_rx_qi_changes(0, lcore-1, 1);
					if(app_cfg.bloom_type == BLOOM_CLASSIC) 
					{
						rte_free(tmp->bit_array); // free BF A @ phase-1 - only inner bit array is freed, not the whole bloom filter
						tmp->bit_array = NULL; // set to NULL to avoid double free
					}
					else if (app_cfg.bloom_type == BLOOM_THREAD_SAFE && lcore==app_cfg.nb_cores) 
					{
						rte_free(tmp->bit_array_ts); // free BF A @ phase-1 - only inner bit array is freed, not the whole bloom filter
						tmp->bit_array_ts = NULL; // set to NULL to avoid double free

					}
					
				}
			}
		}
		sleep(1);
	}
	force_quit = true;
	for (lcore = 1; lcore < app_cfg.nb_cores+1; lcore++)
		    rte_eal_wait_lcore(lcore);
	
	
	for(int i=0;i<app_cfg.nb_cores*3;i++)
	{
		if(i==3 && app_cfg.bloom_type == BLOOM_THREAD_SAFE)
			break;
		if(i==app_cfg.nb_cores && app_cfg.bloom_type == BLOOM_COUNTING)
			break;
		bloom_free(bf_array[i]);
	}
	

	free(bf_array);
	free(phase_array);
	free(nb_requests_array);
	free(nb_responses_dropped_array);
	free(nb_responses_fwd_array);
	free(within_burst_array);

	//DOCA_LOG_INFO("Number of requests: %d", get_port_statistic_by_name(1,"rx_good_packets"));
	//DOCA_LOG_INFO("Total number of rx responses: %d", get_port_statistic_by_name(0,"rx_good_packets"));
	//DOCA_LOG_INFO("Number of filtered tx responses: %d",get_port_statistic_by_name(1,"tx_good_packets"));

	get_port_statistics(0, false);
	get_port_statistics(1, false);

	stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return DOCA_SUCCESS;
}
