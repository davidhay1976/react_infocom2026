#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <signal.h>
#include <ctype.h>


#include <dpdk_utils.h>
#include <rte_ethdev.h>
#include "react.h"

DOCA_LOG_REGISTER(REACT::MAIN);

/**
 * Callback function for setting the time (in second) before the application ends.
 * Default is infinite (until SIGTERM/SIGINT)
 *
 * @param param Pointer to an integer specifying the desired time in second.
 * @param config Pointer to the application's configuration structure.
 * @return DOCA_SUCCESS on success.
 */
 static doca_error_t
 timeout_callback(void *param, void *config)
 {
		 struct react_config *app_config = (struct react_config *) config;
		 app_config->timeout = *(int *) param;
		 DOCA_LOG_DBG("Set # local cores:%d", app_config->timeout);
		 return DOCA_SUCCESS;
 }
 
/**
 * Callback function for setting the number of worker cores.
 *
 * @param param Pointer to an integer specifying the desired number of worker cores.
 * @param config Pointer to the application's configuration structure.
 * @return DOCA_SUCCESS on success.
 */
static doca_error_t
nb_cores_callback(void *param, void *config)
{
        struct react_config *app_config = (struct react_config *) config;
        app_config->nb_cores = *(int *) param;
        DOCA_LOG_DBG("Set # local cores:%d", app_config->nb_cores);
        return DOCA_SUCCESS;
}

/**
 * Callback function for setting Bloom filter size.
 *
 * @param param Pointer to an integer specifying the desired Bloom filter size (in bits).
 * @param config Pointer to the application's configuration structure.
 * @return DOCA_SUCCESS on success.
 */
static doca_error_t
bloom_size_callback(void *param, void *config)
{
        struct react_config *app_config = (struct react_config *) config;
		char *input = (char *) param;
		size_t len = strlen(input);
	    bool ends_with_p2 = len >= 2 && tolower(input[len - 2]) == 'p' && input[len - 1] == '2';
		if(ends_with_p2) {
			app_config->optimized_bloom = true;
			input[len - 2] = '\0'; // Remove the "p2" suffix
		}
		if(strlen(input)>0)
        	app_config->bloom_size = strtoul(input, NULL, 10); 
        DOCA_LOG_DBG("Set Bloom Size:%lu", app_config->bloom_size);
        return DOCA_SUCCESS;
}


/**
 * Callback function for setting reAct's interval length (for the sliding window) 
 *
 * @param param Pointer to an integer value specifying the desired interval length (in seconds).
 * @param config Pointer to the application's configuration structure.
 * @return DOCA_SUCCESS on success.
 */
static doca_error_t
bloom_swap_callback(void *param, void *config)
{
        struct react_config *app_config = (struct react_config *) config;

        app_config->bloom_swap_interval = *(int *) param;
        DOCA_LOG_DBG("Set Bloom Swap Interval:%d", app_config->bloom_swap_interval);
        return DOCA_SUCCESS;
}

/**
 * Callback function for enabling/disabling Counting Bloom filter implementation.
 *
 * @param param Pointer to a boolean value specifying if Counting Bloom filter should be enabled.
 * @param config Pointer to the application's configuration structure.
 * @return DOCA_SUCCESS on success.
 */
static doca_error_t
bloom_type_callback(void *param, void *config)
{
        struct react_config *app_config = (struct react_config *) config;

        int type = *(int *) param;
		if(type==1)
		{
			app_config->bloom_type = BLOOM_COUNTING;
		}
		else if(type==0)
		{
			app_config->bloom_type = BLOOM_CLASSIC;
		}
		else if(type==2)
		{
			app_config->bloom_type = BLOOM_THREAD_SAFE;
		}
		else
		{
			DOCA_LOG_ERR("Invalid bloom type specified, using classic bloom filter");
			app_config->bloom_type = BLOOM_CLASSIC;
		}
        DOCA_LOG_DBG("Set Bloom type:%d", app_config->bloom_type);
        return DOCA_SUCCESS;
}

/**
 * Register ReAct-specific command-line parameters.
 *
 * @return DOCA_SUCCESS on success, or an appropriate doca_error_t on failure.
 */
doca_error_t
register_react_params(void)
{
	doca_error_t result;
	struct doca_argp_param *bloom_type_counting, *bloom_size, *bf_swap_interval, *nb_cores, *timeout;

    // Register Bloom size parameter
	result = doca_argp_param_create(&bloom_size);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
			return result;
	}
	doca_argp_param_set_short_name(bloom_size, "s");
	doca_argp_param_set_long_name(bloom_size, "bloom-size");
	doca_argp_param_set_arguments(bloom_size, "<size>");
	doca_argp_param_set_description(bloom_size, "Set total bloom filter size in bits");
	doca_argp_param_set_callback(bloom_size, bloom_size_callback);
	doca_argp_param_set_type(bloom_size, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(bloom_size);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
			return result;
	}

	// Register Bloom size parameter
	result = doca_argp_param_create(&bf_swap_interval);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
			return result;
	}
	doca_argp_param_set_short_name(bf_swap_interval, "i");
	doca_argp_param_set_long_name(bf_swap_interval, "bloom-swap");
	doca_argp_param_set_arguments(bf_swap_interval, "<length>");
	doca_argp_param_set_description(bf_swap_interval, "Set the length of the bloom filter swap interval in seconds");
	doca_argp_param_set_callback(bf_swap_interval, bloom_swap_callback);
	doca_argp_param_set_type(bf_swap_interval, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(bf_swap_interval);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
			return result;
	}

	// Register Bloom type parameter
	result = doca_argp_param_create(&bloom_type_counting);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
			return result;
	}
	doca_argp_param_set_short_name(bloom_type_counting, "t");
	doca_argp_param_set_long_name(bloom_type_counting, "bloom-type");
	doca_argp_param_set_arguments(bloom_type_counting, "<type>");
	doca_argp_param_set_description(bloom_type_counting, "1 for counting bloom filter, 0 for classic bloom filter, 2 for thread-safe classic bloom filter");
	doca_argp_param_set_callback(bloom_type_counting, bloom_type_callback);
	doca_argp_param_set_type(bloom_type_counting, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(bloom_type_counting);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
			return result;
	} 

	// Register Bloom size parameter
	result = doca_argp_param_create(&nb_cores);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
			return result;
	}
	// Register number of worker cores
    doca_argp_param_set_short_name(nb_cores, "c");
	doca_argp_param_set_long_name(nb_cores, "worker-cores");
	doca_argp_param_set_arguments(nb_cores, "<number>");
	doca_argp_param_set_description(nb_cores, "The number of workers cores");
	doca_argp_param_set_callback(nb_cores, nb_cores_callback);
	doca_argp_param_set_type(nb_cores, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nb_cores);
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
			return result;
	} 


	 // Register timeout parameter
	 result = doca_argp_param_create(&timeout);
	 if (result != DOCA_SUCCESS) {
			 DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
			 return result;
	 }
	 doca_argp_param_set_short_name(timeout, "o");
	 doca_argp_param_set_long_name(timeout, "timeout");
	 doca_argp_param_set_arguments(timeout, "<length>");
	 doca_argp_param_set_description(timeout, "Set the timeout for the application in seconds");
	 doca_argp_param_set_callback(timeout, timeout_callback);
	 doca_argp_param_set_type(timeout, DOCA_ARGP_TYPE_INT);
	 result = doca_argp_register_param(timeout);
	 if (result != DOCA_SUCCESS) {
			 DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
			 return result;
	 }
	return DOCA_SUCCESS;

}

/**
 * Main entry point: registers and launches the ReAct application.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return 0 on success, -1 on failure.
 */
int
main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_hairpin_q = 1,
		.port_config.enable_mbuf_metadata = 1,
		.reserve_main_thread = true
	};
	struct react_config app_cfg = {
		.dpdk_cfg = &dpdk_config,
		.bloom_size = 229376, // 16Kb on 14 cores
		.bloom_swap_interval = 6,
		.bloom_type = BLOOM_CLASSIC,
		.nb_cores = 14,
		.timeout = 0 // never stop
	};


    // Register standard logger backend
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

    // Register SDK logger backend for errors and warnings
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting the sample");

	// Initialize argument parser
	result = doca_argp_init("doca_flow_react", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}

	// Register ReAct parameters
	result = register_react_params();
	if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to register application params: %s", doca_error_get_descr(result));
			doca_argp_destroy();
			goto sample_exit;
	}

	// Attach DPDK init callback to argument parser
	doca_argp_set_dpdk_program(dpdk_init);

	// Parse command-line arguments
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

    // Initialize queues and ports based on DPDK config
	result =dpdk_queues_and_ports_init (&dpdk_config);
	DOCA_LOG_INFO("number of queues after init: %d", dpdk_config.port_config.nb_queues);
	DOCA_LOG_INFO("number of hairpin queues aftere init: %d", dpdk_config.port_config.nb_hairpin_q);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		goto dpdk_cleanup;
	}

    // Enable promiscuous mode on port 1
	rte_eth_promiscuous_enable(1);
	
    // Run the ReAct flow processing logic, with the intended number of queues, and not the number created (which is equal to the number of lcores)
	result = flow_react(dpdk_config.port_config.nb_queues,  app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("flow_react() encountered an error: %s", doca_error_get_descr(result));
		goto dpdk_ports_queues_cleanup;
	}

	exit_status = EXIT_SUCCESS;

// Cleanup routines
dpdk_ports_queues_cleanup:
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
	dpdk_fini();
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("ReAct finished successfully");
	else
		DOCA_LOG_INFO("ReAct finished with errors");
	return exit_status;
}
