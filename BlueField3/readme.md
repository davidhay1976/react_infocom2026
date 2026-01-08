## Description 

We have implemented ReAct on the NVIDIA BlueField-3), a high-performance SmartNIC that integrates both programmable hardware and software processing capabilities. Our deployment assumes a symmetric model in which all DNS requests originate from the client and all responses return to the SmartNIC. This assumption eliminates the need to handle asymmetry, and allows us to compare against existing approaches that only handle symmetric traffic.
We assume a symmetric model because SmartNICs are typically placed near the client; thus they would see both the request and response. 

## Run time parameters

The script <code>react.sh</code> compiles the code (using <code>meson.build</code>) and run the DOCA application. The parameters are as follows

-   <code>--bloom-size</code> or <code>-s</code>: The size ofthe bloom filter is bits. Add a suffix "p2" to indicate that the Bloom Filter size is a power of two, for further optimizations.
-   <code>--bloom-swap</code> or <code>-i</code>: The time interval between bloom filter swaps (in seconds)
-   <code>--bloom-type-counting</code> or <code>-t</code>: The type of the bloom filter. 0 for regular bloom filters, 1 for counting bloom filter (for comparison only), and 2 for a centralized implementation (this version is not described in the infocom paper). 
- <code>--worker-cores</code> or <code>-c</code>: The number of ARM cores dedicated to the application (maximum number of ARM cores is 15, as one core is used as the main core).
- <code>--timeout</code> or <code>-o</code>: Timeout in seconds after which the application is terminated.
- <code>--help</code> or <code>-h</code>: For help

