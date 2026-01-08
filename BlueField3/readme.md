## Description 

We have implemented ReAct on the NVIDIA BlueField-3), a high-performance SmartNIC that integrates both programmable hardware and software processing capabilities. Our deployment assumes a symmetric model in which all DNS requests originate from the client and all responses return to the SmartNIC. This assumption eliminates the need to handle asymmetry, and allows us to compare against existing approaches that only handle symmetric traffic.
We assume a symmetric model because SmartNICs are typically placed near the client; thus they would see both the request and response. 

## Run time parameters

The scriprt <code>react.sh</code> compiles the code (using <code>meson.build</code>) and run the DOCA application. The parameters are as fellows

