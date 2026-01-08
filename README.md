# ReAct: Reflection Attack Mitigation For Asymmetric Routing
## David Hay, Mary Hogan, Shir Landau Feibish
  
Amplification Reflection Distributed Denial-of-Service (AR-DDoS) attacks remain a formidable threat, exploiting stateless protocols to flood victims with illegitimate traffic. Recent advances have enabled data-plane defenses against such attacks, but existing solutions typically assume symmetric routing and are limited to a single switch. These assumptions fail in modern networks where asymmetry is common, resulting in dropped legitimate responses and persistent connectivity issues. 

This paper presents ReAct, an in-network defense for AR-DDoS that is robust to asymmetry. \sysName performs request-response correlation across switches using programmable data planes and a sliding-window of Bloom filters. To handle asymmetric traffic, \sysName introduces a data-plane-based request forwarding mechanism, enabling switches to validate responses even when paths differ. ReAct can automatically adapt to routing changes with minimal intervention, ensuring continued protection even in dynamic network environments. 

We implemented ReAct on both a P4 interpreter and NVIDIA's BlueField-3, demonstrating its applicability across multiple platforms. Evaluation results show that ReAct filters nearly all attack traffic without dropping legitimate responses-even under high-volume attacks and asymmetry. Compared to state-of-the-art approaches, ReAct achieves significantly lower false positives. To our knowledge, \sysName is the first data-plane AR-DDoS defense that supports dynamic, cross-switch collaboration, making it uniquely suitable for deployment in networks with asymmetry.

- NVIDIA's BlueField-3 implementation: in folder <code>/BlueField3 </code>
- P4 Lucid implementation in folder <code>/Lucid</code>
