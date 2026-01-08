 # This represent the OVS flow configuration for reACT: Outgoing DNS requests are being forwarded and copied to the DOCA ReACT app. 
 # All other outgoing traffc is forwarded. Incoming DNS responses are sent to the DOCA ReACT app for filtering. Only filtered DNS 
 # responses will be forwarded. All other incoming traffic is forwarded. 
 # 
 # Bridge configurations (change number to match your configuration)
 #
 #
 #                             ReACT APP
 #                        |                |
 #                        |                |
 #                       2|                |3
 #                       ___              ___
 #                    1 /   \4        6  /   \5
 # Internet ————————   ( br1 )────────── ( br2 )——  host
 #                     \___/              \___/
 #
 #
 #
# clean OVS
sudo ovs-vsctl del-br br1
sudo ovs-vsctl del-br br2
sudo ovs-vsctl del-br br3

#create bridges, add ports, clear default tables
sudo ovs-vsctl add-br br1
sudo ovs-vsctl add-br br2
sudo ovs-vsctl add-br br3
sudo ovs-vsctl add-port br1 p0
sudo ovs-vsctl add-port br1 en3f0pf0sf4
sudo ovs-vsctl add-port br2 pf0hpf
sudo ovs-vsctl add-port br2 en3f0pf0sf5
sudo ovs-vsctl add-port br3 p1
sudo ovs-vsctl add-port br3 pf1hpf
sudo ovs-vsctl add-port br1 patch-br1-br2
sudo ovs-vsctl add-port br2 patch-br2-br1
sudo ovs-vsctl set interface patch-br1-br2 type=patch
sudo ovs-vsctl set interface patch-br2-br1 type=patch
sudo ovs-vsctl set interface patch-br2-br1 options:peer=patch-br1-br2
sudo ovs-vsctl set interface patch-br1-br2 options:peer=patch-br2-br1
sudo ovs-ofctl del-flows br1 "table:0"
sudo ovs-ofctl del-flows br2 "table:0"
sudo ovs-ofctl del-flows br3 "table:0"

# br-2 rules: mirroring requests
sudo ovs-ofctl add-flow br2 "priority=1000,in_port=pf0hpf,dl_type=0x0800,nw_proto=17,tp_dst=53,actions=output:en3f0pf0sf5,patch-br2-br1"
sudo ovs-ofctl add-flow br2 "priority=0,in_port=en3f0pf0sf5,actions=output:pf0hpf"
sudo ovs-ofctl add-flow br2 "priority=0,in_port=patch-br2-br1,actions=output:pf0hpf"
sudo ovs-ofctl add-flow br2 "priority=0,in_port=pf0hpf,actions=output:patch-br2-br1"

sudo ovs-ofctl add-flow br1 "priority=1000,in_port=p0,dl_type=0x0800,nw_proto=17,tp_src=53,actions=output:en3f0pf0sf4"
sudo ovs-ofctl add-flow br1 "priority=0,in_port=patch-br1-br2,actions=output:p0"
sudo ovs-ofctl add-flow br1 "priority=0,in_port=p0,actions=output:patch-br1-br2"

sudo ovs-ofctl add-flow br3 "priority=0,in_port=pf1hpf,actions=output:p1"
sudo ovs-ofctl add-flow br3 "priority=0,in_port=p1,actions=output:pf1hpf" 

# sudo ovs-ofctl add-flow br2 "priority=1000,in_port=5,dl_type=0x0800,nw_proto=17,tp_dst=53,actions=output:3,6"
# sudo ovs-ofctl add-flow br2 "priority=0,in_port=3,actions=output:5"
# sudo ovs-ofctl add-flow br2 "priority=0,in_port=6,actions=output:5"
# sudo ovs-ofctl add-flow br2 "priority=0,in_port=5,actions=output:6"
# sudo ovs-ofctl add-flow br1 "priority=1000,in_port=1,dl_type=0x0800,nw_proto=17,tp_src=53,actions=output:2"
# sudo ovs-ofctl add-flow br1 "priority=0,in_port=4,actions=output:1"
# sudo ovs-ofctl add-flow br1 "priority=0,in_port=1,actions=output:4"
 
 #sudo ovs-ofctl add-flow br1 "priority=0,in_port=1,actions=output:4"
 #sudo ovs-ofctl add-flow br3 "priority=0,in_port=1,actions=output:2"
 #sudo ovs-ofctl add-flow br3 "priority=0,in_port=2,actions=output:1"

# configureation for cloning DNS requests
# Existing flow was priority 1000; make this one, say, 1100
#sudo ovs-ofctl add-flow br2 "table=0,priority=1100,udp,in_port=pf0hpf, nw_src=192.168.8.11,tp_dst=53 actions=clone(resubmit(,1)), output:\"patch-br2-br1\""
#ovs-ofctl add-flow br2 "table=1,priority=1100,udp,in_port=pf0hpf,nw_src=192.168.8.11,tp_dst=53 \
 #  actions=\
 #    clone(resubmit(,1)),                \  # copy #1 → table 1
 #    clone(resubmit(,2)),                \  # copy #2 → table 2
 #    set_field:54->udp_dst,              \  # rewrite the original
 #    output:en3f0pf0sf4,                 \
 #    output:\"patch-br2-br1\""

