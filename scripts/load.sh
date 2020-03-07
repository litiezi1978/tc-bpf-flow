#!/bin/bash
#IFNAME=$1
#tc qdisc add dev ens33 clsact
#tc qdisc add dev $IFNAME handle 0: ingress
#tc filter add dev $IFNAME ingress  bpf obj classifier.o flowid 0:
tc filter add dev ens33 ingress bpf da obj classifier5.o sec ingress verb
tc filter add dev ens33 egress bpf da obj classifier5.o sec egress verb
