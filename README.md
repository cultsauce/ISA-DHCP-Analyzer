##### ISA Final Project
## dhcp-stats: DHCP Traffic Monitoring

### Description

<b>dhcp-stats</b> is a terminal aplication capable of providing statistical information about utilization of IP addresses in a network by analyzing the undergoing DHCP traffic

### Usage

First compile the program using <b>make</b>:

``` $ make ```

Then run the application with the following command:

```./dhcp-stats [-r \<filename>] [-i \<interface-name>] \<ip-prefix> [ \<ip-prefix> [ ... ] ]```

where
```
-r <filename> pcap file containing captured network traffic to analyze (in offline mode)

-i <interface-name> interface to listen on in online mode

<ip-prefix> IP address prefixes whose statistics will be computed
```

### Examples

To terminate the application, press Ctrl+C
```
$ ./dhcp-stats -r examples/dhcp.pcap 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22

$ ./dhcp-stats -i eth0 192.168.1.0/24

$ ./dhcp-stats -i wlp1s0 192.168.1.0/22 192.168.0.0/24
```
