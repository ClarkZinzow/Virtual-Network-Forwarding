# Virtual-Network-Forwarding

A Java implementation of a learning switch that optimally forwards packets based on link layer
headers and a router that:
* generates Internet Control Messaging Protocol (ICMP) messages when error conditions occur;
* populates the ARP cache by generating and consuming Address Resolution Protocol (ARP) messages;
* and builds a routing table using distance vector routing via an Routing Information Protocol v2
  (RIPv2) implementation.
