# NetworkRouting

The project uses multiple Virtual Windows Images and aims 
to ensure that ICMP Packets reach other PCs normally.

This project uses the TCP/IP Layer protocol, but TCP Layer is not implemented separately. 
Routing function is handled by IPLayer.

Virtual machines use VMWare and Windows10.

The test transmits ICMP packets from one PC Image to another PC Image with IP knowledge, 
and the PC Image responsible for routing in the middle acts as Router.

Since the Routing Table uses the Static Routing Table, 
you must set up a connection to the Router program before Test.
