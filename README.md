# Netplt

TCP streams graphing tool

Required packages: tshark, matplotlib

```
usage: netplt.py [-h] path [streams] [time_unit]

Build graphs for TCP steams

positional arguments:
  path        Path to pcap file or directory with pcap files
  streams     Streams to be plotted, space-separated
  time_unit   Time unit on the plot

optional arguments:
  -h, --help  show this help message and exit

usage example: netplt.py /home/roman/My/netplt_test/test.pcap "16 22" 10
```
 
[Example of work](https://helicopter.intra.ispras.ru/vovchenko.ra/netplt/-/blob/master/streams_graph_test.png)