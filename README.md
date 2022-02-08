# Netplt

TCP streams graphing tool

```
usage: netplt.py [-h] [--save] path [streams] [num_intervals]

Build graphs for TCP steams

positional arguments:
  path           Path to pcap file or directory with pcap files
  streams        Streams to be plotted, space-separated
  num_intervals  Number of intervals on graphs

optional arguments:
  -h, --help     show this help message and exit
  --save, -s     Save graphs

usage example: netplt.py /home/roman/My/netplt_test/capture_360_10min_tcp.pcap "16 22" -s
```
 
[Example of work](https://helicopter.intra.ispras.ru/vovchenko.ra/netplt/-/blob/master/streams_graph_capture_360_10min_tcp.pcap.png)