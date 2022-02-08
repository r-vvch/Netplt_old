# Netplt

TCP streams graphing tool

```
usage: netplt.py [-h] [-s] path [streams] [time_unit]

Build graphs for TCP steams

positional arguments:
  path        Path to pcap file or directory with pcap files
  streams     Streams to be plotted, space-separated
  time_unit   Time unit on the plot

optional arguments:
  -h, --help  show this help message and exit
  -s, --save  Save plots

usage example: netplt.py /home/roman/My/netplt_test/test.pcap "16 22" 10 -s
```
 
[Example of work](https://helicopter.intra.ispras.ru/vovchenko.ra/netplt/-/blob/master/streams_graph_test.png)