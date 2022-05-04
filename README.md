# Netplt

TCP streams graphing tool

Required packages: tshark, matplotlib

```
usage: netplt.py [-h] path [mode] [streams] [time_unit]

Build graphs for TCP steams

positional arguments:
  path        Path to pcap file or directory with pcap files
  mode        Graph type: grid or united plot
  streams     Streams to be plotted, space-separated
  time_unit   Time unit on the plot

optional arguments:
  -h, --help  show this help message and exit
```
Work examples:  
![grid](https://helicopter.intra.ispras.ru/vovchenko.ra/netplt/-/blob/master/streams_graph_grid_test.png)  
![united](https://helicopter.intra.ispras.ru/vovchenko.ra/netplt/-/blob/master/streams_graph_united_test.png)