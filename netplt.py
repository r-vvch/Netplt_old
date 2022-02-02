import argparse
import math
import pyshark
import matplotlib.pyplot as plt
from datetime import datetime


class PacketInfo:
    def __init__(self, stream, length, time_relative):
        self.stream = int(stream)
        self.length = float(length)
        self.time_relative = float(time_relative)

    def __str__(self):
        return "% s % s % s" % (self.stream, self.length, self.time_relative)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build graphs for TCP steams')
    parser.add_argument('pcap_file_name', type=str, help='Path to input pcap file')
    parser.add_argument('streams', nargs='?', type=str, default='all', help='Streams to be plotted, space-separated')
    parser.add_argument('num_intervals', nargs='?', type=int, default=10, help='Number of intervals on graphs')
    parser.add_argument('--save', '-s', action='store_true', help='Save graphs')
    args = parser.parse_args()

    pcap = pyshark.FileCapture(args.pcap_file_name, display_filter="tcp")
    num_intervals = args.num_intervals

    selected_streams = []
    selected_streams_str = args.streams
    if selected_streams_str != 'all':
        selected_streams = sorted([int(x) for x in selected_streams_str.split()])

    save = args.save

    packet_storage = {}

    max_stream = 0
    max_time = 0
    min_time = float(pcap[0].sniff_timestamp)
    for packet in pcap:
        if float(packet.sniff_timestamp) < min_time:
            min_time = packet.sniff_timestamp
    for packet in pcap:
        packet_time = float(packet.sniff_timestamp) - min_time
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
        if packet_time > max_time:
            max_time = packet_time
        if selected_streams_str == 'all' or stream_num in selected_streams:
            try:
                packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet_time))
            except KeyError:
                packet_storage[stream_num] = []
                packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet_time))

    time_unit = max_time / num_intervals
    if len(packet_storage) == 1:
        plt.rcParams["figure.figsize"] = (3, 3)
    elif len(packet_storage) == 2:
        plt.rcParams["figure.figsize"] = (6, 3)
    elif selected_streams_str == 'all':
        plt.rcParams["figure.figsize"] = (9, math.ceil((max_stream + 1) / 3) * 3)
    else:
        plt.rcParams["figure.figsize"] = (9, math.ceil(len(selected_streams) / 3) * 3)

    pos = 1
    for stream, stream_packets in packet_storage.items():
        times = []
        lengths = []
        current_time = 0
        while current_time < max_time:
            interval_length = 0
            for packet in stream_packets:
                if current_time < packet.time_relative < current_time + time_unit:
                    interval_length += packet.length
            times.append(current_time)
            lengths.append(interval_length)
            current_time += time_unit
        if len(packet_storage) == 2:
            plt.subplot(1, 2, pos)
        elif len(packet_storage) > 2:
            if selected_streams_str == 'all':
                plt.subplot(math.ceil((max_stream + 1) / 3), 3, stream + 1)
            else:
                plt.subplot(math.ceil(len(selected_streams) / 3), 3, pos)
        times.append(max_time)
        plt.stairs(lengths, times, fill=True)
        plt.title(stream)
        plt.xlabel('time')
        plt.ylabel('length')
        pos += 1

    plt.tight_layout()

    if save:
        now = datetime.now()
        now.replace(microsecond=0)
        plt.savefig('streams_graph_' + now.isoformat(sep='_', timespec='seconds') + '.png')
    else:
        plt.show()
