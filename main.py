import pyshark


class PacketInfo:
    def __init__(self, stream, length, time_relative):
        self.stream = stream
        self.length = length
        self.time_relative = time_relative

    def __str__(self):
        return "% s % s % s" % (self.stream, self.length, self.time_relative)
        # return "stream: % s,\n" \
        #        "length: % s,\n" \
        #        "time:   % s\n" % (self.stream, self.length, self.time_relative)


if __name__ == '__main__':
    pcap = pyshark.FileCapture('/home/roman/My/SSL_try/capture_480_10min_tcp_100_frames.pcap', display_filter="tcp")

    packet_storage = []

    max_stream = 0
    for packet in pcap:
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
        try:
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))
        except IndexError:
            packet_storage.append([])
            while len(packet_storage) < stream_num + 1:
                packet_storage.append([])
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))

    print(max_stream)

    for stream_packets in packet_storage:
        for packet in stream_packets:
            print(packet)

    # curr_stream = 0
    # while curr_stream <= max_stream:
    #     for packet in pcap:
    #         if int(packet.tcp.stream) == curr_stream:
    #             print(packet.tcp.stream, packet.tcp.len, packet.tcp.time_relative)
    #     curr_stream += 1

    # print(dir(packet.tcp))
    # print(packet.tcp)

    # for packet in pcap:
    #     print(packet.tcp.stream, packet.tcp.len, packet.tcp.time_relative)
