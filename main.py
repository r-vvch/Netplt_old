import pyshark


if __name__ == '__main__':
    pcap = pyshark.FileCapture('/home/roman/My/SSL_try/capture_480_10min_tcp.pcap', display_filter="tcp")
    n = 0

    max_stream = 0
    for packet in pcap:
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
    print(max_stream)

    # print(dir(packet.tcp))
    # print(packet.tcp)

    curr_stream = 0
    while curr_stream < max_stream:
        for packet in pcap:
            if packet.tcp.stream == curr_stream:
                print(packet.tcp.stream, packet.tcp.len, packet.tcp.time_relative)
        n += 1
