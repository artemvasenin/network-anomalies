'''Checks for pcap files'''
import datetime

import dpkt

from utils import inet_to_str


class PcapCheck():
    '''Class with shared functionality for checks'''
    def read_file(self, pcap_file):
        '''Create dpkt object from pcap file'''
        pcap_file = open(pcap_file, 'rb')
        pcap_object = dpkt.pcap.Reader(pcap_file)

        return pcap_object

    def count_requests(self, pcap_file):
        '''Count requests from IP by minute'''
        pcap_object = self.read_file(pcap_file)

        timestamp_minutes_dict = {}

        for timestamp, buff in pcap_object:

            timestamp = datetime.datetime.utcfromtimestamp(timestamp)
            timestamp_minute = timestamp.replace(second=0, microsecond=0)
            timestamp_minute = timestamp.strftime('%Y-%m-%d-%H-%M')

            eth = dpkt.ethernet.Ethernet(buff)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip_in_bytes = eth.data.src
            ip = inet_to_str(ip_in_bytes)

            if not timestamp_minute in timestamp_minutes_dict:
                timestamp_minutes_dict[timestamp_minute] = {}

            if ip not in timestamp_minutes_dict[timestamp_minute]:
                timestamp_minutes_dict[timestamp_minute][ip] = 1
            else:
                timestamp_minutes_dict[timestamp_minute][ip] += 1

        return timestamp_minutes_dict

    def run(self, pcap_file):
        '''Run class func'''
        self.count_requests(pcap_file)


class PcapCheckForRequestsSpike(PcapCheck):
    '''Check if there suspicious spike in requests'''
    def count_max_requests_per_minute(self, pcap_file):
        '''Count max requests from IP by minute'''
        timestamp_minutes_dict = self.count_requests(pcap_file)

        max_requests_per_minute_dict = {}

        for minute_with_count in timestamp_minutes_dict.items():
            minute, ip_with_count = minute_with_count

            ip_with_max_requests = max(ip_with_count, key=lambda key: ip_with_count[key])

            max_requests_per_ip = ip_with_count[ip_with_max_requests]

            max_requests_per_minute_dict[minute] = max_requests_per_ip

        return max_requests_per_minute_dict

    def check_for_requests_spikes(self, pcap_file):
        '''Check if there any spikes in requests'''
        max_requests_per_minute_dict = self.count_max_requests_per_minute(pcap_file)

        spike_threshold_times = 5
        spikes_found = False

        previous_minute = None

        for minute_with_count in max_requests_per_minute_dict.items():
            minute, count = minute_with_count

            if not previous_minute:
                previous_minute = count
                continue

            elif count >= previous_minute * spike_threshold_times:
                spikes_found = True
                print('Possible DOS: requests spike more than', spike_threshold_times, 'times at', minute)

            else:
                previous_minute = count

        if not spikes_found:
            print('Requests spikes not found')

    def run(self, pcap_file):
        '''Run class func'''
        self.check_for_requests_spikes(pcap_file)
