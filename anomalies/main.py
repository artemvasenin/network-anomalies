'''Main module. Im planning to call checks from other modules from here'''
import sys

from pcap import PcapCheckForRequestsSpike


def main():
    '''Main func. Calls checks from other modules'''
    pcap_file = sys.argv[1]
    pcap = PcapCheckForRequestsSpike()
    pcap.run(pcap_file)

if __name__ == '__main__':
    main()
