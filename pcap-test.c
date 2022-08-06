#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define ETH_ALEN 6


// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	struct ether_header *eptr;
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct ether_header *ep;
		struct pcap_pkthdr* header;
		const u_char* packet;
		unsigned short ether_type; 
		int chcnt =0;
    	static int count = 1;
		int length=0;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		// 이더넷 헤더를 가져온다. 
    	ep = (struct ether_header *)packet;
		printf("ethernet_ src : %02x:%02x:%02x:%02x:%02x:%02x \n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);
		printf("ethernet_ drc : %02x:%02x:%02x:%02x:%02x:%02x \n",ep->ether_dhost[0],ep->ether_dhost[1],ep->ether_dhost[2],ep->ether_dhost[3],ep->ether_dhost[4],ep->ether_dhost[5]);
		// IP 헤더를 가져오기 위해서 
		// 이더넷 헤더 크기만큼 offset 한다.   
		packet += sizeof(struct ether_header);
		// 프로토콜 타입을 알아낸다. 
    	ether_type = ntohs(ep->ether_type);	
		// 만약 IP 패킷이라면 
		if (ether_type == ETHERTYPE_IP)
		{
			// IP 헤더에서 데이타 정보를 출력한다.  
			iph = (struct ip *)packet;
			printf("IP 패킷\n");
			printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
			printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

			// 만약 TCP 데이타 라면
			// TCP 정보를 출력한다. 
			if (iph->ip_p == IPPROTO_TCP)
			{
				tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
				printf("Src Port : %d\n" , ntohs(tcph->source));
				printf("Dst Port : %d\n" , ntohs(tcph->dest));
			}

			// Packet 데이타 를 출력한다. 
			// IP 헤더 부터 출력한다.  
			length = header->len;
			while(length--)
			{
				printf("%02x", *(packet++)); 
				if ((++chcnt % 16) == 0) 
					printf("\n");
			}
		}
		// IP 패킷이 아니라면 
		else
		{
			printf("NONE IP 패킷\n");
		}
		printf("\n\n");
		
	}

	pcap_close(pcap);
}
