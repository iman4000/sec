#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
// lentgh of array
#define LENTGH 100
//tcp protocol number
#define TCP 6
//UDP protocol number
#define UDP 17


struct ftuple{
    char *src_ip, *des_ip;
    u_short src_port, des_port;
    int protocol;
};

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *eptr;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;
    struct ftuple entity;
    
    eptr = (struct ether_header *)packet;
    //check ethernet header
    if(eptr->ether_type == ETHERTYPE_IP){
        //make ip
        ip = (struct iphdr *)(packet + sizeof(struct ether_header));
        memset(&source, 0, sizeof(source));
	    source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
	    dest.sin_addr.s_addr = ip->daddr;
        entity.src_ip = inet_ntoa(source.sin_addr);  // SOURCE IP
        entity.des_ip = inet_ntoa(dest.sin_addr);    // DEST IP
        iphdrlen = ip->ihl*4;
        if(ip->protocol == TCP){          //TCP
            tcp = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ether_header));
            entity.src_port = ntohs(tcp->source);     //SOURCE PORT
            entity.des_port = ntohs(tcp->dest);       //DEST PORT
            entity.protocol = TCP;
        }
        else if(ip->protocol == UDP){      //UDP
            udp = (struct udphdr *)(packet + iphdrlen + sizeof(struct ether_header));
            entity.src_port = ntohs(udp->source);     //SOURCE PORT
            entity.des_port = ntohs(udp->dest);       //DEST PORT
            entity.protocol = UDP;
        }
    }
}

int main(int argc, char **argv){
    pcap_t *handle;
    pcap_if_t *alldevsp, *device;
    char errbuf[PCAP_ERRBUF_SIZE], *devname, devs[LENTGH][LENTGH];
    int count =1, n;

    //First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

    handle = pcap_open_live(devname, SNAP_LEN, 1, 0, errbuf);
    pcap_loop(handle, -1, process_packet, NULL);

    return 0;
}