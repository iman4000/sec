/*Some notes:
* This source modified some functions of "sniffex.c"
* THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
* Some defines of calculating of headers were copied from "sniffex.c"
*
********************************************************************
* example for compilling this source:
* 
* gcc <file-name>.c -o <file-name> -lpcap -lghthash
* 
******************************************************************** 
* 1. Ethernet headers are always exactly 14 bytes, so we define this
* explicitly with "#define". Since some compilers might pad structures to a
* multiple of 4 bytes - some versions of GCC for ARM may do this -
* "sizeof (struct sniff_ethernet)" isn't used.
* 
* 2. Check the link-layer type of the device that's being opened to make
* sure it's Ethernet, since that's all we handle in this example. Other
* link-layer types may have different length headers (see [1]).
*
* 3. This is the filter expression that tells libpcap which packets we're
* interested in (i.e. which packets to capture). Since this source example
* focuses on IP and TCP, we use the expression "ip", so we know we'll only
* encounter IP packets. The capture filter syntax, along with some
* examples, is documented in the tcpdump man page under "expression."
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>             //for alarm function
#include <sys/socket.h>
#include <arpa/inet.h>          // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	    //Provides declarations for udp header
#include <netinet/tcp.h>	    //Provides declarations for tcp header
#include <netinet/ip.h>         //Provides declarations for ip header

#include <pcap.h>
#include "ght_hash_table.h"

/*###################################__functions__#######################################*/

//callback function for pcap_loop() function
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

//function for computing headers
void process_ip_packet(const u_char * , int);
//void print_tcp_packet(const u_char *  , int );
//void print_udp_packet(const u_char * , int);
//void print_icmp_packet(const u_char * , int );
void insert_entity(void *info, int);
void print_table();

// fonction for comparing in qsort
int compare(const void *p, const void *q);

/*####################################__Global-var__###########################################*/

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
static u_char buff;
static int size;

 

/**********************************************************************/
int compare(const void *p, const void *q){
	struct iphdr *first_ip = (struct iphdr *)p;
	int size_ip_f , size_tcp_f, size_payload_f;
	size_ip_f = first_ip->ihl*4;
	struct tcphdr *first_tcph=(struct tcphdr*)(buff + size_ip_f + sizeof(struct ethhdr));
	size_tcp_f = first_tcph->doff*4;
	size_payload_f = size - (size_ip_f + size_tcp_f);

	struct iphdr *second_ip = (struct iphdr *)q;
	int size_ip_s, size_tcp_s, size_payload_s;
	size_ip_s = second_ip->ihl*4;
	struct tcphdr *second_tcph=(struct tcphdr*)(buff + size_ip_s + sizeof(struct ethhdr));
	size_tcp_s = second_tcph->doff*4;
	size_payload_s = size - (size_ip_s + size_tcp_s);

	return (size_payload_f - size_payload_s);
	
}
//**********************************************************************

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    
   size = header->len;
    
   buff = buffer;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));////////////////////ethernet define////////
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			ght_insert(table3, iph, sizeof(iph), &icmp);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			ght_insert(table1, iph, sizeof(iph), &tcp);
			break;
		
		case 17: //UDP Protocol
			++udp;
			ght_insert(table2, iph, sizeof(iph), &udp);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

//*******************************************************
/*void print_tcp_packet(const u_char *Buffer, int size){

	int flag =1;
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	info[1]=tcph;
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    int payload = size - header_size;

	info[2]= &payload;

	insert_entity(info, flag);

}*/

//*******************************************************
/*void print_icmp_packet(const u_char *Buffer, int size){

	int flag=2;
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	info[0]=iph;

	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	info[1]=icmph;
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);

	int payload = size - header_size;

	info[2]= &payload;

	insert_entity(info, flag);

}*/

//*******************************************************
/*void print_udp_packet(const u_char *Buffer, int size){

	int flag=3;
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	info[0]=iph;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	info[1]=udph;
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

	int payload = size - header_size;

	info[2]= &payload;

    insert_entity(info, flag);
}*/

//*******************************************************
void print_table(){

	struct iphdr *final;
	int option;

	while(1){
	printf("chose what protocol you want to list: \n"
			"1:TCP \n"
			"2:ICMP \n"
			"3:UDP \n"
			"4:exit \n");
	scanf("%d", &option);

	// print TCP information
	if(option == 1){
		struct iphdr *arr[tcp];
		for(tcp-1; tcp < 0; tcp--){
			arr[tcp] = (struct iphdr *)ght_get(table1, sizeof(iph), &tcp);
		}
		qsort(arr, sizeof(arr)/sizeof(arr[0]), sizeof(arr), compare);
	}

	// print ICMP information
	else if(option == 2){
		struct iphdr *arr[icmp];
		for(icmp-1; icmp < 0; icmp--){
			arr[icmp] = (struct iphdr *)ght_get(table3, sizeof(iph), &icmp);
		}
		qsort(arr, sizeof(arr)/sizeof(arr[0]), sizeof(arr), compare);
		}

	// print UDP informations
	else if(option == 3){
		struct iphdr *arr[udp];
		for(udp-1; udp < 0; udp--){
			arr[udp] = (struct iphdr *)ght_get(table2, sizeof(iph), &udp);
		}
		qsort(arr, sizeof(arr)/sizeof(arr[0]), sizeof(arr), compare);
	}
	else if(option == 4){printf("Thanks :D BYE"); break;}
	}
}
/*##############################___Main___###############################*/

int main(int argc, char **argv)
{

	static ght_hash_table_t *table1;
 	table1 = ght_create(1000);
 	ght_set_rehash(table1, TRUE);


 	static ght_hash_table_t *table2;
 	table2 = ght_create(1000);
 	ght_set_rehash(table2, TRUE);

    static ght_hash_table_t *table3;
    table3 = ght_create(1000);
    ght_set_rehash(table3, TRUE);

    pcap_if_t *alldevsp /*list of devices that can be opened for a live capture*/ , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

    
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
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
  
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
		exit(EXIT_FAILURE);
	}

    printf("Done\n");


    pcap_loop(handle, -1, process_packet, NULL);
    //count 5 min
    sleep(5*60);     
    pcap_breakloop(handle);
    //function with table for sorting and printing

    // cleanup
	pcap_close(handle);

	print_table();

    return 0;
}