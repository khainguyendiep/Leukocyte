#include <stdio.h>
#include <pcap.h>
#include "core/network/networkUtils.h"
#include "core/utils/utils.h"
#include "port_scan_detector.h"

const int MAX_DEVS = 10000; //just a random number
int main(){
	printf("Start detect\n");
	port_scanned_state state; //local variable using in call_back function
	pcap_t *handle;
	bpf_u_int32 mask; // netmask of sniffing device
	bpf_u_int32 net;
	struct bpf_program fp; // the complied filter expression
	char *dev_name = NULL, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	char *listDevs[MAX_DEVS];
	char *list_ipv4_devs[MAX_DEVS];
	char *ipv4_dev; // own IPv4 address
	
	for(int i =0; i<MAX_DEVS ; i++){
		listDevs[i] = NULL;
		list_ipv4_devs[i] = NULL;
	}

	if(pcap_findalldevs(&alldevsp, errbuf) != 0){
		printf("Finding netword card error!!!");
		return (2);
	}
	
	//update device name and ipv4 of this device
	choosingDev(alldevsp, listDevs, &dev_name, list_ipv4_devs, &ipv4_dev);
	
	//10000 is a random number to contain all content of expression
	char filter_expression[10000];
	//tcpflags is located in the 13th byte of the TCP header (counting from 0).
	snprintf(filter_expression, sizeof(filter_expression), "((tcp[13] != 0) or udp or icmp) and (not src host %s)", ipv4_dev);

	// pcap_lookupnet() is used to determine the IPv4 network number and mask associated with the network device device.
	if(pcap_lookupnet(dev_name, &net, &mask, errbuf) != 0){
		printf("Cannot get netmask for the device\n");
		return(2);
	}
	handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000000, errbuf);
	if(handle == NULL){
		printf("Cannot open device\n");
		printf("%s\n", errbuf);
		return (2);
	}
	if(pcap_compile(handle, &fp, filter_expression, 1, mask) != 0){
		printf("Could not parse filter\n");
		return (2);	
	}
	
	if(pcap_setfilter(handle, &fp) != 0){
		printf("Could not install filter");
		return (2);
	}
	
	pcap_loop(handle, -1, got_packet, (u_char*)&state);
	printf("Finished detection.");
	pcap_close(handle);
	return(0);
}
