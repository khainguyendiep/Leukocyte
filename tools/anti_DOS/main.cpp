#include <stdio.h>
#include <pcap.h>
#include "core/network/networkUtils.h"
#include "core/utils/utils.h"
#include "anti_DOS.h"

const int MAX_DEVS = 10000; //just a random number
int main(){
	printf("Start detect\n");
	DosDetectorState state; //local variable using in call_back function
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
	/* pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
	* device is name of device
	* snaplen is length of length of the packet to be captured
	* promisc (Promiscuous Mode) with:
	** 0 is Network cards only accept packets specifically addressed to your computer (and broadcast packets). They ignore packets from other users. 
	** 1 is The network card will "grab" all packets p(double)(state->timeEnd - state->timeBegin)assing through the cable, including packets not intended for it.
	* to_ms (read timeout): The unit is milliseconds (ms). It specifies the time the kernel waits to gather enough packets before returning the data to your handler function.
	*
	*/	
	
	handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000000, errbuf);
	if(handle == NULL){
		printf("Cannot open device\n");
		printf("%s\n", errbuf);
		return (2);
	}
	
	/* int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
	 * pcap_t * p: This is the session management pointer for the packet capture you created earlier using the pcap_open_live function.
	 * struct bpf_program *fp: This is the "destination". After the function finishes running, the compiled machine code will be saved to this structure variable.
	 * const char *str: This is the rules what you want to capture in the captured packet.
	 * int optimize: accelerate compile code.a
	 * bpf_u_int32 netmask: netmask of listening network card (the mask parameter of pcap_lookupnet)
	*/
	
	if(pcap_compile(handle, &fp, filter_expression, 1, mask) != 0){
		printf("Could not parse filter\n");
		return (2);	
	}
	
	if(pcap_setfilter(handle, &fp) != 0){
		printf("Could not install filter");
		return (2);
	}
	
	state.handle = handle;
	state.timeBegin = std::chrono::steady_clock::now();
	state.packetNumber = 0;
	state.countCapturedPacket = 0;

	pcap_loop(handle, -1, got_packet, (u_char*)&state);
	printf("Finished detection.");
	pcap_close(handle);
	return(0);
}
