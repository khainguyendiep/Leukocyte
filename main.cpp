#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <chrono>
#include <map>
#include <string.h>

#if defined(_WIN32)
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib") 
#else
	#include <sys/socket.h>
    #include <unistd.h>
#endif
const long long DOSPACKETTHRESHOLD = 15000; // packets
const double DOSTIMETHRESHOLD = 10000; //milisecond

struct DosDetectorState{
	pcap_t *handle;
	std::chrono::steady_clock::time_point timeBegin = std::chrono::steady_clock::now();
	std::chrono::steady_clock::time_point timeEnd = std::chrono::steady_clock::now();
	long long packetNumber = 0;
	long long countCapturedPacket = 0;
};

static const char hex_table[] = "0123456789abcdef";
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	char source[10]; //10 memory cells can be contain 4 bytes of source IPv4 (XX.YY.ZZ.TT)
	int offset = 0; //offset of source
	for(int i=26; i<30; i++){
		if(*(packet+i) < 16){ //add 0 before byte < 16 in hexdecimal (in hex it just has 1 character) 
			offset += snprintf(source + offset, sizeof(source) - offset, "0");
		}
		offset += snprintf(source + offset, sizeof(source) - offset, "%x", packet[i]);
	}
	//printf("%s\n", source);
	DosDetectorState *state = (DosDetectorState*)args;
	state->packetNumber++;
	state->countCapturedPacket++;
	printf("Captured %lld packets\n", state->packetNumber);
	if(state->countCapturedPacket == DOSPACKETTHRESHOLD){
			state->timeEnd = std::chrono::steady_clock::now();
			std::chrono::milliseconds elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(state->timeEnd - state->timeBegin);
			if(elapsedTime.count() <= DOSTIMETHRESHOLD){
				printf("The computer got a Dos attack.\n");
				pcap_breakloop(state->handle);
			}
		printf("Elapsed time: %ld\n", elapsedTime.count());
		state->timeBegin = std::chrono::steady_clock::now(); // if there is not a Dos a attack, setting new time-counter
		state->countCapturedPacket = 0;
	}
}

bool listAllDevs(pcap_if_t *alldevsp, char *listDev[], int &countDevs, char *list_ipv4_devs[]){
	for(pcap_if_t *d = alldevsp; d != NULL; d = d->next){
		// finding ipv4 of a device by iterating a linked list of addresses (include ipv6, ipv4, MAC address... without any order)
		for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next){
			if(a->addr->sa_family == AF_INET){ // device has IP
				countDevs++;
				listDev[countDevs] = d->name;
				printf("[%d] - %s - %s\n", countDevs, d->name, d->description);
				struct sockaddr_in *dev_info = (struct sockaddr_in *)a->addr;
				// because of inet_ntoa just point to a static memory in despite the differences between the two sin_addr
				// so we need to use strdup() to allocate each sin_addr to new position
				list_ipv4_devs[countDevs] = strdup(inet_ntoa(dev_info->sin_addr));
				break;
			}
		}
	}
	if(countDevs == 0) return false;
	return true;
}
void choosingDev(pcap_if_t *alldevsp, char *listDevs[], char **dev_name, char *list_ipv4_devs[], char** ipv4_dev){
	int countDevs = 0;
	if(listAllDevs(alldevsp, listDevs, countDevs, list_ipv4_devs) == false){
		printf("No devices available.\n");
		return; 
	}
	printf("Choose one device:\n");
	int devOrderNumber = 0;
	while(true){
		scanf("%d", &devOrderNumber);
		if(devOrderNumber <= countDevs){
			break;
		}
		else{
			printf("Please choosing available number.\n"); 
		}
	}
	*ipv4_dev = list_ipv4_devs[devOrderNumber];
	*dev_name = listDevs[devOrderNumber];
	printf("Device: %s - IPv4: %s\n", *dev_name, *ipv4_dev);
	return;
}

const int MAX_DEVS = 10000; //just a random number
int main(){
	printf("Start detect\n");
	DosDetectorState state;
	pcap_t *handle;
	bpf_u_int32 mask; // netmask of sniffing device
	bpf_u_int32 net;
	struct bpf_program fp; // the complied filter expression
	char *dev_name = NULL, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	char *listDevs[MAX_DEVS];
	char *list_ipv4_devs[MAX_DEVS];
	char *ipv4_dev;
	
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
	*  device is name of device
	*  snaplen is length of length of the packet to be captured
	*  promisc (Promiscuous Mode) with:
	**  	0 is Network cards only accept packets specifically addressed to your computer (and broadcast packets). They ignore packets from other users. 
	**  	1 is The network card will "grab" all packets p(double)(state->timeEnd - state->timeBegin)assing through the cable, including packets not intended for it.
	*  to_ms (read timeout): The unit is milliseconds (ms). It specifies the time the kernel waits to gather enough packets before returning the data to your handler function.
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
	pcap_loop(handle, -1, got_packet, (u_char*)&state);
	printf("Finished detection.");
	pcap_close(handle);
	return(0);
}
