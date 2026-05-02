#include "networkUtils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
