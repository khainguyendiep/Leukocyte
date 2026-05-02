#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <pcap.h>

// If this comment still exists, then this program does not work on Windows
#if defined(_WIN32)
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib") 
#else
	#include <sys/socket.h>
    #include <unistd.h>
#endif

bool listAllDevs(pcap_if_t *alldevsp, char *listDev[], int &countDevs, char *list_ipv4_devs[]);
void choosingDev(pcap_if_t *alldevsp, char *listDevs[], char **dev_name, char *list_ipv4_devs[], char** ipv4_dev);

#endif
