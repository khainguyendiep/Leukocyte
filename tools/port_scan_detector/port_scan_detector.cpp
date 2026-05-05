//port_scanning_detector.cpp
#include "port_scan_detector.h"
#include "core/logger/logger.h"
#include "core/utils/utils.h"
#include "core/network/packetParser.h"

const int SCANNED_PORTS_THRESHOLD = 10;
void add_port_into_hashtable(struct hash_struct *scanned_ports, port_scanned_state *state){
	HASH_ADD_INT(state->hash_head, port_index, scanned_ports);
}

struct hash_struct *is_port_exist(int port_index, port_scanned_state *state){
	struct hash_struct *scanned_ports;
	HASH_FIND_INT(state->hash_head, &port_index, scanned_ports);
	return scanned_ports;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	port_scanned_state *state = (port_scanned_state*)args; //using local variables
	ParsedPacket captured_packet;
	parse_packet(packet, captured_packet);
	
	struct hash_struct *scanned_ports = is_port_exist(captured_packet.dest_port, state);
	if(scanned_ports == NULL){
		printf("%d\n", captured_packet.dest_port);
		scanned_ports = (struct hash_struct *) malloc(sizeof(struct hash_struct));
		add_port_into_hashtable(scanned_ports, state);
		scanned_ports->scanning_times = 1;
		state->port_counter++;
	}
	else{
		scanned_ports->scanning_times++;
	}
	printf("%d\n", state->port_counter);
	if(state->port_counter >= SCANNED_PORTS_THRESHOLD){
		printf("YES\n"); LogEvent event;
		event.timestamp = format_timestamp_from_header(header);
		event.tool = "port_scanning_detector";
		event.event_type = "port scanning";
		event.severity = "medium";
		event.threat_id = 100060;
		event.src_ip = "N/A";
		event.dest_port = -1;
		event.protocol = "N/A";
		event.description =	"Possible port scan";
		write_log(event, "/var/log/soc_toolkit/port_scan_detector.log");

		pcap_breakloop(state->handle);
	}
}
