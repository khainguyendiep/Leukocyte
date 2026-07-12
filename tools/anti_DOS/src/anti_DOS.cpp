#include "anti_DOS.h"
#include "core/logger/logger.h"
#include "core/utils/utils.h"
#include "core/network/packetParser.h"
#include <stdlib.h>
#include <string.h>

const long long DOSPACKETTHRESHOLD = 8000; // packets
const double DOSTIMETHRESHOLD = 10000; //milisecond

void add_source_into_hashtable(struct hash_struct *s, DosDetectorState *state){
	HASH_ADD_STR(state->hash_head, source_IPv4, s);
} 

struct hash_struct *is_source_exist(char source[20], DosDetectorState *state){
	struct hash_struct *s;
	HASH_FIND_STR(state->hash_head, source, s);
	return s;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	DosDetectorState *state = (DosDetectorState*)args; //using local variables
	ParsedPacket captured_packet;
	parse_packet(packet, captured_packet);

	//adding all sources that sent packets to localhost
	struct hash_struct *s = is_source_exist(captured_packet.src_ip, state);
	if(s == NULL){
		s = (struct hash_struct *) malloc(sizeof(struct hash_struct));
		strcpy(s->source_IPv4, captured_packet.src_ip);
		s->number_packets_sent = 1;
		add_source_into_hashtable(s, state);
	}
	else{
		s->number_packets_sent++;
	}

	//adding every source into priority queue to find the source that sent the most packets
	state->most_sender.push({s->source_IPv4, s->number_packets_sent});

	state->packetNumber++;
	state->countCapturedPacket++;
	printf("Captured %lld packets\n", state->packetNumber);
	if(state->countCapturedPacket == DOSPACKETTHRESHOLD){
			state->timeEnd = std::chrono::steady_clock::now();
			std::chrono::milliseconds elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(state->timeEnd - state->timeBegin);
			if(elapsedTime.count() <= DOSTIMETHRESHOLD){
				printf("The server got a Dos attack from %s\n", captured_packet.src_ip);

				LogEvent event;
				event.event_time = format_timestamp_from_header(header);
				event.tool = "anti_DOS";
				event.event_type = "DOS attack detected";
				event.severity = "high";
				event.threat_id = 100050;
				event.src_ip = captured_packet.src_ip;
				event.dest_port = captured_packet.dest_port;
				event.protocol = captured_packet.protocol;
				event.description =	"Possible DoS attack: Request rate exceeded threshold";
				write_log(event, state->LOG_PATH);

				pcap_breakloop(state->handle);
			}
		printf("Elapsed time: %ld\n", elapsedTime.count());
		state->timeBegin = std::chrono::steady_clock::now(); // if there is not a Dos a attack, setting new time-counter
		state->countCapturedPacket = 0;
	}
}
