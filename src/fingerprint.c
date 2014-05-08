#include "fps.h"
#include "state.h"

#define FPS_INVALID "invalid packet data"
#define FPS_UNKNOWN "unknown"

static char _fingerprint[4096]; // not thread safe!
static int unique_systems;

/***********************************************************/

const char *get_OS(char *query_fp) {
	unsigned int i = 0;

	for (i = 0; i < sizeof(fingerprints) / sizeof(fingerprints[0]); i++){
		if (strcmp(fingerprints[i].print, query_fp) == 0){
			fingerprints[i].count += 1;
			return fingerprints[i].os;
		}
	}

	return FPS_UNKNOWN;
}

void fingerprint(char *buffer, int len){
	const char *os, *end, *ptr, ip_hdr_size = 0;

	snprintf(_fingerprint, sizeof(_fingerprint) - 1, "%04x:%02x:%04x",
           len + 20 - ip_hdr_size, // total length (calculated with assumed ipv4 header
           (unsigned char) buffer[ip_hdr_size + 12],        // tcp header length(and flags)
           ntohs(*(in_port_t *) &buffer[ip_hdr_size + 14]));       // window size

	end = &buffer[len];

	if (len > ip_hdr_size + (unsigned char) buffer[ip_hdr_size + 12])
		end = &buffer[ip_hdr_size + (unsigned char) buffer[ip_hdr_size + 12]];

	for (ptr = &buffer[ip_hdr_size + 20]; ptr < end; ){
		switch (*ptr){
			case 0x0:			// end of options
				ptr = end;
				break;
			case 0x1:                  // some pad entire options portion with NOP to keep response option size the same
				strncat(_fingerprint, ":NOP", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
				ptr++;
				break;
			case 0x2:                  // segment size
				snprintf(&_fingerprint[strlen(_fingerprint)], sizeof(_fingerprint) - strlen(_fingerprint), ":SS%04x", ntohs(*(in_port_t *) (ptr + 2)));
				ptr += 4;
				break;
			case 0x3:                  // window scaling
				strncat(_fingerprint, ":WSxx", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
				ptr += 3;
				break;
			case 0x4:                  // Sack Permitted / Sack Denied
				switch (ptr[1]) 
				{
					case 0x2:
						strncat(_fingerprint, ":SP", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
						break;
					default:
						strncat(_fingerprint, ":SD", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
						break;
				}
				ptr += 2;
				break;
			case 0x6:			// echo request
				strncat(_fingerprint, ":PI", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
				ptr += 6;
				break;
			case 0x7:			// echo reply
				strncat(_fingerprint, ":PO", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
				ptr += 6;
				break;
			case 0x8:                  // Time stamp
				strncat(_fingerprint, ":TS", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
				ptr += 10;
				break;
			default:                   // unknown
				snprintf(&_fingerprint[strlen(_fingerprint)], sizeof(_fingerprint) - strlen(_fingerprint), ":UOP%02x", (unsigned char)(*ptr));
				ptr += (unsigned char)ptr[1];
				break;
		}
	}

	_fingerprint[sizeof(_fingerprint) - 1] = 0;
	os = get_OS(_fingerprint);

	if (strcmp(os, FPS_UNKNOWN) == 0){
	        write_fingerprint(_fingerprint);
	}
	else{
		write_fingerprint(os);
	}
}

int get_unique_systems(){
	unsigned int index;

	for(index = 0; index < sizeof(fingerprints) / sizeof(fingerprints[0]); index++){
		if(fingerprints[index].count != 0)
			unique_systems++;
	}

	return unique_systems;
}

void write_fingerprint(const char* output){
	if (!zconf.fingerprint_file) {
		  fprintf(stderr, "Can't open file: %s!\n", zconf.fingerprint_filename);
		  exit(1);
	}
		
	fprintf(zconf.fingerprint_file, "%s\n", output);
}
