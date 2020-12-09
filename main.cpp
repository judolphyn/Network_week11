#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdio>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define MAC_LEN 6
#define ESSID_MAX_LEN 100
#define BEACON_MAX_COUT 100

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

typedef struct ieee80211_radiotap_header {
    u_int8_t    it_version;     /* set to 0 */
    u_int8_t    it_pad;
    u_int16_t   it_len;         /* entire length */
    u_int32_t   it_present;     /* fields present */
} __attribute__((__packed__)) Rad_hdr;      /* https://www.radiotap.org */

typedef struct beacon_frame_header {
    u_int8_t    type;
    u_int8_t    control;
    u_int16_t   duration;
    u_int8_t    dst_addr[MAC_LEN]; //=receiver addr
    u_int8_t    src_addr[MAC_LEN]; //=transmitter addr
    u_int8_t    bss_id[MAC_LEN]; //=receiver addr
    u_int16_t   fra_seq;
} __attribute__((__packed__)) Beac_hdr; 

typedef struct beacon { // structure to store the information.
    u_int8_t    bss_id[MAC_LEN];
    int         beacons;
    char        ess_id[ESSID_MAX_LEN];
} Beacon;

Beacon beacon_list[BEACON_MAX_COUT]; // Answer List
int beacon_list_size = 0;

void print_mac(u_char *Mac){
    int i;
    for (i = 0; i < 5; i++) {
        printf("%02X:", Mac[i]);
    }
    printf("%02X", Mac[5]);
    return;
}

void printbeac(){
    system("clear"); // to clear 
    printf("BSSID\t\t\tBeacon\t\tESSID\n");
    for(int i = 0 ; i < beacon_list_size ; i++) {
		print_mac(beacon_list[i].bss_id);
		printf("   %d\t\t", beacon_list[i].beacons);
		printf("%s\n", beacon_list[i].ess_id);
	}
    return;
}

void airodump(const u_char* packet, int packet_len){
    Rad_hdr *rad_hdr = (Rad_hdr*)packet;
    Beac_hdr *beac_hdr = (Beac_hdr*)(packet + rad_hdr->it_len);
    if(beac_hdr->type != 0x80) return; 
    
    int i;
    for(i=0;i<beacon_list_size;i++){ //now check if it is in list
        if(!memcmp(beac_hdr->bss_id, beacon_list[i].bss_id, MAC_LEN)) { // it is in.
            beacon_list[i].beacons ++; // increase beacon.
            int wireless_idx = rad_hdr->it_len + sizeof(beac_hdr) + 12; // 12 : Fixed parameters
            if(packet[wireless_idx] != 0) return ; // first tagged parameter should be SSID. 
            int tag_len = packet[wireless_idx + 1]; // store Tag length
            memcpy(beacon_list[i].ess_id, packet+wireless_idx+2, tag_len);
            break;
        } 
        // it is not in.
        memcpy(beacon_list[i].bss_id, beac_hdr->bss_id, MAC_LEN);
        beacon_list[i].beacons = 1;
        
        int wireless_idx = rad_hdr->it_len + sizeof(beac_hdr) + 12; 
        if(packet[wireless_idx] != 0) return ; 
        int tag_len = packet[wireless_idx + 1];
        memcpy(beacon_list[i].ess_id, packet+wireless_idx+2, tag_len);
        beacon_list_size ++; //we input new beacon, so increase.      
    }
    printbeac();
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char *interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 100, errbuf);

    if (!handle) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        } 
        airodump(packet, header->caplen);
    }
    pcap_close(handle);

    return 0;
}