/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h> 
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void process_ip_pkt(struct sr_instance* sr, uint8_t * packet,unsigned int len, char* incoming_interface);
void process_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* incoming_interface);
int is_icmp_pkt_valid(struct sr_ip_hdr *ip_hdr, unsigned int len);
int is_arp_pkt_valid(unsigned int len);
int is_ip_packet_valid(uint8_t *packet);
void send_icmp_pkt(struct sr_instance* sr, unsigned int len, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code, char* incoming_interface);
void forward_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* incoming_interface);
struct sr_rt* sr_rtable_lookup(struct sr_instance *sr, uint32_t destIP);

static uint16_t ip_id = 0;







void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */

	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	print_hdr_eth(packet);
  
    if (ethertype(packet) == ethertype_ip) {
    	if(sr->nat_enabled == 1){
    		int fail = sr_nat_modify_packet(sr, packet, len, interface);
    		if(fail){
    			return;
    		}
    	}
        process_ip_pkt(sr, packet, len, interface);
        
    } else if (ethertype(packet) == ethertype_arp) {
        process_arp_packet(sr, packet, len, interface);        
    }else{
		/* unknow packet type*/
		return;	
	}
	printf("finshe\n");
}/* end sr_ForwardPacket */

/*lookup rtable and return interface*/
struct sr_rt* sr_rtable_lookup(struct sr_instance *sr, uint32_t destIP){
    struct sr_rt* rTable = sr->routing_table;
	struct sr_rt* longest_match;
	longest_match = 0;
    while(rTable)
    {
        uint32_t curMask = rTable->mask.s_addr;
		
        uint32_t curDest = rTable->dest.s_addr;
		uint32_t cur_entry_prefix = curMask & curDest;
		uint32_t dst_prefix = destIP& curMask;
		if(cur_entry_prefix == dst_prefix && (!longest_match || curMask > longest_match->mask.s_addr)){
			longest_match =rTable;
		}
        rTable = rTable->next;
    }
    return longest_match;
}


void process_ip_pkt(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* incoming_interface/* lent */)
{
	
	struct sr_ip_hdr *ip_hdr;
	struct sr_rt *longest_prefix_match;
	ip_hdr = get_ip_header(packet);
	if(!is_ip_packet_valid(packet)){
		printf("not valid ip packet\n");
		return;	
	}
	
	print_hdr_ip((uint8_t *)ip_hdr);
	longest_prefix_match = sr_rtable_lookup(sr, ip_hdr->ip_dst);
	
	if(sr_contains_interface(sr, ip_hdr->ip_dst)){
		
		if(ip_hdr->ip_p == ip_protocol_icmp){
			printf("icmp\n");
			send_icmp_pkt(sr, len, packet, ICMP_ECHO_REPLY_CODE, 0, incoming_interface);
		}else{
			printf("icmp 3 port unreachable\n");

			send_icmp_pkt(sr, len, packet, ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE, incoming_interface);
			return;
		}	
	}else{
		if(longest_prefix_match == NULL){
			/*Send Icmp destation unreachable*/	
			printf("Cannot found in rt. Send Icmp destation unreachable");
			send_icmp_pkt(sr, len, packet, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE, incoming_interface);
			return;	
		}
		if(ip_hdr->ip_ttl < 2){
			/*Send ICMP packet timeout*/
			ip_hdr->ip_ttl--;
			send_icmp_pkt(sr, len, packet, ICMP_TIME_EXCEEDED_TYPE, 0, incoming_interface);	
			return;
		}
				
		printf("packet forwarding\n");

		forward_ip_packet(sr, packet, len, incoming_interface);
	}

}

int is_ip_packet_valid(uint8_t *packet){
	struct sr_ip_hdr *ip_hdr;
	ip_hdr = get_ip_header(packet);
	uint16_t ip_sum_received;
	uint16_t ip_sum_correct;
	ip_sum_received = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	ip_sum_correct = cksum(ip_hdr, ip_hdr->ip_hl*4);
	ip_hdr->ip_sum = ip_sum_received;
	if(ip_hdr->ip_hl*4 < MIN_IP_HEADER_LEN){
		return 0;
	}
	if(ip_sum_correct != ip_sum_received){
		return 0;	
	}
	
	return 1;
}

void send_icmp_pkt(struct sr_instance* sr, unsigned int len, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code, char* incoming_interface){
	struct sr_ip_hdr *original_ip_hdr;
	struct sr_icmp_hdr *icmp_hdr;
	uint8_t *new_packet;
	struct sr_rt *longest_prefix_match;
	struct sr_ethernet_hdr *original_ether_hdr;
	struct sr_ethernet_hdr *new_ether_hdr;
	struct sr_ip_hdr *ip_hdr;
	struct sr_icmp_t3_hdr *icmp_t3_hdr;
	unsigned int new_pkt_len = len;  
	struct sr_if *outgoing_interface;


	ip_hdr = get_ip_header(packet);
	
	
	original_ether_hdr = (struct sr_ethernet_hdr *)packet;
	original_ip_hdr = get_ip_header(packet);
	/*printf("before icmp match src ip\n");
	longest_prefix_match = sr_rtable_lookup(sr, original_ip_hdr->ip_src);
	printf("after icmp match src ip\n");
	
	outgoing_interface = sr_get_interface(sr, longest_prefix_match->interface);
	printf("before icmp typing\n");
	if(!longest_prefix_match){
		printf("there is no interface match found for icmp reply\n");
		return;		
	}*/
	if(icmp_type == ICMP_ECHO_REPLY_CODE){
		icmp_hdr = get_icmp_header(ip_hdr);
		print_hdr_icmp((uint8_t *)icmp_hdr);
		if(!is_icmp_pkt_valid(ip_hdr, len)){
			printf("invalid icmp packet");
			return;	
		}
		new_packet = (uint8_t *)malloc(len);
		new_pkt_len = len;
		memcpy(new_packet, packet, len);
		new_ether_hdr = (struct sr_ethernet_hdr *)new_packet;
		ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
		icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));


		icmp_hdr->icmp_type = icmp_type;
		icmp_hdr->icmp_code = icmp_code;
		icmp_hdr->icmp_sum = 0;

		ip_hdr->ip_id = htons(ip_id); ip_id++;
		ip_hdr->ip_dst = original_ip_hdr->ip_src;
		ip_hdr->ip_src = original_ip_hdr->ip_dst;	
		ip_hdr->ip_ttl = INIT_TTL;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_tos = 0;
		ip_hdr->ip_p = ip_protocol_icmp;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);

		
		icmp_hdr = get_icmp_header(ip_hdr);
		icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);
		new_ether_hdr->ether_type = htons(ethertype_ip);

	}
	
	else if(icmp_type == ICMP_UNREACHABLE_TYPE || icmp_type == ICMP_TIME_EXCEEDED_TYPE){
		printf("icmp 3\n");
		new_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
		new_packet = (uint8_t *)malloc(new_pkt_len);
		new_ether_hdr = (sr_ethernet_hdr_t *)new_packet;
		ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
		icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		
		ip_hdr->ip_hl = MIN_IP_HEADER_LEN;
		ip_hdr->ip_v = IPV4;
		ip_hdr->ip_id = htons(ip_id); ip_id++;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_tos = 0;
		ip_hdr->ip_len = htons(new_pkt_len - sizeof(sr_ethernet_hdr_t));
		ip_hdr->ip_off = htons(IP_DF);
		ip_hdr->ip_ttl = INIT_TTL;
        if (icmp_code == ICMP_PORT_CODE) {
            ip_hdr->ip_src = original_ip_hdr->ip_dst;
        } else {
        	longest_prefix_match = sr_rtable_lookup(sr, original_ip_hdr->ip_src);
			outgoing_interface = sr_get_interface(sr, longest_prefix_match->interface);
            ip_hdr->ip_src = outgoing_interface->ip;
        }
		ip_hdr->ip_dst = original_ip_hdr->ip_src;
		ip_hdr->ip_p = ip_protocol_icmp;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);	
		
		icmp_t3_hdr->icmp_type = icmp_type;
		icmp_t3_hdr->icmp_code = icmp_code;
		icmp_t3_hdr->icmp_sum = 0;
		icmp_t3_hdr->unused = htons(0);
		memcpy(icmp_t3_hdr->data, original_ip_hdr, ICMP_DATA_SIZE);
		
		icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
		memcpy(new_ether_hdr->ether_shost, original_ether_hdr->ether_dhost, ETHER_ADDR_LEN);
		memcpy(new_ether_hdr->ether_dhost, original_ether_hdr->ether_shost, ETHER_ADDR_LEN);
		new_ether_hdr->ether_type = htons(ethertype_ip);

	}
	printf("before forwarding icmp\n");
	forward_ip_packet(sr, new_packet, new_pkt_len, incoming_interface);
	free(new_packet);
	
}


void forward_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* incoming_interface/* lent */){
    struct sr_ip_hdr *ip_hdr;
	struct sr_arpentry *arp_cache_entry;
	struct sr_ethernet_hdr *ethernet_hdr;
	struct sr_if *outgoing_interface;
	struct sr_arpreq *arp_req;
	struct sr_rt *longest_prefix_match;

	ethernet_hdr = (struct sr_ethernet_hdr *)packet;
	ip_hdr = get_ip_header(packet);
	longest_prefix_match = sr_rtable_lookup(sr, ip_hdr->ip_dst);
	
	printf("i got here\n");
	outgoing_interface = sr_get_interface(sr, longest_prefix_match->interface); 
	
	arp_cache_entry = sr_arpcache_lookup(&sr->cache, longest_prefix_match->gw.s_addr);

    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl <= 0) {
        send_icmp_pkt(sr, len, packet, ICMP_TIME_EXCEEDED_TYPE, 0, incoming_interface);
    } else {
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
    }

    if (arp_cache_entry == NULL) {
		printf("no entry found\n");
        arp_req = sr_arpcache_queuereq(&sr->cache, longest_prefix_match->gw.s_addr, packet, len, incoming_interface);
		handle_arpreq(arp_req, sr);
    } else {
		/*Modifiy ethernet packet*/
		longest_prefix_match = sr_rtable_lookup(sr, ip_hdr->ip_dst);
		outgoing_interface = sr_get_interface(sr, longest_prefix_match->interface); 
		memcpy(ethernet_hdr->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
		memcpy(ethernet_hdr->ether_dhost, arp_cache_entry->mac, ETHER_ADDR_LEN);


        sr_send_packet(sr, packet, len, outgoing_interface->name);

		free(arp_cache_entry);

    }

	
}

void process_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* incoming_interface/* lent */)
{

    struct sr_arp_hdr *arp_hdr;
	struct sr_arpreq *arp_req;
	struct sr_if *src_iface; 
	struct sr_ethernet_hdr *ether_hdr;
	if(!is_arp_pkt_valid(len)){
		fprintf(stderr, "ARP packet not valid");
		return;	
	}
	arp_hdr = get_arp_header(packet);
	ether_hdr = (struct sr_ethernet_hdr *)packet;
	src_iface = sr_get_interface(sr, incoming_interface);
	if(ntohs(arp_hdr->ar_op) == arp_op_request){

		if(arp_hdr->ar_tip != src_iface->ip){
			return;
		}
		/*Add the sender ip/MAC into cache*/
		sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
		
		arp_hdr->ar_op = htons(arp_op_reply);
		memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		arp_hdr->ar_tip = arp_hdr->ar_sip;
		memcpy(arp_hdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
		arp_hdr->ar_sip = src_iface->ip;
		memcpy(ether_hdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
		memcpy(ether_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, len, incoming_interface);
  
	}

	else if(ntohs(arp_hdr->ar_op) == arp_op_reply){

		arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);	
		if(arp_req){

			struct sr_packet *packet = arp_req->packets;
			
			while(packet){
				/*sr_handlepacket(sr, packet->buf, packet->len, packet->iface);*/
				if (ethertype(packet->buf) == ethertype_ip) {

			        process_ip_pkt(sr, packet->buf, packet->len,  packet->iface);
        
			    } else if (ethertype(packet->buf) == ethertype_arp) {
			        process_arp_packet(sr, packet->buf, packet->len, packet->iface);        
   				}	
				packet = packet->next;
			}
				
		}
		sr_arpreq_destroy(&sr->cache, arp_req);	
	}

}

int is_icmp_pkt_valid(struct sr_ip_hdr *ip_hdr, unsigned int len){
	struct sr_icmp_hdr *icmp_hdr;
	icmp_hdr = get_icmp_header(ip_hdr);
	uint16_t icmp_sum_received;
	uint16_t icmp_sum_correct;
	icmp_sum_received = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	icmp_sum_correct = cksum (icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);
	fprintf(stderr, "\tchecksum: %d\n", icmp_sum_correct);
	icmp_hdr->icmp_sum = icmp_sum_received;
	if (len < sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t)) {
		fprintf(stderr, "invaild icmp packet, length is too short\n");
		return 0;
    }
	if(icmp_sum_correct != icmp_sum_received){
		return 0;	
	}
	return 1;
	
}

int is_arp_pkt_valid(unsigned int len){
	if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){
		return 0;	
	}
	return 1;
}



