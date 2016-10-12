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
struct sr_ip_hdr *get_ip_header(uint8_t *buf){
	return (struct sr_ip_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
}


struct sr_icmp_hdr *get_icmp_header(struct sr_ip_hdr *ip_hdr){
	return (struct sr_icmp_hdr *)((uint8_t *)ip_hdr + ip_hdr->ip_hl * 4);
}
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
  
  print_hdr_eth(packet);
  
  /* if(ethertype(packet) != ethertype_arp){

	sr_ip_hdr_t *iphr = get_ip_header(packet);
 

	printf("s\n");
	process_ip_pkt(sr, packet, len, interface);	

  } */

    printf("*** -> Received packet of length %d \n",len);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_arp_hdr_t *)(packet);
    
    if (ethertype(packet) == ethertype_ip) {
        print_hdr_ip(packet);
        sr_arpentry_t *entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
        if (entry == NULL) {
            printf("ip not in cache, sending arp requests\n");
            sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, interface);
        } else {
            printf("ip in cache, forwarding packet\n");
            sr_send_packet(sr, packet, len, entry->mac);
        }
    } else if (ethertype(packet) == ethertype_arp) {
        print_hdr_arp(packet);
        /* Look in arp table */
        sr_arpentry_t *entry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_tip);
        if (entry == NULL) {
            printf("ip not in cache, sending arp requests\n");
            /* send arp request to all clients */
            sr_arpcache_queuereq(&(sr->cache), arp_hdr->ar_sip, packet, len, interface);
        } else {
            printf("ip in cache, sending result back to origin\n");
            /* forward packet back to origin */
            /* sr_send_packet(sr, packet, len, arp_hdr->ar_sha); */
        }
    }
}/* end sr_ForwardPacket */

void process_ip_pkt(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	enum sr_ip_protocol ip_ser = ip_protocol_icmp;
	struct sr_if* if_walker = 0;
	
	struct sr_ip_hdr *ip_hdr;
	ip_hdr = get_ip_header(packet);
	printf("a\n");
	if(sr_contains_interface(sr, ip_hdr->ip_dst)){
		if(ip_hdr->ip_p == ip_protocol_icmp){
			printf("icmp\n");
			process_icmp_packet(sr, ip_hdr);		
		}else{
			/*port unreachable?;*/
		}	
	}

}

void sr_send_icmp_pkt(struct sr_instance* sr, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code){
	struct sr_ip_hdr *original_ip_hdr;
	uint32_t new_dst;
	uint32_t new_src;
	struct sr_icmp_hdr *icmp_hdr;
	struct sr_if *sr_interface;
	uint8_t *new_pkt;
	struct sr_rt *routing_table;
	uint16_t new_pkt_len;
	
	if(icmp_type == ICMP_ECHO_REPLY_CODE){
		original_ip_hdr = (struct sr_ip_hdr_t *)packet;

		icmp_hdr = get_icmp_header(original_ip_hdr);
		icmp_hdr->icmp_type = icmp_type;
		icmp_hdr->icmp_code = icmp_code;
		icmp_hdr->icmp_sum = 0;

		new_dst = original_ip_hdr->ip_src;
		new_src = original_ip_hdr->ip_dst;
		original_ip_hdr->ip_dst = new_dst;
		original_ip_hdr->ip_src = new_src;	
		printf("modified packet ======================\n");
		print_hdr_ip(original_ip_hdr);
		new_pkt_len = ntohs(original_ip_hdr);
		new_pkt = malloc(new_pkt_len);
		memcpy(new_pkt, original_ip_hdr, new_pkt_len);
		icmp_hdr = get_icmp_header((struct sr_ip_hdr_t *)new_pkt);
		icmp_hdr->icmp_sum = cksum(icmp_hdr, new_pkt_len - ICMP_IP_HDR_LEN);
	}
}

void process_icmp_packet(struct sr_instance* sr, struct sr_ip_hdr_t *ip_hdr)
{
	struct sr_icmp_hdr *icmp_hdr;
	printf("ha\n");
	
	icmp_hdr = get_icmp_header(ip_hdr);
	print_hdr_icmp(icmp_hdr);
	if(!is_icmp_pkt_valid(ip_hdr)){
		printf("herea\n");
		return;	
	}
	printf("here\n");
	sr_send_icmp_pkt(sr, ip_hdr, ICMP_ECHO_REPLY_CODE, 0);
}

int is_icmp_pkt_valid(struct sr_ip_hdr *ip_hdr){
	struct sr_icmp_hdr *icmp_hdr;
	icmp_hdr = get_icmp_header(ip_hdr);
	uint16_t icmp_sum_received;
	uint16_t icmp_sum_correct;
	icmp_sum_received = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	icmp_sum_correct = cksum (icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);
	fprintf(stderr, "\tchecksum: %d\n", icmp_sum_correct);
	if(icmp_sum_correct != icmp_sum_received){
		return 0;	
	}
	
	if(icmp_hdr->icmp_type != ICMP_ECHO_REQUEST_CODE || icmp_hdr->icmp_code !=
		ICMP_ECHO_REPLY_CODE){
		return 0;
	}
	return 1;

	
}
