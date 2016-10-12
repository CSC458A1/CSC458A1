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
    
    struct sr_ethertype_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    struct sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)packet;
    struct sr_ip_hdr_t *ip_hdr = (sr_arp_hdr_t *)packet;
    
    if (ethertype(packet) == ethertype_ip) {
        print_hdr_ip(packet);
        struct sr_arpentry *entry = sr_arpcache_lookup(sr->cache, entry->ip);
        if (entry == NULL) {
            printf("ip not in cache, sending arp requests\n");
            sr_arpcache_queuereq(sr->cache, entry->ip, packet, len, interface);
        } else {
            printf("ip in cache, forwarding packet\n");
            sr_send_packet(sr, packet, len, entry.mac);
        }
    } else if (ethertype(packet) == ethertype_arp) {
        print_hdr_arp(packet);
        //Look in arp table
        struct sr_arpentry *entry = sr_arpcache_lookup(sr->cache, arp_hdr->ar_tip);
        if (entry == NULL) {
            printf("ip not in cache, sending arp requests\n");
            //send arp request to all clients
            sr_arpcache_queuereq(sr->cache, entry->ip, packet, len, interface);
        } else {
            printf("ip in cache, sending result back to origin\n");
            //forward packet back to origin
            sr_send_packet(sr, packet, len, arp_hdr->ar_sha);
        }
    }

}/* end sr_ForwardPacket */