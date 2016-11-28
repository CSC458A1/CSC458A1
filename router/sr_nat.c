
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sr_router.h"
#include "sr_nat.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->last_assigned_aux = 1023;

  

  return success;
}




int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));
	printf("gone\n");
	/* free nat memory here */
	struct sr_nat_mapping *current_entry = nat->mappings;
	struct sr_nat_mapping *destory_entry;
	while(current_entry){
		struct sr_nat_mapping *req, *prev = NULL, *next = NULL; 
        for (req = nat->mappings; req != NULL; req = req->next) {
        	if(req == current_entry){
        		if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    nat->mappings = next;
                }  
                break;
            }
            prev = req;
        }
        
        struct sr_nat_connection *connection, *nxt;
        
        for (connection = current_entry->conns; connection; connection = nxt) {
            nxt = connection->next;
            free(connection);
        }
        destory_entry = current_entry;
        current_entry =  current_entry->next;
        free(destory_entry);
	}
  
	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) &&
    	pthread_mutexattr_destroy(&(nat->attr));

}

void sr_nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *mapping){
	printf("gone\n");

	struct sr_nat_mapping *req, *prev = NULL, *next = NULL; 
	for (req = nat->mappings; req != NULL; req = req->next) {
		if(req == mapping){
			if (prev) {
				next = req->next;
                prev->next = next;
			} 
			else {
				next = req->next;
				nat->mappings = next;
			}  
			break;
		}
		prev = req;
	}
        
	struct sr_nat_connection *connection, *nxt;
        
	for (connection = mapping->conns; connection; connection = nxt) {
		nxt = connection->next;
		free(connection);
	}

	free(mapping);
		
}

void sr_nat_mapping_con_destroy(struct sr_nat_mapping* mapping, struct sr_nat_connection* connection){
	struct sr_nat_connection *req, *prev = NULL, *next = NULL; 
	for (req = mapping->conns; req != NULL; req = req->next) {
		if(req == connection){
			if (prev) {
				next = req->next;
                prev->next = next;
			} 
			else {
				next = req->next;
				mapping->conns = next;
			}  
			break;
		}
		prev = req;
	}
	free(connection);
}


void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  printf("timeout\n");
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *current_entry = nat->mappings;
    struct sr_nat_mapping *entry_holder;
    int time_diff;
    while(current_entry){
    	
    	if(current_entry->type == nat_mapping_icmp){
    		time_diff = curtime - current_entry->last_updated;
    		entry_holder = current_entry;
    		current_entry = current_entry->next;
    		if(time_diff > nat->icmp_timeout){
    			sr_nat_mapping_destroy(nat, entry_holder);
    		}
    		
    	}else if(current_entry->type == nat_mapping_tcp){
    	
    		struct sr_nat_connection* current_connection = current_entry->conns;
    		struct sr_nat_connection* connection_holder; 
    		while(current_connection){
    			time_diff = curtime - current_connection->last_updated;
    			if(current_connection->tcp_state == tcp_connected){
    				if(time_diff > nat->tcp_est_timeout){
    					connection_holder = current_connection;
    					current_connection = current_connection->next;
    					sr_nat_mapping_con_destroy(current_entry, connection_holder);
    				}
    			}
    		}
    		
    	}
    	current_entry = current_entry->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = NULL;
  
	struct sr_nat_mapping *current_entry = nat->mappings;
	while(current_entry){
		printf("current_entry port ext %x\n", current_entry->aux_ext);
		if(current_entry->type == type && current_entry->aux_ext == aux_ext){
			printf("find ext mapping\n");
			copy = malloc(sizeof(struct sr_nat_mapping));
			copy->type = type;
			copy->ip_int = current_entry->ip_int;
			copy->ip_ext = current_entry->ip_ext;
			copy->aux_int = current_entry->aux_int;
			copy->aux_ext = current_entry->aux_ext;
			copy->last_updated = current_entry->last_updated;
			copy->conns = current_entry->conns;
			copy->next = current_entry->next;
			break;
		}
		current_entry = current_entry->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *current_entry = nat->mappings;
	while(current_entry){
		printf("current_entry port %x\n", current_entry->aux_int);
		if(current_entry->type == type && current_entry->aux_int == aux_int && 
		current_entry->ip_int == ip_int){
			copy = malloc(sizeof(struct sr_nat_mapping));
			copy->type = type;
			copy->ip_int = current_entry->ip_int;
			copy->ip_ext = current_entry->ip_ext;
			copy->aux_int = current_entry->aux_int;
			copy->aux_ext = current_entry->aux_ext;
			copy->last_updated = current_entry->last_updated;
			copy->conns = current_entry->conns;
			copy->next = current_entry->next;
			break;
		}
		current_entry = current_entry->next;
	}

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
	struct sr_if *ext_if = sr_get_nat_interface_ext(nat->sr);
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = ext_if->ip;
	mapping->aux_int = aux_int;
	mapping->aux_ext = htons(nat->last_assigned_aux + 1);
	printf("generated aux %x\n", mapping->aux_ext);
	mapping->last_updated = time(NULL);
	mapping->conns = NULL;
	mapping->next = nat->mappings;
	nat->mappings = mapping;
	
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
	memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

struct sr_if* sr_get_nat_interface_ext(struct sr_instance *sr){

	return sr_get_interface(sr, "eth2");
}

struct sr_if* sr_get_nat_interface_int(struct sr_instance *sr){
	return sr_get_interface(sr, "eth1");
}

struct sr_nat_mapping *sr_nat_packet_mapping_lookup(struct sr_instance *sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        int is_incoming_pkt){
	struct sr_ip_hdr *ip_hdr = get_ip_header(packet);
	struct sr_nat_mapping *mapping;
	uint16_t port_number = 0;
	sr_nat_mapping_type type;
	if(ip_hdr->ip_p == ip_protocol_icmp){
		struct sr_icmp_hdr *icmp_hdr;
		icmp_hdr = get_icmp_header(ip_hdr);
		type = nat_mapping_icmp;
		port_number = icmp_hdr->icmp_id;
	}
	
	if(is_incoming_pkt){
		printf("incoming port %x\n", port_number);
		mapping = sr_nat_lookup_external(sr->nat, port_number, type);
		if(mapping == NULL){
		
		}
	}
	
	if(!is_incoming_pkt){
		mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, port_number, type);
		if(mapping == NULL){
			mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, port_number, type);
		}
	}
	
	return mapping;
	
}

int sr_nat_modify_packet(struct sr_instance *sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	struct sr_ip_hdr *ip_hdr = get_ip_header(packet);
	print_addr_ip_int(ntohl(ip_hdr->ip_src));
	printf("before incoming finding end\n");
	int incoming_pkt = sr_nat_is_incoming_pkt(sr, ip_hdr);
	printf("incoming finding end\n");
	struct sr_nat_mapping *mapping = sr_nat_packet_mapping_lookup(sr, packet, len, interface, incoming_pkt);
	printf("mapping finding end\n");
	if(mapping == NULL){
		printf("no mapping found\n");
		if(ip_hdr->ip_p == ip_protocol_icmp){
			return 0;
		}
		return 1;
	}
	
	if(ip_hdr->ip_p == ip_protocol_icmp){
		struct sr_icmp_hdr *icmp_hdr;
		icmp_hdr = get_icmp_header(ip_hdr);
		printf("before incoming/outgoing\n");
		if(incoming_pkt){
			printf("incoming\n");
			print_addr_ip_int(ntohl(mapping->ip_int));
			ip_hdr->ip_dst = mapping->ip_int;
			icmp_hdr->icmp_id = mapping->aux_int;		
		}else{
			printf("outgoing\n");
			printf("port %x\n", mapping->aux_ext);
			ip_hdr->ip_src = mapping->ip_ext;
			icmp_hdr->icmp_id = mapping->aux_ext;
		}
		
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);
	}
	
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
	
	free(mapping);
	return 0;

}

int sr_nat_is_incoming_pkt(struct sr_instance *sr,
        struct sr_ip_hdr *ip_hdr){
    int is_src_int = 0;
	int is_dst_int = 0;
	struct sr_rt *routing_src = sr_rtable_lookup(sr, ip_hdr->ip_src);
	if(!routing_src){
		is_src_int = -1;
	}else{
		if(strncmp(routing_src->interface, "eth1", 4) == 0){
			is_src_int = 1;
		}
	}
	struct sr_rt *routing_dst = sr_rtable_lookup(sr, ip_hdr->ip_dst);
	if(!routing_dst){
		is_dst_int = -1;
	}else{
		if(strncmp(routing_dst->interface, "eth1", 4) == 0){
			is_dst_int = 1;
		}
	}

	
	struct sr_if *ext_if = sr_get_nat_interface_ext(sr);
	if(!is_src_int && ext_if->ip == ip_hdr->ip_dst){
		printf("this is the icmp reply\n");
		return 1;
	}
	if(is_src_int && ext_if->ip != ip_hdr->ip_dst){
		return 0;
	}
	
	return 0;
}


