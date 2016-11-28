
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>

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
  nat->last_assigned_aux = 1024;
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

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
		if(current_entry->type == type && current_entry->aux_ext == aux_ext){
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
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = nat->nat_ext_ip;
	mapping->aux_int = aux_int;
	mapping->aux_ext = nat->last_assigned_aux + 1;
	mapping->last_updated = time(NULL);
	mapping->conns = NULL;
	mapping->next = nat->mappings;
	nat->mappings = mapping;

	pthread_mutex_unlock(&(nat->lock));
	return mapping;
}
