
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

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

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
    while(nat->mappings != NULL) {
        sr_nat_mapping_t* temp = nat->mappings->next;
        while (natMappings->conns != NULL) {
            sr_nat_connection_t * temp_conn = nat->mappings->conns->next;
            free(nat->mapping->conns);
            nat->mappings = temp_conn;
        }
        free(nat->mappings);
        nat->mappings = temp;
    }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
      
    /* handle periodic tasks here */
      sr_nat_mapping_t* mapping_iterator = nat->mappings;
      sr_nat_mapping_t* previous_mapping = NULL;
      while (mapping_iterator != NULL) {
          if (mapping_iterator->type == nat_mapping_tcp) {
              sr_nat_connection_t* connection_iterator = mapping_iterator->conns;
              sr_nat_connection_t* prev_connection = NULL;
              while(connection_iterator != NULL) {
                  if (connection_iterator->connection_state == tcp_connected) &&(difftime(curtime, connection_iterator->last_updated > nat->tcpEstabilishedIdleTimeout)) {
                      sr_nat_connection_t* temp = connection_iterator->next;
                      if (prev_connection == NULL) {
                          mapping_iterator->conns = temp;
                          free(connection_iterator);
                          connection_iterator = temp;
                      } else {
                          previous_connection->next = temp;
                          free(connection_iterator);
                          connection_iterator = temp;
                      }
                  } else if (((connection_iterator->connection_state == tcp_outbound_syn) || (connection_iterator->connection_state == tcp_wait) || (connection_iterator->connectionState == tcp_inbound_syn)) && difftime(curtime, connection_iterator->last_udpated) > nat->tcp_transitory_idle_timeout)  {
                      if (prev_connection == NULL) {
                          mapping_iterator->conns = temp;
                          free(connection_iterator);
                          connection_iterator = temp;
                      } else {
                          previous_connection->next = temp;
                          free(connection_iterator);
                          connection_iterator = temp;
                      }
                  } else {
                      previous_connection = connection_iterator;
                      connection_iterator = connection_iterator->next;
                  }
              }
              if (mapping_iterator->conns == NULL && difftime(curtime, mapping_iterator->last_updated) > 10) {
                  sr_nat_mapping_t* temp_mapping = mapping_iterator->next;
                    if (prev_mapping == NULL) {
                        nat->mappings = temp_mapping;
                        while (mapping_iterator->conns != NULL) {
                            sr_nat_connection_t * temp_conn = mapping_iterator->conns->next;
                            free(mapping_iterator->conns);
                            mapping_iterator = temp_conn;
                        }
                        free(mapping_iterator);
                        mapping_iterator = temp_mapping;
                    } else {
                        previous_mapping->next = temp_mapping;
                        free(mapping_iterator);
                        mapping_iterator = temp_mapping;
                    }
              } else {
                  previous_mapping = mapping_iterator;
                  mapping_iterator = mapping_iterator->next;
              }
          } else {
              if (difftime(curtime, mapping_iterator->last_updated) > nat->icmp_query_timeout) {
                  if (prev_mapping == NULL) {
                        nat->mappings = temp_mapping;
                        free(mapping_iterator);
                        mapping_iterator = temp_mapping;
                    } else {
                        previous_mapping->next = temp_mapping;
                        free(mapping_iterator);
                        mapping_iterator = temp_mapping;
                    }
              } else {
                  previous_mapping = mapping_iterator;
                  mapping_iterator = mapping_iterator->next;
              }
          }
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
    
    struct sr_nat_mapping *result = sr_nat_get_external(nat, aux_ent, type);
    
    if (result != NULL) {
        copy = malloc(sizeof(sr_nat_mapping_t));
        memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
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
    
    struct sr_nat_mapping *result = sr_nat_get_internal(nat, ip_int, aux_int, type);
    
    if (result != NULL) {
        copy = malloc(sizeof(sr_nat_mapping_t));
        memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
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
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

struct sr_nat_connection *sr_nat_get_connection(struct sr_nat_mapping *nat_mapping, uint32_t ip, uint16_t port) {
    struct sr_nat_connection* connection = NULL;
    connection = nat_map->conns;
    while (connection != NULL) {
      if ((connection->ip == ip) && (connection->port == port)) {
        return connection;
      }
      connection = connection->next;
  }
    return connection;
}

struct sr_nat_mapping *sr_nat_get_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {
    struct sr_nat_mapping *iterator = NULL;
    iterator = nat->mappings;
    while (iterator != NULL) {
        if ((iterator->type == type) && (iterator->aux_int == aux_int) && (iterator->ip_int == ip_int)) {
            return iterator;
        }
        iterator = iterator->next;
  }
    return iterator;
}

struct sr_nat_mapping *sr_nat_get_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
    struct sr_nat_mapping *iterator = NULL;
    iterator = nat->mappings;
    while (iterator != NULL) {
        if ((iterator->type == type) && (iterator->aux_ext == aux_ext)) {
        return iterator;
      }
        iterator = iterator->next;
  }
    return iterator;
}

uint16_t sr_nat_get_next_port() {
    uint16_t result = nat->current_port;
    if (nat->current_port == PORT_RANGE_END) {
        nat->current_port = PORT_RANGE_START;
    } else {
        nat->current_port++;
    }
    return result;
}