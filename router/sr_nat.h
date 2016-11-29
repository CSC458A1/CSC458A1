
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define FIN 0x01
#define SYN 0x02 

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum{
  tcp_connected,
  tcp_other,
  tcp_begin
} current_tcp_conn_state;

typedef enum{
	incoming,
	outgoing,
	int_ext_only
} pkt_forwarding_dir;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  time_t last_updated;
  current_tcp_conn_state tcp_state;
  uint32_t ip_ext;
  uint16_t aux_ext;
  uint8_t INT_SYN;
  uint8_t EXT_SYN;
  uint8_t INT_FIN;
  uint8_t EXT_FIN;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_unsolicited_pkts {
	time_t last_updated;
	uint8_t *packet;
	char *incoming_interface;
	unsigned int len;
	uint32_t ip_ext;
	uint16_t aux_ext;
	struct sr_unsolicited_pkts *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  int icmp_timeout;
  int tcp_est_timeout;
  int tcp_trans_timeout;
  uint32_t nat_ext_ip;
  uint32_t last_assigned_aux;
  struct sr_unsolicited_pkts *unsolicited_pkts;
  struct sr_instance *sr;
    

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

int sr_nat_modify_packet(struct sr_instance *sr, uint8_t * packet, unsigned int len, char* interface);

pkt_forwarding_dir sr_nat_get_pkt_dir(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr);
struct sr_if* sr_get_nat_interface_ext(struct sr_instance *sr);
void sr_nat_tcp_connection_update(struct sr_instance *sr, uint8_t * packet, uint32_t ip_ext, uint16_t aux_ext, struct sr_nat_mapping *mapping, pkt_forwarding_dir pkt_dir);

#endif
