#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include "IP.h"
#include "MAC.h"
#include <list>
#include <utility>
#include <cstddef>
#include <string.h>

typedef std::list<std::pair<IP, MAC>> cache_type;

class arp_cache
{
  private:
    cache_type cache;
  public:
    arp_cache();
    bool insert_IP_MAC(IP, MAC);
    void remove_IP_MAC(IP);
    cache_type::iterator find_IP(IP);
    bool find_IP_(IP);
    bool find_MAC(MAC);
    MAC get_MAC(IP);
    void remove();
};

#endif
