#include "arp_cache.h"
#include <stdio.h>

arp_cache::arp_cache()
{

}

bool arp_cache::insert_IP_MAC(IP _ip, MAC _mac)
{
  cache.push_front(std::make_pair(_ip, _mac));
  return true;
}

void arp_cache::remove_IP_MAC(IP _ip)
{
  cache.erase(find_IP(_ip));
}

cache_type::iterator arp_cache::find_IP(IP _ip)
{
  cache_type::iterator itr;
  for(itr = cache.begin(); itr != cache.end(); ++itr)
  {
    if(!memcmp(&(itr->first), &_ip, sizeof(_ip)))
    {
      return itr;
    }
  }
  return cache_type::iterator(0);
}

MAC arp_cache::get_MAC(IP _ip)
{
  cache_type::iterator itr = find_IP(_ip);
  if(itr == cache_type::iterator(0))
  {
    return MAC("00:00:00:00:00");
  }
  return itr->second;
}

bool arp_cache::find_MAC(MAC _mac)
{
  for(cache_type::iterator itr = cache.begin(); itr != cache.end(); ++itr)
  {
    if(!memcmp(&(itr->second), &_mac, sizeof(_mac)))
    {
      return true;
    }
  }
  return false;
}

bool arp_cache::find_IP_b(IP _ip)
{
  cache_type::iterator itr;
  for(itr = cache.begin(); itr != cache.end(); ++itr)
  {
    if(!memcmp(&(itr->first), &_ip, sizeof(_ip)))
    {
      return true;
    }
  }
  return false;
}

void arp_cache::remove()
{
  cache.pop_back();
}
