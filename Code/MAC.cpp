#include "MAC.h"
#include <cstdio>

MAC::MAC()
{
  a_mac[0] = 0;
  a_mac[1] = 0;
  a_mac[2] = 0;
  a_mac[3] = 0;
  a_mac[4] = 0;
  a_mac[5] = 0;
}

MAC::MAC(unsigned long long int a)
{
  a_mac[5] = a & 0xff; 
  a_mac[4] = (a & ((unsigned long long int)0x000000ff << 8)) >> 8; 
  a_mac[3] = (a & ((unsigned long long int)0x000000ff << 16)) >> 16; 
  a_mac[2] = (a & ((unsigned long long int)0x000000ff << 24)) >> 24;
  a_mac[1] = (a & ((unsigned long long int)0x000000ff << 32)) >> 32;
  a_mac[0] = (a & ((unsigned long long int)0x000000ff << 40)) >> 40;
}

MAC::MAC(unsigned char a, unsigned char b, unsigned char c,
    unsigned char d, unsigned char e, unsigned char f)
{
  a_mac[0] = a;
  a_mac[1] = b;
  a_mac[2] = c;
  a_mac[3] = d;
  a_mac[4] = e;
  a_mac[5] = f;
}

MAC::MAC(char* addr)
{
  sscanf(addr,"%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", &a_mac[0], &a_mac[1], &a_mac[2],
      &a_mac[3], &a_mac[4], &a_mac[5]);
}

void * MAC::getbuf()
{
  return a_mac;
}

void MAC::print_x()
{
  printf("%02X:%02X:%02X:%02X:%02X:%02X\n", a_mac[0], a_mac[1], a_mac[2], a_mac[3]
      , a_mac[4], a_mac[5]);
}

void MAC::set_MAC(unsigned long long int a)
{
  a_mac[5] = a & 0xff; 
  a_mac[4] = (a & ((unsigned long long int)0x000000ff << 8)) >> 8; 
  a_mac[3] = (a & ((unsigned long long int)0x000000ff << 16)) >> 16; 
  a_mac[2] = (a & ((unsigned long long int)0x000000ff << 24)) >> 24; 
  a_mac[1] = (a & ((unsigned long long int)0x000000ff << 32)) >> 32;
  a_mac[0] = (a & ((unsigned long long int)0x000000ff << 40)) >> 40;
}

void MAC::set_MAC(unsigned char a, unsigned char b, unsigned char c,
    unsigned char d, unsigned char e, unsigned char f)
{
  a_mac[0] = a;
  a_mac[1] = b;
  a_mac[2] = c;
  a_mac[3] = d;
  a_mac[4] = e;
  a_mac[5] = f;
}

void MAC::set_MAC(char* addr)
{
  sscanf(addr,"%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", &a_mac[0], &a_mac[1], &a_mac[2],
      &a_mac[3], &a_mac[4], &a_mac[5]);
}
