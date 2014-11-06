#include "IP.h"
#include <cstdio>

IP::IP()
{
  a_ip[0] = 0;
  a_ip[1] = 0;
  a_ip[2] = 0;
  a_ip[3] = 0;
}

IP::IP(unsigned int a)
{
  a_ip[3] = a & 0xff; 
  a_ip[2] = (a & (0x000000ff << 8)) >> 8; 
  a_ip[1] = (a & (0x000000ff << 16)) >> 16; 
  a_ip[0] = (a & (0x000000ff << 24)) >> 24;
}

IP::IP(unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
  a_ip[0] = a;
  a_ip[1] = b;
  a_ip[2] = c;
  a_ip[3] = d;
}

IP::IP(char* addr)
{
  sscanf(addr,"%hhu.%hhu.%hhu.%hhu", &a_ip[0], &a_ip[1], &a_ip[2], &a_ip[3]);
}

void * IP::getbuf()
{
  return a_ip;
}

void IP::print_x()
{
  printf("0x%02x%02x%02x%02x\n", a_ip[0], a_ip[1], a_ip[2], a_ip[3]);
}

void IP::print_d()
{
  printf("%d.%d.%d.%d\n", a_ip[0], a_ip[1], a_ip[2], a_ip[3]);
}

void IP::set_IP(unsigned int a)
{
  a_ip[3] = a & 0xff; 
  a_ip[2] = a & (0x000000ff << 8) >> 8; 
  a_ip[1] = a & (0x000000ff << 16) >> 16; 
  a_ip[0] = a & (0x000000ff << 24) >> 24; 
}

void IP::set_IP(unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
  a_ip[0] = a;
  a_ip[1] = b;
  a_ip[2] = c;
  a_ip[3] = d;
}

void IP::set_IP(char* addr)
{
  sscanf(addr,"%hhu.%hhu.%hhu.%hhu", &a_ip[0], &a_ip[1], &a_ip[2], &a_ip[3]);
}
  

