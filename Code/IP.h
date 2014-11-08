#ifndef IP_H
#define IP_H

class IP
{
  private:
    unsigned char a_ip[4];
  public:
    IP();
    IP(unsigned int);
    IP(unsigned char, unsigned char, unsigned char, unsigned char);
    IP(char*);
    void * getbuf();
    void print_x();
    void print_d();
    void set_IP(unsigned int);
    void set_IP(unsigned char, unsigned char, unsigned char, unsigned char);
    void set_IP(char*);
    unsigned int getint();
};

#endif
