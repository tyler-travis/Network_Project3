#ifndef MAC_H
#define MAC_H

class MAC
{
  private:
    unsigned char a_mac[6];
  public:
    MAC();
    MAC(unsigned long long int);
    MAC(unsigned char, unsigned char, unsigned char,
        unsigned char, unsigned char, unsigned char);
    MAC(char*);
    void * getbuf();
    void print_x();
    void set_MAC(unsigned long long int);
    void set_MAC(unsigned char, unsigned char, unsigned char, 
        unsigned char, unsigned char, unsigned char);
    void set_MAC(char*);
};

#endif
