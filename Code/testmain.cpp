#include "MAC.h"

int main()
{
  char str[] = "00:1A:A0:AC:DF:57";
  MAC mac(str);
  mac.print_x();
  mac.set_MAC(0x12, 0x96, 0xa2, 0x45, 0x35, 0x11);
  mac.print_x();
  mac.set_MAC(0x0F86A4D2F9E1);
  mac.print_x();
  return 0;
}
