// Tyler Travis A01519795
// Clint Fernelius A01225128
#include "frameio.h"
#include "util.h"
#include "IP.h"
#include "MAC.h"
#include "arp_cache.h"
#include "chksum.cpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <queue>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack
message_queue icmp_queue;// message queue for the ICMP protocol stack
message_queue frame_queue; // message queue for sending IP frames
arp_cache cache;
IP gateway("192.168.1.1");
IP myIP("192.168.1.40");
const octet *mac;


struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

struct ether_header       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
};

struct arp_frame
{
  octet HTYPE[2]; // Hardware Type
  octet PTYPE[2]; // Protocol Type
  octet HLEN;     // Hardware address length
  octet PLEN;     // Protocl address length
  octet OPER[2];  // Operation
  octet SHA[6];   // Sender hardware address
  octet SPA[4];   // Sender protocol address
  octet THA[6];   // Target hardware address
  octet TPA[4];   // Target protocol address
};

struct icmp_frame
{
  octet Type;           // offset 0 - Echo Request = 8; Echo Reply = 0
  octet Code;           // offset 1 - Echo Request = 0; Echo Reply = 0
  octet Checksum[2];    // offset 2
  octet Header_Data[4]; // offset 4 - Data
  octet Data[48];       // offset 8
};

struct ip_header
{
  octet V_IHL;            // offset 0 - 4 bits version, 4 bits IP Header Length
  octet DiffServ;         // offset 1 - probably 0
  octet TL[2];            // offset 2 - Total length
  octet ID[2];            // offset 4 - Everything in the same packet has the same ID
  octet Flags_FragOff[2]; // offset 6 - Flags are first 3 bits, fragment offset is the remaining
  octet TTL;              // offset 8 - Time to live
  octet Protocol;         // offset 9 - The protocol
  octet Checksum[2];      // offset 10 - The checksum
  octet SIPA[4];          // offset 12 - The source IP Address
  octet TIPA[4];          // offset 16 - The target IP Address
};

struct ip_frame
{
  octet V_IHL;            // offset 0 - 4 bits version, 4 bits IP Header Length
  octet DiffServ;         // offset 1 - probably 0
  octet TL[2];            // offset 2 - Total length
  octet ID[2];            // offset 4 - Everything in the same packet has the same ID
  octet Flags_FragOff[2]; // offset 6 - Flags are first 3 bits, fragment offset is the remaining
  octet TTL;              // offset 8 - Time to live
  octet Protocol;         // offset 9 - The protocol
  octet Checksum[2];      // offset 10 - The checksum
  octet SIPA[4];          // offset 12 - The source IP Address
  octet TIPA[4];          // offset 16 - The target IP Address
  octet Data[1500];       // offset 20 - data stuff
};

ip_frame create_IP(icmp_frame*, IP, IP);

//
// This thread sits around and receives frames from the network.
// When it gets one, it dispatches it to the proper protocol stack.
//
void *protocol_loop(void *arg)
{
   ether_frame buf;
   while(1)
   {
      int n = net.recv_frame(&buf,sizeof(buf));
      if ( n < 42 ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             ip_queue.send(PACKET,buf.data,n);
             break;
          case 0x806:
             arp_queue.send(PACKET,buf.data,n);
             break;
      }
   }
   return 0;
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   ip_frame buf;
   event_kind event;
   int timer_no = 1;

   // for fun, fire a timer each time we get a frame
   while ( 1 )
   {
      ip_queue.recv(&event, &buf, sizeof(buf));
      
      ip_frame temp = buf;
      temp.Checksum[0] = 0;
      temp.Checksum[1] = 0;
      int check = chksum((octet *)(&temp), 20, 0);
      
      if (check != (buf.Checksum[0]<<8 | buf.Checksum[1]))
      {
        continue;
      }

      if (event != TIMER && buf.Protocol == 0x1)
      {
        icmp_queue.send(PACKET, buf.Data, sizeof(icmp_frame));
        continue;
      }
      
      
      
      
      /*if ( event != TIMER )
      {
         printf("got an IP frame from %d.%d.%d.%d, queued timer %d\n",
                  buf[12],buf[13],buf[14],buf[15],timer_no);
         ip_queue.timer(10,timer_no);
         timer_no++;
      }                              
      else                            
      {
         printf("timer %d fired\n",*(int *)buf);
      }*/
   }
   return 0;
}

void *icmp_protocol_loop(void *arg)
{
  icmp_frame buf;
  event_kind event;
  unsigned int seq_num = 0;
  const int id_num = 1234;

  while (1)
  {
    icmp_queue.recv(&event, &buf, sizeof(icmp_frame));
    if(event == PACKET || event == ICMP)
    {
      printf("Recieved ICMP Packet!\n");
      if(buf.Type == 0)
      {
        // Echo Reply
      }
      else if(buf.Type == 8)
      {
        // Echo Request
        
        // Set id
        buf.Header_Data[0] = 0xff & (id_num >> 8);
        buf.Header_Data[1] = 0xff & id_num;

        // Set seq
        buf.Header_Data[2] = 0xff & (seq_num >> 8);
        buf.Header_Data[3] = 0xff & seq_num;

        // Set Checksum
        int check = chksum((octet *)(&buf), 8, 0);
        buf.Checksum[0] = 0xff & (check >> 8);
        buf.Checksum[1] = 0xff & check;

        IP TIP;
        memcpy(TIP.getbuf(), buf.Data, 4);

        ip_frame ipFrame = create_IP(&buf, myIP, TIP);

        seq_num++;

        // TODO:
        // Send ip_frame out on the network
      }
    }

  }
}

ip_frame create_IP(icmp_frame* icmpFrame, IP sIP, IP tIP)
{
  ip_frame ret;

  ret.V_IHL = 0x45;

  ret.DiffServ = 0;         // offset 1 - probably 0

  ret.TL[0] = 0;            // offset 2 - Total length
  ret.TL[1] = 0x54;            // offset 2 - Total length

  ret.ID[0];            // offset 4 - Everything in the same packet has the same ID
  ret.ID[1];            // offset 4 - Everything in the same packet has the same ID

  ret.Flags_FragOff[0] = 0x40; // offset 6 - Flags are first 3 bits, fragment offset is the remaining
  ret.Flags_FragOff[1] = 0; // offset 6 - Flags are first 3 bits, fragment offset is the remaining

  ret.TTL = 64;              // offset 8 - Time to live

  ret.Protocol = 1;         // offset 9 - The protocol

  memcpy(ret.SIPA, sIP.getbuf(), sizeof(4));
  memcpy(ret.TIPA, tIP.getbuf(), sizeof(4));

  ret.Checksum[0] = 0;
  ret.Checksum[1] = 0;

  int check = chksum((octet *)(&ret), 8, 0);
  ret.Checksum[0] = 0xff & (check >> 8);
  ret.Checksum[1] = 0xff & check;

  return ret;
}

//
// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   octet buf[150];
   event_kind event;
   arp_frame frame;
   ether_header header;
   
   while ( 1 )
   {
      arp_queue.recv(&event, buf, sizeof(buf));
      
      if(buf[7]==1 && memcmp(buf+8,mac,6) && !memcmp(buf+24,myIP.getbuf(),4)) // If it's a request and it's not from us and it's for us...
      {
        // Request recieved
        // Make reply

        printf("\nARP event!\nRequest received\n");

        frame.HTYPE[0] = 0;
        frame.HTYPE[1] = 1; // HTYPE - Ethernet

        frame.PTYPE[0] = 8;
        frame.PTYPE[1] = 0; // PTYPE - IP

        frame.HLEN = 6;
        
        frame.PLEN = 4;

        frame.OPER[0] = 0;
        frame.OPER[1] = 2;  // OPER - reply

        // SHA - Our MAC address
        memcpy(frame.SHA, mac, sizeof(frame.SHA));

        // SPA - Our IP Address
        memcpy(frame.SPA, buf+24, sizeof(frame.SPA));

        // THA - Their MAC Address
        memcpy(frame.THA, buf+8, sizeof(frame.THA));

        // TPA - Their IP Address
        memcpy(frame.TPA, buf+14, sizeof(frame.TPA));

        memcpy(header.dst_mac, frame.THA, sizeof(frame.THA));
        memcpy(header.src_mac, frame.SHA, sizeof(frame.SHA));
        header.prot[0] = 8;
        header.prot[1] = 6;

        octet send_buf[sizeof(arp_frame) + sizeof(ether_header)];

        memcpy(send_buf, &header, sizeof(ether_header));
        memcpy(send_buf + sizeof(ether_header), &frame, sizeof(arp_frame));

        for(unsigned int i = 0; i < sizeof(send_buf); i+=8)
        {
          printf("%02X %02X %02X %02X %02X %02X %02X %02X\n", send_buf[i],send_buf[i+1],
              send_buf[i+2],send_buf[i+3],send_buf[i+4],send_buf[i+5],send_buf[i+6],send_buf[i+7]);
        }
        printf("\n");

        printf("Sending Reply\n");
        
        net.send_frame(send_buf, sizeof(send_buf));
      }
      else if(memcmp(buf+8,mac,6) && buf[7] == 2 && !memcmp(buf+24,myIP.getbuf(),4))
      {
        // Reply recieved
        // Update cache

        printf("\nARP event!\nReceived Reply\n\n");

        MAC SHA(buf[8], buf[9], buf[10], buf[11], buf[12], buf[13]);
        IP SPA(buf[14],buf[15],buf[16],buf[17]);
        printf("Recieved MAC: ");
        SHA.print_x();
        printf("Recieved IP: ");
        SPA.print_d();
        if(!cache.find_IP_(SPA))
        {
          printf("Not in cache\n");

          if(cache.insert_IP_MAC(SPA,SHA))
          {
            printf("Inserted IP+MAC in cache\n");
          }
        }
        if(cache.find_IP_(SPA))
        {
          printf("\tIP+MAC is in cache\n");
        }
        else
        {
          printf("\tIP+MAC is not in cache\n");
        }
        // TODO:
        // Add ip/mac to icmp message queue
        // 

        event_kind event1;
        icmp_frame icmp;
        
        frame_queue.recv(&event1, &icmp, sizeof(icmp_frame));
        icmp_queue.send(event1, &icmp, sizeof(icmp_frame));

        //memcpy(ipFrame.Data, &icmp, sizeof(icmp_frame));

        //create_IP(&ipFrame, myIP, SPA);

        arp_queue.timer(200, (int)((int*)SHA.getbuf())[0]);
      }

      if(event == TIMER)
      {
        printf("Removing last item\n");
        cache.remove();
      }
   }
   return 0;
}


void *ping(void *args)
{
  IP ip = *(static_cast<IP*>(args));
  octet packet[1500];
  if(cache.find_IP_(ip))
  {
    printf("IP+MAC is in cache\n");
    cache_type::iterator itr = cache.find_IP(ip);
    // TODO:
    // Add ip/mac to icmp message queue
    //
    icmp_frame icmp;
    icmp.Type = 8;  // Echo Request
    icmp.Code = 0;
    icmp.Checksum[0] = 0;
    icmp.Checksum[1] = 0;
    icmp.Header_Data[0] = 0;
    icmp.Header_Data[1] = 0;
    icmp.Header_Data[2] = 0;
    icmp.Header_Data[3] = 0;

    
    icmp_queue.send(ICMP, &icmp, sizeof(icmp_frame));

  }
  else
  {
    printf("Not in cache, sending broadcast.\n");

    arp_frame frame;
    ether_header eth;
    
    frame.HTYPE[0] = 0;
    frame.HTYPE[1] = 1; // HTYPE - Ethernet

    frame.PTYPE[0] = 8;
    frame.PTYPE[1] = 0; // PTYPE - IP

    frame.HLEN = 6;
    
    frame.PLEN = 4;

    frame.OPER[0] = 0;
    frame.OPER[1] = 1;  // OPER - request

    memcpy(frame.SHA,mac,sizeof(frame.SHA));

    memcpy(frame.SPA,myIP.getbuf(),sizeof(frame.SPA));

    octet temp[] = {0,0,0,0,0,0};
    memcpy(frame.THA,temp,sizeof(temp));

    memcpy(frame.TPA,ip.getbuf(),sizeof(frame.TPA));

    for(int i = 0; i < 6; ++i) temp[i] = 0xff;

    memcpy(eth.dst_mac,temp,sizeof(eth.dst_mac));
    memcpy(eth.src_mac,mac,sizeof(eth.src_mac));
    eth.prot[0] = 8;
    eth.prot[1] = 6;
    
    octet send_buf[sizeof(frame) + sizeof(ether_header)];

    memcpy(send_buf, &eth, sizeof(ether_header));
    memcpy(send_buf + sizeof(ether_header), &frame, sizeof(arp_frame));

    printf("Broadcast sent\n");

    net.send_frame(send_buf, sizeof(send_buf));

    //TODO:
    //QUEUE FRAME AND THEN IN THE RECEIVE REPLY SECTION, SEND ALL QUEUED FRAMES WITH THE MAC ADDRESS

    icmp_frame icmp;
    icmp.Type = 8;  // Echo Request
    icmp.Code = 0;
    icmp.Checksum[0] = 0;
    icmp.Checksum[1] = 0;
    icmp.Header_Data[0] = 0;
    icmp.Header_Data[1] = 0;
    icmp.Header_Data[2] = 0;
    icmp.Header_Data[3] = 0;

    memcpy(icmp.Data, ip.getbuf(), sizeof(6));    // Only way to get TIP up the stack... we think....

    frame_queue.send(ICMP,&icmp,sizeof(icmp_frame));
  }

  return 0;
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread, ping_thread, icmp_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main(int argc, char** argv)
{  
  char input[18];
  mac = net.get_mac();
  net.open_net("enp3s0");

  pthread_create(&loop_thread,NULL,protocol_loop,NULL);
  pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
  pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
  pthread_create(&icmp_thread,NULL,icmp_protocol_loop,NULL);

  for ( ; ; )
  {
    printf("\nEnter IP address to ping(d.d.d.d): \n");
    scanf("%s", input);
    printf("%s\n",input);
    IP ip(input);
    pthread_create(&ping_thread,NULL,ping,&ip);
    sleep(1);
  }
}

