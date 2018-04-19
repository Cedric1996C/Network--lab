#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

int main(int argc, char *argv[])
{
      int sock_fd;
      //   int proto;
      int n_read;
      char buffer[BUFFER_MAX];
      char *eth_head;
      char *head;
      char *ip_head;
      char *arp_head;
      char *rarp_head;
      //char *tcp_head;
      //char *udp_head;
      //char *icmp_head;
      unsigned char *p;
      //if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0)
      //more protocol type
      if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
      {
            printf("error create raw socket\n");
            return -1;
      }
      while (1)
      {
            n_read = recvfrom(sock_fd, buffer, 2048, 0, NULL, NULL);
            if (n_read < 42)
            {
                  printf("error when recv msg \n");
                  return -1;
            }
            printf("*****************************************\n");
            printf("Ethernet II:\n");
            //Mac address
            eth_head = buffer;
            p = eth_head;
            printf("   MAC address:\n");
            printf("      Destination: %.2x:%02x:%02x:%02x:%02x:%02x\n      Source: %.2x:%02x:%02x:%02x:%02x:%02x\n", p[6], p[7], p[8], p[9], p[10], p[11], p[0], p[1], p[2], p[3], p[4], p[5]);
            //Type
            head = eth_head + 12;
            unsigned short type = *(unsigned short *)head;
            switch (type)
            {
            case 0x0008:
                  printf("   Type: IP (0x0800)\n");
                  break;
            case 0x0608:
                  printf("   Type: ARP (0x0806)\n");
                  break;
            case 0x3580:
                  printf("   Type: RARP (0x8035)\n");
                  break;
            default:
                  printf("   Unknown type\n");
            }

            //More detailed information
            if (type == 0x0008) //IP
            {
                  ip_head = eth_head + 14;
                  printf("Internet Protocol:\n");
                  unsigned char v = (ip_head[0] >> 4) & 0xf;
                  unsigned char hl = ip_head[0] & 0xf;
                  printf("   Version: %d\n   Header Length: %d bytes\n", v, hl * 4);
                  unsigned char tos = ip_head[1];
                  printf("   Type of Service: 0x%02x\n", tos);
                  unsigned short tl = (ip_head[2] << 8) + ip_head[3];
                  printf("   Total Length: %d\n", tl);
                  unsigned short iden = (ip_head[4] << 8) + ip_head[5];
                  printf("   Identification: 0x%04x (%d)\n", iden, iden);
                  unsigned char flags = (ip_head[6] >> 5) & 0x7;
                  unsigned short fo = ((ip_head[6] & 0x1f) << 8) + ip_head[7];
                  printf("   Flags: 0x%02x\n   Fragment offset: %d\n", flags, fo);
                  unsigned char ttl = ip_head[8];
                  printf("   Time to live: %d\n", ttl);
                  unsigned char proto = ip_head[9];
                  printf("   Protocol: ");
                  switch (proto)
                  {
                  case IPPROTO_ICMP:
                        printf("icmp\n");
                        break;
                  case IPPROTO_IGMP:
                        printf("igmp\n");
                        break;
                  case IPPROTO_IPIP:
                        printf("ipip\n");
                        break;
                  case IPPROTO_TCP:
                        printf("tcp\n");
                        break;
                  case IPPROTO_UDP:
                        printf("udp\n");
                        break;
                  default:
                        printf("Pls query yourself\n");
                  }
                  unsigned short hcs = (ip_head[10] << 8) + ip_head[11];
                  printf("   Header Checksum: 0x%04x\n", hcs);
                  p = ip_head + 12;
                  printf("   IP address:\n");
                  printf("      Source: %d.%d.%d.%d\n      Destination: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
                  p = ip_head + 20 + 8;
                  printf("Inserted data:%s\n", p);
            }

            else //ARP or RARP
            {
                  printf("Address Resolution Protocol:\n");
                  arp_head = rarp_head = eth_head + 14;
                  //since their formats are the same,it's reasonable to use arp_head.
                  unsigned short ht = (arp_head[0] << 8) + arp_head[1];
                  if (ht == 1)
                        printf("   Hardware type: Ethernet (%d)\n", ht);
                  unsigned short pt = (arp_head[2] << 8) + arp_head[3];
                  if (pt == 0x0800)
                        printf("   Protocol type: IP (0x0800)\n");
                  unsigned char hs = arp_head[4];
                  printf("   Hardware size: %d\n", hs);
                  unsigned char ps = arp_head[5];
                  printf("   Protocol size: %d\n", ps);
                  unsigned short opcode_type = (arp_head[6] << 8) + arp_head[7];
                  if (opcode_type == 1 || opcode_type == 3)
                        printf("   Opcode: request (%d)\n", opcode_type);
                  else
                  {
                        printf("   Opcode: reply (%d)\n", opcode_type);
                        //return -1;
                  }
                  p = arp_head + 14;
                  printf("   Sender Ip address: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
                  p += 10;
                  printf("   Target IP address: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
                  //if(opcode_type==2||opcode_type==4) return -1;
            }
      }
      return -1;
}
