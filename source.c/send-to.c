#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>
#include<sys/time.h>

//icmp packet length
#define ICMP_PACKET_LEN sizeof(struct icmp)

void err_exit(const char *err_msg)
{
  perror(err_msg);
  exit(1);
}

//checksum
unsigned short check_sum(unsigned short *addr,int len)
{
  int nleft=len;
  int sum=0;
  unsigned short *w=addr;
  unsigned short answer=0;

  while(nleft>1)
  {
    sum+=*w++;
    nleft-=2;
  }
  if(nleft==1)
  {
    *(unsigned char *)(&answer)=*(unsigned char *)w;
    sum+=answer;
  }
  sum=(sum>>16)+(sum&0xffff);
  sum+=(sum>>16);
  answer=~sum;

  return answer;
}

//my memset
#define DATA_MAX_SIZE 20
void my_memset(char *dest,const char *src,int n)
{
  strncpy(dest,src,n);
}
//fill icmp packet
struct icmp *fill_icmp_packet(int icmp_type,int icmp_sequ)
{
  struct icmp *icmp_packet;
  
  icmp_packet=(struct icmp *)malloc(ICMP_PACKET_LEN);
  icmp_packet->icmp_type=icmp_type;
  icmp_packet->icmp_code=0;
  icmp_packet->icmp_cksum=0;
  icmp_packet->icmp_id=htons(getpid());
  icmp_packet->icmp_seq=htons(icmp_sequ);

  const char data[DATA_MAX_SIZE]="Insert successfully";
  my_memset((char *)&icmp_packet->icmp_data,data,DATA_MAX_SIZE);

  //send time
  //gettimeofday((struct timeval *)icmp_packet->icmp_data,NULL);
  //checksum
  icmp_packet->icmp_cksum=check_sum((unsigned short *)icmp_packet,ICMP_PACKET_LEN);
//printf("Len:%d\n",sizeof(icmp_packet->icmp_dun));
  return icmp_packet;
}

//send icmp request
void icmp_request(const char *dst_ip,int icmp_type,int icmp_sequ)
{
  struct sockaddr_in dst_addr;
  struct icmp *icmp_packet;
  int sockfd,ret_len;
  char buf[ICMP_PACKET_LEN];

  //request address
  bzero(&dst_addr,sizeof(struct sockaddr_in));
  dst_addr.sin_addr.s_addr=inet_addr(dst_ip);

  if((sockfd=socket(PF_INET,SOCK_RAW,IPPROTO_ICMP))==-1)
     err_exit("sockfd()");

  //icmp packet
  icmp_packet=fill_icmp_packet(icmp_type,icmp_sequ);
  memcpy(buf,icmp_packet,ICMP_PACKET_LEN);

  //send request
  ret_len=sendto(sockfd,buf,ICMP_PACKET_LEN,0,(struct sockaddr *)&dst_addr,sizeof(struct sockaddr_in));
  if(ret_len>0)
  {
    printf(".");
    fflush(stdout);
  }
  close(sockfd);

  if(ret_len<=0)  err_exit("Fail to send packet!\n");
}

int main(int argc,const char *argv[])
{
  if(argc!=2)
  {
    printf("usage:%s dst_ip\n",argv[0]);
    exit(1);
  }

  //send icmp request
  while(1)
  {
    icmp_request(argv[1],8,1);
    sleep(1);
  }
 
  return 0;
}
