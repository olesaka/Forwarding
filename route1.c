#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pthread.h>


/*
	Program that implements basic functionality.
	Authors: Andrew Olesak, Joey Seder, Keith Roders
*/


/* method declarations */
void *net_thread(void *p_mac);
int findMacAddress(char myMacs[3][6], char mac[6]);
int rand(void);
int getIP(char ipTable[4][9], char ip[4], int row);
int createTable(char *table, char ipTable[4][9]);
int tableLookup(char ipTable[4][9], char destIP[4]);
int createICMPResponse(char *buff);
int createArpRequest(char *buff, char srcIP[4], char destIP[4], char mac[6]);
int scanFromFile(char filename[], char table[]);
int createArpResponse(char *buff, char ip[4], char mac[6]);
int scanFromFile(char filename[], char table[]);
short calcCheckSum(char* buffer, int length);
void* malloc(size_t size);
int newEthHeader(char *buff, char srcMac[6], char destMac[6]);
int TTLUpdate(char *buff);
int findIPAddress(char myIps[3][4], char ip[4]);
int verifyChecksum(char *buff, int length);
int createICMPError(char *buff, int type, int code);

  // creat the ARP header struct to braek it up
  struct arphdr
  {
  	unsigned short int ar_type;      // hardware address
  	unsigned short int ar_pro;		// protocal address
  	unsigned char ar_hln;			// length of hardware address
  	unsigned char ar_pln;			// length of protocal address
  	unsigned short int ar_op;		// ARP opcode
  	u_int8_t send_MAC_adds[6]; // senders mac address
  	u_int8_t send_IP_adds[4];	// senders ip address
  	u_int8_t targ_MAC_adds[6]; // receivers mac adddress
  	u_int8_t targ_IP_adds[4]; // receivers ip address
  };

  // create a struct to hold all of the mac addresses
  // for this particualr router
  // also include a counter to make sure
  // everything gets assigned correctly.
	struct myAddresses
  {
  	char ip[4];
  	char eth[6];
  	int sock_num;
  };

  struct queue
  {
  	char buffer[1500];
  	int length;
  };
  
  /* Class variables, used in main and thread methods */
  char myMacs[3][6];
  char myIps[3][4];
  char ipTable[4][9];
  int ports[3];
  int timeout = 0;

int main(){
  int packet_socket;
  int router_socket;
  pthread_t pth[10];
	
	// read in the routing table
   char table1[200];
   // char tables1[4][40];
  
  // read in routing table 1 and create table
  scanFromFile("r1-table.txt", table1); 
  createTable(table1, ipTable);

  // count is used to keep track of all addresses in myMacs 2d array.
  // threads counts the index of the current thread
  int count = 0;
  int threads = 0;


  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
	  struct myAddresses *mac;
	  mac = malloc(sizeof(struct myAddresses));
    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    if(tmp->ifa_addr->sa_family==AF_PACKET){
	      printf("Interface: %s\n",tmp->ifa_name);
	      //create a packet socket on interface r?-eth1
	      struct sockaddr_ll *s = (struct sockaddr_ll*)tmp->ifa_addr;

		  // get the mac address for this interface instance
		  memcpy(&mac->eth, s->sll_addr, 6);
		  
	      // get all of the mac addresses for this router
	      if(count==1){
	      	memcpy(&myMacs[0], s->sll_addr, 6);
	      	myIps[0][0] = 0xa;
	      	myIps[0][1] = 0x0;
	      	myIps[0][2] = 0x0;
	      	myIps[0][3] = 0x1;
	      	ports[count-1] = 19;
	      }
	      if(count==2){
	      	memcpy(&myMacs[1], s->sll_addr, 6);
	      	myIps[1][0] = 0xa;
	      	myIps[1][1] = 0x1;
	      	myIps[1][2] = 0x0;
	      	myIps[1][3] = 0x1;
	      	ports[count-1] = 20;
		  }
	      if(count==3){
	      	memcpy(&myMacs[2], s->sll_addr, 6);
	      	myIps[2][0] = 0xa;
	      	myIps[2][1] = 0x1;
	      	myIps[2][2] = 0x1;
	      	myIps[2][3] = 0x1;
	      	ports[count-1] = 21;
		  }
	      ++count;

      if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){
		printf("Creating Socket on interface %s\n",tmp->ifa_name);
		//create a packet socket
		//AF_PACKET makes it a packet socket
		//SOCK_RAW makes it so we get the entire packet
		//could also use SOCK_DGRAM to cut off link layer header
		//ETH_P_ALL indicates we want all (upper layer) protocols
		//we could specify just a specific one
		packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		mac->sock_num = packet_socket;
		if(packet_socket<0){
		  perror("socket");
		  return 2;
		}
		//Bind the socket to the address, so we only get packets
		//recieved on this specific interface. For packet sockets, the
		//address structure is a struct sockaddr_ll (see the man page
		//for "packet"), but of course bind takes a struct sockaddr.
		//Here, we can use the sockaddr we got from getifaddrs (which
		//we could convert to sockaddr_ll if we needed to)
		if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
		  perror("bind");
		}
		
		// Creates a thread for each ethernet interface. 
		// mac - structure parameter containing socket number, ip address, and MAC address
		pthread_create(&pth[threads], NULL, net_thread, (void *)(mac));
		threads++;
	
      } // !!! else if below is unreachable, all ethernet sockets should be caught above
	  else if(!strncmp(&(tmp->ifa_name[3]), "eth0", 4)) {
		router_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(packet_socket<0){
		  perror("socket");
		  return 2;
		}
		if(bind(router_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
		  perror("bind");
		}
      }
    }
	
  }
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  // wait for at least one thread to finish at program termination
  // Each thread should continue until program termination
  pthread_join(pth[0], NULL);
}



  // create a struct to hold a packet while arp requests
  // are being sent
  struct queue que;

void *net_thread(void *p_mac) {
	// read p_mac into myAddresses struct
	struct myAddresses mac = *((struct myAddresses *) p_mac); 
	

	//loop and recieve packets. We are only looking at one interface,
	//for the project you will probably want to look at more (to do so,
	//a good way is to have one socket per interface and use select to
	//see which ones have data)
	printf("Ready to recieve now\n");
	while(1){
		char buf[1500];
		struct sockaddr_ll recvaddr;
		int recvaddrlen=sizeof(struct sockaddr_ll);
		//we can use recv, since the addresses are in the packet, but we
		//use recvfrom because it gives us an easy way to determine if
		//this packet is incoming or outgoing (when using ETH_P_ALL, we
		//see packets in both directions. Only outgoing can be seen when
		//using a packet socket with some specific protocol)
		int n = recvfrom(mac.sock_num, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
		//ignore outgoing packets (we can't disable some from being sent
		//by the OS automatically, for example ICMP port unreachable
		//messages, so we will just ignore them here)
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
		  continue;
		//start processing all others
		printf("Got a %d byte packet\n", n);

		// struct ether_addr eth;
		// struct arphdr arp;
		// put ethernet type into a short
		short c = (((short)buf[12]) << 8) | buf[13];

		/* handle arp request */
		if(c == 0x806){
			printf("arp\n");

			// find out if this is an arp request or arp resposne
			char dest[6];
			memcpy(dest, buf, 6);
			int place = findMacAddress(myMacs, dest);
			if(place==-1){
				// check to see if the destination of the arp request
				// matches ours
				memcpy(dest, &buf[38], 4);
				int row = tableLookup(ipTable, dest);
				if(row!=-1 && row!=3){
					// get the source ip address from the arp request
					memcpy(dest, &buf[38], 4);
				
					// create an arp response with the given ip address from above
					// and the associated mac address
					createArpResponse(buf, dest, mac.eth);

					// send the arp response
					send(mac.sock_num, buf, 42, 0);
					continue;
				}
			}else{
				//got an arp response, so formulate the packets
				// destination with the new mac address and send it on
				timeout=0;
				char dest[6];
				char src[6];
				memcpy(src, buf, 6);
				memcpy(dest, &buf[6], 6);
				memcpy(buf, que.buffer, 98);

	        	// redo checksum
	        	buf[24] = 0x0;
	        	buf[25] = 0x0;
	        	char temp[20];
	        	memcpy(temp, &buf[14], 20);
	        	short s = calcCheckSum(temp, 20);
	        	s = htons(s);
	        	buf[24] = s & 0xff;
	        	buf[25] = (s>>8) & 0xff;
				// create new eth header
				newEthHeader(buf, src, dest);
				// send packet to next destination
				send(mac.sock_num, buf, que.length, 0);



			}


		}
		/* handle icmp request */
		else{

	      	// validate the checksum value
	      	char temp[20];
	      	memcpy(temp, &buf[14], 20);
	      	if(verifyChecksum(temp, 20)==1){

	        //find out if the mac address in the ICMP request
	        // belongs to us 
	        char mac2[6];
	        memcpy(mac2, &buf, 6);
	        int macRow = findMacAddress(myMacs, mac2);
	        if(macRow!=-1){
	        	if(TTLUpdate(buf)!=0){
			          char dest[4];
			          memcpy(dest, &buf[30], 4);
			          int ipRow = tableLookup(ipTable, dest);
			          if(ipRow!=-1){
				          char destIP[4];
				          memcpy(destIP, &buf[30], 4);
				          int myIpRow = findIPAddress(myIps, destIP);
				          if(myIpRow!=-1){
					            // ip address an immediate address, so we can
					            // forward the packet from here
					            createICMPResponse(buf);
					            send(mac.sock_num, buf, 98, 0);
					        }else{
					        	if(ipRow>=0 && ipRow<3){
					        		memcpy(dest, &buf[30], 4);
					        	}else{
						            // send and arp request to get the next hops mac address
						            getIP(ipTable, dest, ipRow);
					        	}
					        	if(ipRow==3){
					        		ipRow=0;
					        	}
				                  if(timeout==2){
				                    createICMPError(buf, 3, 1);
				                    send(mac.sock_num, buf, 70, 0);
				                    timeout=0;
				                    continue;
				                  }
        
					            //packet ip address is not for this router, so 
					            // store the packet
					            memcpy(que.buffer, buf, n);
					            que.length = n;
					            createArpRequest(buf, myIps[0], dest, myMacs[ipRow]);
					            send(ports[ipRow], buf, 42, 0);
					            ++timeout;
					            continue;

					        }
					    	}else{
					    		// ip address wasn't found in the table, so send icmp unreachable error
					    		createICMPError(buf, 3, 0);
					    		send(mac.sock_num, buf, 70, 0);
					    	}
				    	}else{
				    		// send time exceeded error 
				    		createICMPError(buf, 11, 0);
				    		send(mac.sock_num, buf, 70, 0);
				    	}

			        }
		    	}
		    }
	  	}
	}

// function calculates the checksum value for a given
// buffer and length
short calcCheckSum(char* buffer, int length){
  	int j=0;
  	unsigned int checkSum=0;
  	unsigned short c=0;
  	for(j=0; j<length; j+=2){
  		if(length%2==1 && j+1==length){
  			unsigned char one = buffer[j];
  			c = ((( unsigned short)one) << 8) | 0x00;
		}else{
			unsigned char one = buffer[j];
			unsigned char two = buffer[j+1];
    		c = ((one) << 8) | two; // unsigned short
		}
  		checkSum+=c;
  		if((checkSum & 0x10000)==0x10000){
  			checkSum&=0xFFFF;
  			checkSum++;
		}
  	}
  	return (short)((~checkSum)&0xFFFF);
}


/*Function that reads from a file and saves the contents to a char array*/
int scanFromFile(char filename[], char table[]) {
/*scan from routing table*/
   FILE *fp;
   int c;
   int i=0;
   fp = fopen(filename, "r");

   if(fp == NULL) {
      perror("Error in opening file");
      return(-1);
   } do {
      c = fgetc(fp);
      if( feof(fp) ) {
         break ;
      }
      table[i] = c;
      ++i;
   } while(1);
   
   fclose(fp);
   return(0);
}

// creates and arp response with the given buffer, ip, and mac address
int createArpResponse(char *buff, char ip[4], char mac[6]){

	// initialize some structs to work with
	struct ether_header eth;
    struct arphdr arp;
	
	// ****set the arp response
	// arp OP
	arp.ar_type = 1;
	// arp protocal type
	arp.ar_pro = (((short)buff[16]) << 8 | buff[17]);
	// arp hardware size
	arp.ar_hln = buff[18];
	// arp protocal size
	arp.ar_pln = buff[19];
	// arp OP
	arp.ar_op = 2;

    eth.ether_type = (((short)buff[12]) << 8) | buff[13];

    memcpy(arp.targ_IP_adds, &buff[28], 4);
	// arp senders ip address
	memcpy(arp.send_IP_adds, ip, 4);
	memcpy(arp.send_MAC_adds, mac, 6);
	// set the mac adddress of the router
	memcpy(eth.ether_shost, mac, 6);
	memcpy(arp.targ_MAC_adds, &buff[22], 6);
	memcpy(eth.ether_dhost, arp.targ_MAC_adds, 6);

	// *** write the contents of the structs to the char array
	eth.ether_type = ntohs(eth.ether_type);
	memcpy(buff, &eth, 14);
	// print out all of the packet info
	// for(i=0; i<14; ++i){
	// 	printf("hey %x\n", buf[i]);
	// }

	// *** write the contents of the arp struct now
	arp.ar_type = ntohs(arp.ar_type);
	arp.ar_pro = ntohs(arp.ar_pro);
	arp.ar_op = ntohs(arp.ar_op);
	memcpy(&buff[14], &arp, 28);

	return 42;
}

// creates an arp request with the given buffer, source ip,
// destination ip, and mac address
int createArpRequest(char *buff, char srcIP[4], char destIP[4], char mac[6]){

	// initialize some structs to work with
    struct ether_header ether;
    struct arphdr arpRequest;


    // ****set the arp response
	// arp OP
	arpRequest.ar_type = 1;
	// arp protocal type
	arpRequest.ar_pro = 0x800;
	// arp hardware size
	arpRequest.ar_hln = 6;
	// arp protocal size
	arpRequest.ar_pln = 4;
	// arp OP
	arpRequest.ar_op = 1;
	// set the senders mac address
	memcpy(arpRequest.send_MAC_adds, mac, 6);
	// set the senders ip address
	memcpy(arpRequest.send_IP_adds, srcIP, 4);
	// set the target mac address
	int i;
	for(i=0; i<6; ++i){
		arpRequest.targ_MAC_adds[i] = 0x0;
	}
	// set the target ip address
	memcpy(arpRequest.targ_IP_adds, destIP, 4);
	// set the mac adddress of the router

	// set the link layer destination
	for(i=0; i<6; ++i){
		ether.ether_dhost[i] = 0xff;
	}
	// set the link layer source
	memcpy(ether.ether_shost, mac, 6);
	// set the packet type
	ether.ether_type = 0x806;

	// *** write the contents of the structs to the char array
	ether.ether_type = ntohs(ether.ether_type);
	memcpy(buff, &ether, 14);

	// *** write the contents of the arp struct now
	arpRequest.ar_type = ntohs(arpRequest.ar_type);
	arpRequest.ar_pro = ntohs(arpRequest.ar_pro);
	arpRequest.ar_op = ntohs(arpRequest.ar_op);
	memcpy(&buff[14], &arpRequest, 28);

	return 0;
}

// creates an icmp response with the given buffer
int createICMPResponse(char *buff){

	struct icmphdr icmpin;
	struct icmphdr icmpout;
	struct ether_header ethin;
	struct ether_header ethout;
	struct iphdr ipin;
	struct iphdr ipout;
	char data[56];
	char dest[4];

	memcpy(dest, &buff[30], 4);
	memcpy(&ethin, buff, 14);
	memcpy(&ipin, &buff[14], 20);
	memcpy(&icmpin, &buff[34], 8);
	memcpy(&data, &buff[42], 56);

	// set the output eth header
	ethout.ether_dhost[0] = (ethin.ether_shost[0]);
	ethout.ether_dhost[1] = (ethin.ether_shost[1]);
	ethout.ether_dhost[2] = (ethin.ether_shost[2]);
	ethout.ether_dhost[3] = (ethin.ether_shost[3]);
	ethout.ether_dhost[4] = (ethin.ether_shost[4]);
	ethout.ether_dhost[5] = (ethin.ether_shost[5]);

	ethout.ether_shost[0] = (ethin.ether_dhost[0]);
	ethout.ether_shost[1] = (ethin.ether_dhost[1]);
	ethout.ether_shost[2] = (ethin.ether_dhost[2]);
	ethout.ether_shost[3] = (ethin.ether_dhost[3]);
	ethout.ether_shost[4] = (ethin.ether_dhost[4]);
	ethout.ether_shost[5] = (ethin.ether_dhost[5]);

	// set ethernet header type
	ethout.ether_type = ethin.ether_type;

	// set the output ip header
	ipout.ihl = ipin.ihl;
	ipout.version = ipin.version;
	ipout.tos = ipin.tos;
	ipout.frag_off = ipin.frag_off;
	ipout.protocol = ipin.protocol;
	ipout.tot_len = ipin.tot_len;
	ipout.saddr = (ipin.daddr);
	ipout.daddr = (ipin.saddr);
	ipout.ttl = 64;
	ipout.check = 0;
	ipout.id = rand();
	// set output ip header checksum
	char d1[20];
	int i=0;
	for(i=0; i<20; ++i){
		d1[i]=0;
	}
	memcpy(&d1, &ipout, 20);
	ipout.check = calcCheckSum(d1, 20);
	ipout.check = htons(ipout.check);

	// set the output icmp header
	icmpout.type = 0;
	icmpout.code = 0;
	icmpout.checksum = 0;
	icmpout.un.echo.id = icmpin.un.echo.id;
	icmpout.un.echo.sequence = icmpin.un.echo.sequence;
	// set output icmp header checksum
	char d2[64];
	for(i=0; i<64; ++i){
		d2[i]=0;
	}
	memcpy(d2, &icmpout, 8);
	memcpy(&d2[8], &data, 56);
	icmpout.checksum = calcCheckSum(d2, 64);
	icmpout.checksum = htons(icmpout.checksum);

	// *** write the contents of the structs to the char array
	memcpy(buff, &ethout, 14);
	memcpy(&buff[14], &ipout, 20);
	memcpy(&buff[34], &icmpout, 8);
	memcpy(&buff[42], &data, 56);

	return 0;	
}

// creates ICMP error messages with the given buffer,
// type, and code
int createICMPError(char *buff, int type, int code){

	// get the ip header and first 8 bytes of the next header
	char append[28];
	memcpy(append, &buff[14], 28);

	// switch the eth header destination and source mac addresses
	char temp[6];
	memcpy(temp, buff, 6);
	memcpy(buff, &buff[6], 6);
	memcpy(&buff[6], temp, 6);

	// set the destination and source ip in
	// the ip header
	memcpy(&buff[30], &buff[26], 4);
	char adds[6];
	memcpy(adds, &buff[6], 6);
	int row = findMacAddress(myMacs, adds);
	memcpy(&buff[26], myIps[row], 4);

	// set the ttl and the type
	buff[22] = 64;
	buff[23] = 1;

	// set the type to destination unreachable
	buff[34] = type;

	// set the code
	buff[35] = code;

	// set the four zeros
	int i;
	for(i=38; i<42; ++i){
		buff[i] = 0x0;
	}

	buff[17] = 56;


	// append the previous info to the end of the packet
	memcpy(&buff[42], append, 28);

	// recompute checksums
	buff[24] = 0x0;
	buff[25] = 0x0;
	char check[20];
	memcpy(check, &buff[14], 20);
	short c = calcCheckSum(check, 20);
	c = htons(c);
	buff[24] = c & 0xff;
	buff[25] = (c>>8) & 0xff;

	//compute the other checksum
	buff[36] = 0x0;
	buff[37] = 0x0;
	char check2[36];
	memcpy(check2, &buff[34], 36);
	c = calcCheckSum(check2, 36);
	c = htons(c);
	buff[36] = c & 0xff;
	buff[37] = (c>>8) & 0xff;

  return 0;
}

// finds the row of the destination ip address in
// the table and returns it
// returns negative one if it is not found
int tableLookup(char ipTable[4][9], char destIP[4]){

	int match=0;
	int i;
	int j;
	for(i=0; i<4; ++i){
		for(j=0; j<3; ++j){
			if(destIP[j]!=ipTable[i][j]){
				match = -1;
			}else{
				++match;
			}
			if(ipTable[i][4]==16 && match==2){
				return i;
			}
			if(match==3){
				return i;
			}
		}
		match=0;
	}
	return -1;
}

// creates the lookup table from the char buffer
int createTable(char *table, char ipTable[4][9]){

	char temp[4][40];

	 //first table  
	int j = 0;
	int k = 0;
	int m = 0;
	while( j != 92) {
		if( table[j] == '\n') {
		    k++;
		    m = 0;
		}else {
		  	temp[k][m] = table[j];
		  	if(k==3){
		  	}
		  	m++;
		}
		j++;
	}
	int i;
	int c=0;
	int spot=0;
	int track=0;
	for(i=0; i<4; ++i){
		for(j=0; j<21; ++j){
			if(temp[i][j]=='-'){
				break;
			}
			if(temp[i][j]!='.' && temp[i][j]!='/' && temp[i][j]!=' '){
				if(track==0){
					spot = temp[i][j]-'0';
				}else{
					spot = spot*10 + (temp[i][j]-'0');
				}
				++track;
			}else{
				ipTable[i][c] = spot;
				++c;
				spot=0;
				track=0;
			}
		}
		c=0;
	}
	return 0;
}

// gets the ip from the given table and row and puts
// it in ip
int getIP(char ipTable[4][9], char ip[4], int row){

	if(row==3){
		memcpy(ip, &ipTable[row][5], 4);
	}else{
		memcpy(ip, &ipTable[row][0], 4);
	}
	return 0;
}

// finds the matching row of the given mac address
// in the list of mac addresses for this router
// returns negative one if it is not found
int findMacAddress(char myMacs[3][6], char mac[6]){
	int i;
	int j;
	int count = 0;
	for(i=0; i<3; ++i){
		for(j=0; j<6; ++j){
			if(mac[j]!=myMacs[i][j]){
				break;
			}else{
				++count;
			}
		}
		if(count==6){
			return i;
		}
		count=0;
	}
	return -1;
}

// finds the matching row of the given ip address
// in the list of ip addresses for this router
// returns negative one if it is not found
int findIPAddress(char myIps[3][4], char ip[4]){
  int i;
  int j;
  int count = 0;
  for(i=0; i<4; ++i){
    for(j=0; j<4; ++j){
      if(ip[j]!=myIps[i][j]){
        break;
      }else{
        ++count;
      }
    }
    if(count==4){
      return i;
    }
    count=0;
  }
  return -1;
}

// changes the ethernet header to the new
// destination and source mac addresses
int newEthHeader(char *buff, char srcMac[6], char destMac[6]){

	memcpy(&buff[6], srcMac, 6);
	memcpy(buff, destMac, 6);

	return 0;
}

// returns one if the given range of the packet's
// checksum value is correct and zero if it's not
int verifyChecksum(char *buff, int length){

	int i;
	unsigned int checkSum=0;
	unsigned short c;
	for(i=0; i<length; i+=2){
		if(i!=10){
			if(length%2==1 && i+1==length){
	  			unsigned char one = buff[i];
	  			c = ((( unsigned short)one) << 8) | 0x00;
			}else{
				unsigned char one = buff[i];
				unsigned char two = buff[i+1];
	    		c = ((one) << 8) | two; // unsigned short
			}
	  		checkSum+=c;
	  		if((checkSum & 0x10000)==0x10000){
	  			checkSum&=0xFFFF;
	  			checkSum++;
			}
		}
	}
	unsigned char one = buff[10];
	unsigned char two = buff[11];
	c = ((one) << 8) | two;
	checkSum+=c;
	if((checkSum & 0xFFFF)==0xFFFF){
		return 1;
	}
	return 0;
}

// updates the ttl in the packet as long
// as it doesnt put the ttl to 0
// correctly updtades the packet for valid ttl
// and returns one for true
// returns zero for false
int TTLUpdate(char *buff){
	if(buff[22]==1){
		return 0;
	}
	buff[22] -= 1;
	return 1;
}