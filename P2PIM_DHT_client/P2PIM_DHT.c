#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
//#include <arpa/inet.h> // for linux
#include <sys/types.h>
//#include <sys/socket.h> // for linux
//#pragma comment(lib,"libwsock32.a");

#ifndef WIN32
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <w32api.h>
#define WINVER WindowsXP
#include <ws2tcpip.h>
#endif

#include <signal.h>

#include "dht.h"

#define MAX_BOOTSTRAP_NODES 20
#define LOG_FILENAME "Log.txt"
#define TRANS_FILENAME "trans"
#define MYID_FILENAME "MyID.txt"
#define TARGETID_FILENAME "TargetID.txt"
#define IP_FILENAME "IP.txt"
#define TEMP_FILENAME "temp.txt"
#define ID_LENGTH 20

// for dht.c link parameter
unsigned int dump_flag = 0;
static unsigned char buf[4096];

static void callback(void *closure,
         			 int event,
         			 unsigned char *info_hash,
         			 void *data, size_t data_len)
{
    if(event == DHT_EVENT_SEARCH_DONE)
        printf("Search done.\n");
    else if(event == DHT_EVENT_VALUES){
        printf("Received %d values.\n", (int)(data_len / 6));
        /* show the message to check peer's id and local server binded address */
        printf("!!! Waiting peer ...");
        unsigned int i = 0;
        unsigned ip = ntohl(*((unsigned int *)data));
        unsigned short port = ntohs(*((unsigned int *)data + 1));
        for(i = 0; i < 20; i++)
            fprintf(stdout, "%02x", info_hash[i]);
        printf(" connect to local address %d.%d.%d.%d:%d.\n\n", ip >> 24 & 0xFF, ip >> 16 & 0xFF, ip >> 8 & 0xFF, ip & 0xFF, port);
    }
}

// decimal to hex (20 bytes to 40 bytes)
static void dec_to_hex(unsigned char *srcStr, int srcStrlen, unsigned char *desStr)
{
	FILE *fptrTrans;
	fptrTrans = fopen(TRANS_FILENAME, "w+"); // open the trans file
	if(fptrTrans) // test the trans file opening
	{
	    int i;
	    for(i = 0; i < srcStrlen; i++) // print the hex into trans file
	        fprintf(fptrTrans, "%02x", srcStr[i]);
	    rewind(fptrTrans); // rewind the file pointer back to the start
	    fscanf(fptrTrans, "%s", desStr); // get the hex result
	    fclose(fptrTrans); // close the trans file
	    remove(TRANS_FILENAME); // delete the trans file
	}
	else
	{
		printf("dec_to_hex(): ERROR!\n");
	}
}

// copy the string before the char "cut"
static void cutstr(unsigned char *srcStr, int srcStrlen, unsigned char *desStr, unsigned char cut)
{
	int i;
	for(i=0; i<srcStrlen; i++)
	{
		if(srcStr[i] == cut)
		{
			desStr[i] = '\0';
			break;
		}
		else
			desStr[i] = srcStr[i];
	}
}

int main()
{	
	struct sockaddr_in sin; // UDP socket address
	struct sockaddr_in bootstrap_nodes; // socket address to bootstrap 
    int rc, s; // parameter for dht_init()
    int bootstrap; // bootstrap status
    int ipv4 = 1; // Using IPv4
    struct sockaddr_storage from;
    socklen_t fromlen;
    time_t tosleep = 1; // sleep sec
    // int exploring = 5; // dht_periodic loop times
    FILE *fptrLog; // FILE pointer for log
    int searching = 1; // searching mode on
    
    // Display
    printf("< DHT for Client >\n");

    // wait for My ID
    unsigned char myid[ID_LENGTH] = {0}; 
    printf("Waiting for My ID...\n");
    while(1)
    {
    	FILE *fptrID;
    	if(fptrID = fopen(MYID_FILENAME, "r"))
    	{
    		fgets(myid, ID_LENGTH+1, fptrID);
    		fclose(fptrID);
    		remove(MYID_FILENAME);
    		break;
    	}
    }
    printf("ID: %s\n", myid);
	
	// wait for Target ID
	unsigned char targetid[ID_LENGTH] = {0};
	unsigned char targetidhex[2*ID_LENGTH];
	printf("Waiting for Target ID...\n");
    while(1)
    {
    	FILE *fptrID;
    	if(fptrID = fopen(TARGETID_FILENAME, "r"))
    	{
    		fgets(targetid, ID_LENGTH+1, fptrID);
    		fclose(fptrID);
    		remove(TARGETID_FILENAME);
    		break;
    	}
    }
    printf("Target ID: %s\n", targetid);
	dec_to_hex(targetid, ID_LENGTH, targetidhex);	
	
	// IP & ports
	unsigned short local_dht_udp_port = 11111; // local port
	char bootstrap_ip[16] = "140.115.152.32"; // bootstrap IP
    unsigned short bootstrap_port = 11111; // bootstrap port
	
	// Set UDP socket address
	memset((char *)&sin, 0, sizeof(sin)); // initial socket
    sin.sin_family = AF_INET; // must be
    sin.sin_addr.s_addr = INADDR_ANY; // any address
 	sin.sin_port = htons(local_dht_udp_port); // port
 	
 	// Set address to bootstrap
 	memset(&bootstrap_nodes, 0, sizeof(bootstrap_nodes)); // initial socket
    bootstrap_nodes.sin_family = AF_INET; // must be 
    bootstrap_nodes.sin_addr.s_addr = inet_addr(bootstrap_ip); // IP; to net
 	bootstrap_nodes.sin_port = htons(bootstrap_port); // port; htons(): host to net short int
 	
 	// IP version control
 	WSADATA wsd;
    WORD wVersionRequested;
    wVersionRequested = MAKEWORD(2,2);
    int res = 0;
    if(res = WSAStartup(wVersionRequested,&wsd) != 0) // res = 0, it confirm that the WinSock DLL supports 2.2
    {
        fprintf(stderr, "WSAStartup failed...%d",res);
        WSACleanup();
        goto exit_;                 
    }
    
    // Set IPv4 UDP Socket
    if(ipv4) {
        s = socket(PF_INET, SOCK_DGRAM, 0); // open datagram UDP socket
        if(s < 0) {
            perror("socket(IPv4)");
        }
    }
    
    if(s < 0) {
        fprintf(stderr, "Eek!");
        goto exit_;
    }
    
    if(s >= 0) {
        rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
        if(rc < 0) {
            perror("bind(IPv4)");
            goto exit_;
        }
    }
 	
 	// DHT initialize
 	rc = dht_init(s, -1, myid, (unsigned char*)"JC\0\0");
 	if(rc < 0)
 		printf("DHT initailizing: failed.\n");
 	else
 		printf("DHT initializing: successful.\n");
 	
 	// bootstrap
 	bootstrap = dht_ping_node((struct sockaddr*)&bootstrap_nodes, sizeof(bootstrap_nodes));
 	if(bootstrap < 0)
 		printf("Bootstrap: failed.\n");
 	else
 		printf("Bootstrap: successful.\n");
 	
	// dht_periodic: explore nodes
	char targetIP[16]; // string to store the target IP later 	
 	while(1)
 	{
 		struct timeval tv;
        fd_set readfds;
        tv.tv_sec = tosleep;  /* waiting packets time, maybe cloud set shorter */
        tv.tv_usec = rand() % 1000000;
        
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        fflush(stdin);
        rc = select(s + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select");
                Sleep(1000);
            }
        }
        
        if(rc > 0) {
            fromlen = sizeof(from);
            if(s >= 0 && FD_ISSET(s, &readfds))
                rc = recvfrom(s, (char *)buf, sizeof(buf) - 1, 0,
                              (struct sockaddr*)&from, &fromlen);
            
            else
                abort();
        }
        
        if(rc > 0) {
            buf[rc] = '\0';
            rc = dht_periodic(buf, rc, (struct sockaddr*)&from, fromlen,
                              &tosleep, callback, NULL);
        } else {
            rc = dht_periodic(NULL, 0, NULL, 0, &tosleep, callback, NULL);
        }
        if(rc < 0) {
            if(errno == EINTR) {
                continue;
            } else {
                perror("dht_periodic");
                if(rc == EINVAL || rc == EFAULT)
                    abort();
                tosleep = 1;
            }
        }
        
        dht_dump_tables(stdout);
        
        // search and take out the target node
        if(searching)
        {	
		 	printf("Searching the target ID...\n");
		 	printf(">> Target ID: %s\n", targetidhex);
		 	if(s >= 0)
		        dht_search(targetid, 0, AF_INET, callback, NULL);
			fptrLog = fopen(LOG_FILENAME, "w"); // open log file for writing
			
			char scan[25] = {'\0'}; // char array for scaning
			if(fptrLog) // test the file opening result
			{	
				printf("Opening the log file: successful.\n");
				dht_dump_tables(fptrLog); // dump search result to log file
				fclose(fptrLog); // close log file
				fptrLog = fopen(LOG_FILENAME, "r"); // open log file for reading
				while(fscanf(fptrLog, "%s", scan) != EOF) // scan through the log file
				{
					if(strcmp(scan, targetidhex) == 0) // found!
					{
						printf("Searching Result: found the node!!\n");
						fscanf(fptrLog, "%s", scan); 
						cutstr(scan, sizeof(scan), targetIP, ':');
						printf("IP: %s\n", targetIP);
						searching = 0; // Search done. It won't loop in the while(1) anymore.
						break;
					}	
				}
				fclose(fptrLog); // close log file 
				if(fscanf(fptrLog, "%s", scan) == EOF)
					printf("Searching Result: no matched node.\n");
			}
			else
				printf("Opening the log file: failed.\n");
        }
        else // Search done.
        	break;
 	}
		
	// create IP.txt for UI
	FILE *fptrIP;
	fptrIP = fopen(TEMP_FILENAME, "w");
	fprintf(fptrIP, "%s", targetIP);
	fclose(fptrIP);
	rename(TEMP_FILENAME, IP_FILENAME);
   	
    // un-initial
    dht_uninit();
    remove(LOG_FILENAME);
	
	// system("pause");
	return 0;
	
	// exit_ for goto
	exit_:
    system("PAUSE");
    exit(1);
}

void dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    const char *c1 = (const char *)v1, *c2 = (const char *)v2, *c3 = (const char *)v3;
    char key[9]; // crypt is limited to 8 characters 
    int i;
    
    memset(key, 0, 9);
	#define CRYPT_HAPPY(c) ((c % 0x60) + 0x20)
    
    for(i = 0; i < 2 && i < len1; i++)
        key[i] = CRYPT_HAPPY(c1[i]);
    for(i = 0; i < 4 && i < len1; i++)
        key[2 + i] = CRYPT_HAPPY(c2[i]);
    for(i = 0; i < 2 && i < len1; i++)
        key[6 + i] = CRYPT_HAPPY(c3[i]);
           
    strncpy((char *)hash_return, (char *)crypt1(key, "jc"), hash_size);    
}

// for dht.c link function
int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return 0;
}

// for dht.c link function
int dht_random_bytes(void *buf, size_t size)
{  
    int fd, rc, save;

    unsigned int i = 0;
    unsigned char *buf_ptr = (unsigned char *)buf;
    for(i = 0; i < size; i++){
        buf_ptr[i] = (unsigned char)rand()%256; /* 0~255 */
        Sleep(20);
    }
    return rc;
}
