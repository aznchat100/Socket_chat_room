//
//  main.c
//  dht_test
//
//  Created by 吳 政樺 on 12/12/5.
//  Copyright (c) 2012年 吳 政樺. All rights reserved.
//
/* This example code was written by Juliusz Chroboczek.
 You are free to cut'n'paste from it to your heart's content. */

/* For crypt */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
//#include <arpa/inet.h> // for linux
#include <sys/types.h>
//#include <sys/socket.h> // for linux
//#pragma comment(lib,"libws2_32.a");
//#pragma comment(lib,"libwsock32.a");
//#pragma comment(lib,"wsock32.lib")
//#pragma comment(lib, "Ws2_32.lib");

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
#define ID_FILENAME "ID.txt"

static int num_bootstrap_nodes = 0;

static volatile sig_atomic_t dumping = 0, searching = 0, exiting = 0; // searching off

// for test
unsigned int dump_flag = 0; // set 1 to Show the found nodes

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
sigtest(int signo)
{
    searching = 1;
}

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
init_signals(void)
{
	/*
    struct sigaction sa;
    sigset_t ss;
    
    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    
    sigemptyset(&ss);
    sa.sa_handler = sigtest;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    
    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    */
}

const unsigned char hash[20] = {
    0x54, 0x57, 0x87, 0x89, 0xdf, 0xc4, 0x23, 0xee, 0xf6, 0x03,
    0x1f, 0x81, 0x94, 0xa9, 0x3a, 0x16, 0x98, 0x8b, 0x72, 0x7b
};

/* The call-back function is called by the DHT whenever something
 interesting happens.  Right now, it only happens when we get a new value or
 when a search completes, but this may be extended in future versions. */
static void
callback(void *closure,
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

static unsigned char buf[4096];

int
main()
{
    int i, rc, fd;
    int s = -1;
    time_t tosleep = 5;
    int opt;
    int quiet = 0, ipv4 = 1;
    struct sockaddr_in sin;
    struct sockaddr_storage from;
    socklen_t fromlen;
    
    // Display
    printf("< DHT for Server >\n");
    
    // wait for My ID 
    unsigned char myid[20] = {'\0'}; /* 20 bytes unique id*/
    printf("Waiting for ID...\n");
    while(1)
    {
    	FILE *fptrID;
    	if(fptrID = fopen(ID_FILENAME, "r"))
    	{
    		fgets(myid, 20+1, fptrID);
    		fclose(fptrID);
    		if(myid != '\0')
    		{
    			remove(ID_FILENAME);
    			break;
    		}
    	}
    }
    printf("ID: %s\n", myid);
    
    /* set local dht udp address */
//    unsigned short local_dht_udp_port = 0;
    unsigned short local_dht_udp_port = 11111;
    memset((char *)&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
 	sin.sin_port = htons(local_dht_udp_port); 

    /* bootstrap node's ip and udp port */ 
//    char bootstrap_ip[16] = "0.0.0.0"; 
//    unsigned short bootstrap_port = 0;
    char bootstrap_ip[16] = "140.115.152.32"; 
    unsigned short bootstrap_port = 11111;

    struct sockaddr_in bootstrap_nodes;
    memset(&bootstrap_nodes, 0, sizeof(bootstrap_nodes));
    bootstrap_nodes.sin_family = AF_INET;
    bootstrap_nodes.sin_addr.s_addr = inet_addr(bootstrap_ip);
 	bootstrap_nodes.sin_port = htons(bootstrap_port);
    
    {
        srand(time(NULL));
    }
    
    /* If you set dht_debug to a stream, every action taken by the DHT will
     be logged. */
    if(!quiet)
        dht_debug = stdout;
    
    /* We need an IPv4 and an IPv6 socket, bound to a stable port.  Rumour
     has it that uTorrent works better when it is the same as your
     Bittorrent port. */
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
    
    if(ipv4) {
        s = socket(PF_INET, SOCK_DGRAM, 0);
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
    
    /* Init the dht.  This sets the socket into non-blocking mode. */
    rc = dht_init(s, -1, myid, (unsigned char*)"JC\0\0");
    if(rc < 0) {
        perror("dht_init");
        goto exit_;
    }
    
    /* useless */
    init_signals();
    
    /* For bootstrapping, we need an initial list of nodes.  This could be
     hard-wired, but can also be obtained from the nodes key of a torrent
     file, or from the PORT bittorrent message.
     
     Dht_ping_node is the brutal way of bootstrapping -- it actually
     sends a message to the peer.  If you're going to bootstrap from
     a massive number of nodes (for example because you're restoring from
     a dump) and you already know their ids, it's better to use
     dht_insert_node.  If the ids are incorrect, the DHT will recover. */
    int bootstrap;
    bootstrap = dht_ping_node((struct sockaddr*)&bootstrap_nodes,
                      sizeof(bootstrap_nodes));
    printf("bootstrap: %d\n", bootstrap);
	
    
    while(1) {
        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = tosleep;  /* watting packets time, maybe cloud set shorter */
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
        
        if(exiting)
            break;
        
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
        
        /* This is how you trigger a search for a torrent hash.  If port
         (the second argument) is non-zero, it also performs an announce.
         Since peers expire announced data after 30 minutes, it's a good
         idea to reannounce every 28 minutes or so. */
        if(searching) { /* searching flag default is false(0) */
            printf("dht start searching\n");
            if(s >= 0)
                dht_search(hash /* searching id */, 0 /* port number */, AF_INET, callback, NULL);
            searching = 0;
        }
        
        /* For debugging, or idle curiosity. */
        /* show informations of known nodes, if you want to check status every times, setting the flags as TRUE(1) */
        if(dumping || dump_flag) {
            dht_dump_tables(stdout);
            dumping = 0;
            dump_flag = 0;
        }
    }
    
    {
        struct sockaddr_in sin[500];
        struct sockaddr_in6 sin6[500];
        int num = 500, num6 = 500;
        int i;
        i = dht_get_nodes(sin, &num, sin6, &num6);
        printf("Found %d (%d + %d) good nodes.\n", i, num, num6);
    }
    
    dht_uninit();
    printf("exit\n");
    system("PAUSE");
    return 0;
    
usage:
    printf("Usage: dht-example [-q] [-4] [-6] [-i filename] [-b address]...\n"
           "                   port [address port]...\n");
    goto exit_;

exit_:
    system("PAUSE");
    exit(1);
}

/* Functions called by the DHT. */

int
dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return 0;
}

/* We need to provide a reasonably strong cryptographic hashing function.
 Here's how we'd do it if we had RSA's MD5 code. */
#if 0 // won't compile 
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    static MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, v1, len1);
    MD5Update(&ctx, v2, len2);
    MD5Update(&ctx, v3, len3);
    MD5Final(&ctx);
    if(hash_size > 16)
        memset((char*)hash_return + 16, 0, hash_size - 16);
    memcpy(hash_return, ctx.digest, hash_size > 16 ? 16 : hash_size);
}
#else
/* But for this example, we might as well use something weaker. */
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    const char *c1 = (const char *)v1, *c2 = (const char *)v2, *c3 = (const char *)v3;
    char key[9];                /* crypt is limited to 8 characters */
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
#endif

int
dht_random_bytes(void *buf, size_t size)
{
// test    
    int fd, rc, save;
/*
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0)
        return -1;
    
    rc = read(fd, buf, size);
    
    save = errno;
    close(fd);
    errno = save;
*/
    unsigned int i = 0;
    unsigned char *buf_ptr = (unsigned char *)buf;
    for(i = 0; i < size; i++){
        buf_ptr[i] = (unsigned char)rand()%256; /* 0~255 */
        Sleep(20);
    }
    return rc;
}
