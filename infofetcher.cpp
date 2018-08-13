#ifndef __INFOFETCHER_CPP__
#define __INFOFETCHER_CPP__

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include "infofetcher.h"
#include <arpa/inet.h>
#include <string>
#include <iostream>

using namespace std;

#define CMD_BUF_SIZE 256
#define STDOUT_BUF_SIZE 256

int get_my_ip_str(char *ifname, IPv4_addr& ip_addr) 
{
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	char stdout_buf[STDOUT_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c 'ifconfig %s' | grep 'inet ' | awk '{print $2}' | cut -d':' -f2", ifname);
	fp = popen(cmdbuf, "r");

	if (fp == NULL) 
	{
		perror("Fail to fetch ip address\n");
		return EXIT_FAILURE;
	}

	fgets(stdout_buf, STDOUT_BUF_SIZE - 1, fp);
	pclose(fp);
	for (int i=0; i < STDOUT_BUF_SIZE; i++) 
	{
		//slice ending new line character to handle processing error
		if (stdout_buf[i] == '\n') 
		{
			stdout_buf[i] = '\0';
			break;
		}
	}

	ip_addr = stdout_buf;
	return EXIT_SUCCESS;
}

int get_my_mac_str(char *ifname, MAC_addr& mac_addr) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	char stdout_buf[STDOUT_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep -oh '[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]'", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch MAC address\n");
		return EXIT_FAILURE;
	}
	fgets(stdout_buf, STDOUT_BUF_SIZE - 1, fp);
	pclose(fp);
	mac_addr = stdout_buf;
	return EXIT_SUCCESS;
}

#endif
