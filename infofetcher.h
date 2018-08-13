#ifndef __INFOFETCHER_H__
#define __INFOFETCHER_H__

#include "ip.h"
#include "mac.h"

int get_my_ip_str(char *, IPv4_addr&);
int get_my_mac_str(char *, MAC_addr&);

#endif
