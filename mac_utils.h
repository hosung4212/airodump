#pragma once

#include <string>

#include <pcap/pcap.h>

#include "types.h"

std::string formatMacAddress(const MacAddress& mac);
MacAddress readMacAddress(const u_char* data);
bool isUnicastAddress(const MacAddress& address);
