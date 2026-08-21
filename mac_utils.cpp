#include "mac_utils.h"

#include <iomanip>
#include <sstream>

std::string formatMacAddress(const MacAddress& mac) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < kMacAddressLength; ++i) {
        if (i != 0) {
            output << ':';
        }
        output << std::setw(2) << static_cast<unsigned int>(mac[i]);
    }
    return output.str();
}

MacAddress readMacAddress(const u_char* data) {
    MacAddress address{};
    for (std::size_t i = 0; i < address.size(); ++i) {
        address[i] = data[i];
    }
    return address;
}

bool isUnicastAddress(const MacAddress& address) {
    return (address[0] & 0x01U) == 0;
}
