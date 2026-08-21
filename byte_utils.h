#pragma once

#include <cstdint>

#include <pcap/pcap.h>

// Radiotap/802.11 필드는 모두 little-endian이다. 캡처된 패킷 버퍼는 정렬이
// 보장되지 않으므로 uint16_t*/uint32_t*로 캐스팅해 읽으면 정렬되지 않은
// 메모리 접근(UB)이 발생할 수 있다. 이를 피하기 위해 바이트 단위로 읽어
// 값을 조립한다.
inline std::uint16_t readLittleEndian16(const u_char* data) {
    return static_cast<std::uint16_t>(data[0]) |
           (static_cast<std::uint16_t>(data[1]) << 8);
}

inline std::uint32_t readLittleEndian32(const u_char* data) {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}
