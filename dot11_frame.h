#pragma once

#include <cstddef>

#include <pcap/pcap.h>

#include "types.h"

constexpr std::size_t kDot11ManagementHeaderLength = 24;

// 패킷 하나(Radiotap + 802.11)를 파싱해 AP/Station 테이블을 갱신한다.
// pcap_next_ex로 얻은 header/packet을 그대로 전달하면 된다.
// user는 실제로는 CaptureState*이며, pcap 콜백 시그니처를 맞추기 위해
// u_char*로 받는다.
void handlePacket(u_char* user, const pcap_pkthdr* header,
                  const u_char* packet);
