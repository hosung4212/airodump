#pragma once

#include <cstddef>
#include <optional>

#include <pcap/pcap.h>

constexpr std::size_t kRadiotapMinimumLength = 8;

// Radiotap 헤더를 파싱해 Antenna Signal(PWR, dBm) 필드를 추출한다.
// 필드가 없거나 헤더가 손상된 경우 std::nullopt를 반환한다.
// 필드 순서 및 정렬 규칙은 radiotap.org 스펙을 따른다.
std::optional<int> parseAntennaSignal(const u_char* radiotap,
                                      std::size_t radiotapLength);
