#include "dot11_frame.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "byte_utils.h"
#include "mac_utils.h"
#include "radiotap.h"

namespace {

constexpr std::size_t kBeaconFixedParametersLength = 12;
constexpr std::size_t kFrameControlOffset = 0;
constexpr std::size_t kBssidOffset = 16;
constexpr std::uint8_t kSsidElementId = 0;
constexpr std::uint8_t kDsParameterSetElementId = 3;
constexpr std::uint8_t kRsnElementId = 48;
constexpr std::uint8_t kHtOperationElementId = 61;
constexpr std::uint8_t kVendorSpecificElementId = 221;
constexpr std::size_t kMaximumSsidLength = 32;
constexpr std::uint16_t kTypeMask = 0x000c;
constexpr std::uint16_t kManagementType = 0x0000;
constexpr std::uint16_t kDataType = 0x0008;
constexpr std::uint16_t kSubtypeMask = 0x00f0;
constexpr std::uint16_t kBeaconSubtype = 0x0080;
constexpr std::uint16_t kProbeRequestSubtype = 0x0040;
constexpr std::uint16_t kNoDataSubtypeBit = 0x0040;
constexpr std::uint16_t kToDsBit = 0x0100;
constexpr std::uint16_t kFromDsBit = 0x0200;
constexpr std::uint16_t kPrivacyCapabilityBit = 0x0010;
constexpr std::size_t kCapabilityOffset = kDot11ManagementHeaderLength + 10;

std::string sanitizeSsid(const u_char* data, std::size_t length) {
    if (length == 0) {
        return "<hidden>";
    }

    std::string ssid;
    ssid.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        const unsigned char byte = data[i];
        ssid.push_back(byte >= 0x20 && byte <= 0x7e
                           ? static_cast<char>(byte)
                           : '.');
    }
    return ssid;
}

std::optional<std::string> findSsidElement(const u_char* dot11,
                                           std::size_t frameLength,
                                           std::size_t firstElementOffset) {
    if (firstElementOffset > frameLength) {
        return std::nullopt;
    }

    std::size_t offset = firstElementOffset;
    while (offset + 2 <= frameLength) {
        const std::uint8_t elementId = dot11[offset];
        const std::size_t elementLength = dot11[offset + 1];
        offset += 2;
        if (elementLength > frameLength - offset) {
            return std::nullopt;
        }
        if (elementId == kSsidElementId &&
            elementLength <= kMaximumSsidLength) {
            return sanitizeSsid(dot11 + offset, elementLength);
        }
        offset += elementLength;
    }
    return std::nullopt;
}

void handleDataFrame(CaptureState& state, const u_char* dot11,
                     std::uint16_t frameControl) {
    const bool toDs = (frameControl & kToDsBit) != 0;
    const bool fromDs = (frameControl & kFromDsBit) != 0;
    if (toDs && fromDs) {
        return;  // WDS(AP 간 중계) 프레임은 단일 BSSID 필드로 식별할 수 없다.
    }

    // toDS/fromDS 조합에 따라 addr1/addr2/addr3에 들어가는 값이 달라진다
    // (802.11 표준 표 그대로): addr1=offset 4, addr2=offset 10, addr3=offset 16.
    const std::size_t dataBssidOffset = toDs ? 4 : (fromDs ? 10 : 16);
    const std::size_t stationOffset = toDs ? 10 : (fromDs ? 4 : 10);
    const MacAddress bssid = readMacAddress(dot11 + dataBssidOffset);
    const MacAddress stationAddress = readMacAddress(dot11 + stationOffset);
    const auto accessPoint = state.accessPoints.find(bssid);
    if (accessPoint == state.accessPoints.end()) {
        return;  // Beacon을 아직 수신하지 못한 BSSID는 airodump-ng와 동일하게 무시한다.
    }

    // subtype bit 6이 설정된 프레임(Null/QoS-Null 등)은 헤더만 있고 실제
    // payload가 없으므로 #Data 카운트에서 제외한다.
    if ((frameControl & kNoDataSubtypeBit) == 0) {
        ++accessPoint->second.dataCount;
    }
    if (isUnicastAddress(stationAddress)) {
        Station& station = state.stations[stationAddress];
        station.associatedBssid = bssid;
        ++station.frameCount;
    }
}

void handleProbeRequest(CaptureState& state, const u_char* dot11,
                        std::size_t remainingLength) {
    // Probe Request는 AP와 연결되지 않은 station도 보내므로 associatedBssid는
    // 갱신하지 않는다(연결 여부는 Data 프레임에서 확인되면 채워진다).
    const MacAddress stationAddress = readMacAddress(dot11 + 10);
    if (!isUnicastAddress(stationAddress)) {
        return;
    }
    Station& station = state.stations[stationAddress];
    ++station.frameCount;
    const auto probedEssid = findSsidElement(
        dot11, remainingLength, kDot11ManagementHeaderLength);
    if (probedEssid && *probedEssid != "<hidden>") {
        station.probedEssid = *probedEssid;
    }
}

void handleBeacon(CaptureState& state, const u_char* dot11,
                  std::size_t remainingLength,
                  const std::optional<int>& antennaSignal) {
    constexpr std::size_t kInformationElementsOffset =
        kDot11ManagementHeaderLength + kBeaconFixedParametersLength;
    if (remainingLength < kInformationElementsOffset) {
        return;
    }

    const MacAddress bssid = readMacAddress(dot11 + kBssidOffset);
    const std::uint16_t capability =
        readLittleEndian16(dot11 + kCapabilityOffset);
    const bool privacy = (capability & kPrivacyCapabilityBit) != 0;

    std::string essid;
    bool foundSsid = false;
    bool foundRsn = false;
    bool foundWpa = false;
    std::optional<unsigned int> dsChannel;
    std::optional<unsigned int> htPrimaryChannel;
    std::size_t offset = kInformationElementsOffset;
    while (offset + 2 <= remainingLength) {
        const std::uint8_t elementId = dot11[offset];
        const std::size_t elementLength = dot11[offset + 1];
        offset += 2;

        if (elementLength > remainingLength - offset) {
            break;  // IE가 프레임 끝에서 잘려 있으면 파싱을 중단한다(존재하지 않는 데이터를 읽지 않기 위함).
        }
        if (!foundSsid && elementId == kSsidElementId &&
            elementLength <= kMaximumSsidLength) {
            essid = sanitizeSsid(dot11 + offset, elementLength);
            foundSsid = true;
        } else if (elementId == kDsParameterSetElementId &&
                   elementLength == 1 && dot11[offset] != 0) {
            dsChannel = dot11[offset];
        } else if (elementId == kRsnElementId) {
            foundRsn = true;
        } else if (elementId == kHtOperationElementId &&
                   elementLength >= 1 && dot11[offset] != 0) {
            htPrimaryChannel = dot11[offset];
        } else if (elementId == kVendorSpecificElementId &&
                   elementLength >= 4 &&
                   dot11[offset] == 0x00 && dot11[offset + 1] == 0x50 &&
                   dot11[offset + 2] == 0xf2 && dot11[offset + 3] == 0x01) {
            // WPA1은 표준 RSN IE 대신 이 vendor-specific IE로 표시된다.
            // OUI 00:50:f2는 Microsoft, vendor type 1은 WPA를 의미한다.
            foundWpa = true;
        }
        offset += elementLength;
    }

    AccessPoint& accessPoint = state.accessPoints[bssid];
    ++accessPoint.beaconCount;
    if (antennaSignal) {
        accessPoint.powerDbm = antennaSignal;
    }
    if (dsChannel) {
        accessPoint.channel = dsChannel;
    } else if (htPrimaryChannel) {
        accessPoint.channel = htPrimaryChannel;
    }
    if (foundSsid) {
        accessPoint.essid = std::move(essid);
    }
    if (!privacy) {
        accessPoint.encryption = "OPN";
    } else if (foundRsn && foundWpa) {
        accessPoint.encryption = "WPA/WPA2";
    } else if (foundRsn) {
        accessPoint.encryption = "WPA2";
    } else if (foundWpa) {
        accessPoint.encryption = "WPA";
    } else {
        accessPoint.encryption = "WEP";
    }
}

}  // namespace

void handlePacket(u_char* user, const pcap_pkthdr* header,
                  const u_char* packet) {
    if (user == nullptr || header == nullptr || packet == nullptr) {
        return;
    }

    const std::size_t capturedLength = header->caplen;
    if (capturedLength < kRadiotapMinimumLength) {
        return;
    }

    // Radiotap 헤더는 version(1B) + pad(1B) + length(2B) + present bitmap
    // 순서이므로 length는 offset 2에서 읽는다.
    const std::uint16_t radiotapLength = readLittleEndian16(packet + 2);
    if (radiotapLength < kRadiotapMinimumLength ||
        radiotapLength > capturedLength) {
        return;
    }
    const std::optional<int> antennaSignal =
        parseAntennaSignal(packet, radiotapLength);

    const std::size_t remainingLength = capturedLength - radiotapLength;
    if (remainingLength < kDot11ManagementHeaderLength) {
        return;
    }

    const u_char* dot11 = packet + radiotapLength;
    const std::uint16_t frameControl =
        readLittleEndian16(dot11 + kFrameControlOffset);
    auto& state = *reinterpret_cast<CaptureState*>(user);

    // Frame Control 필드에서 type은 bit 2-3, subtype은 bit 4-7에 위치한다.
    // 이 값으로 관리 프레임(Beacon/Probe Request)과 데이터 프레임을 구분한다.
    const std::uint16_t frameType = frameControl & kTypeMask;

    if (frameType == kDataType) {
        handleDataFrame(state, dot11, frameControl);
        return;
    }

    if (frameType != kManagementType) {
        return;
    }

    const std::uint16_t subtype = frameControl & kSubtypeMask;
    if (subtype == kProbeRequestSubtype) {
        handleProbeRequest(state, dot11, remainingLength);
        return;
    }

    if (subtype != kBeaconSubtype) {
        return;
    }

    handleBeacon(state, dot11, remainingLength, antennaSignal);
}
