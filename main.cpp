#include <pcap/pcap.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

pcap_t* gCaptureHandle = nullptr;

constexpr std::size_t kRadiotapMinimumLength = 8;
constexpr std::size_t kDot11ManagementHeaderLength = 24;
constexpr std::size_t kBeaconFixedParametersLength = 12;
constexpr std::size_t kFrameControlOffset = 0;
constexpr std::size_t kBssidOffset = 16;
constexpr std::size_t kMacAddressLength = 6;
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
constexpr std::size_t kCapabilityOffset =
    kDot11ManagementHeaderLength + 10;

using MacAddress = std::array<std::uint8_t, kMacAddressLength>;

struct AccessPoint {
    std::uint64_t beaconCount = 0;
    std::uint64_t dataCount = 0;
    std::optional<int> powerDbm;
    std::optional<unsigned int> channel;
    std::string encryption = "?";
    std::string essid = "<unknown>";
};

struct Station {
    std::optional<MacAddress> associatedBssid;
    std::uint64_t frameCount = 0;
    std::string probedEssid;
};

struct CaptureState {
    std::map<MacAddress, AccessPoint> accessPoints;
    std::map<MacAddress, Station> stations;
    std::chrono::steady_clock::time_point lastDisplay{};
};

void handleSignal(int) {
    if (gCaptureHandle != nullptr) {
        pcap_breakloop(gCaptureHandle);
    }
}

const char* findIwExecutable() {
    constexpr std::array<const char*, 2> candidates{
        "/usr/sbin/iw", "/usr/bin/iw"};
    for (const char* candidate : candidates) {
        if (access(candidate, X_OK) == 0) {
            return candidate;
        }
    }
    return nullptr;
}

bool setChannel(const char* iwPath, const std::string& interfaceName,
                unsigned int channel) {
    const std::string channelText = std::to_string(channel);
    const pid_t child = fork();
    if (child < 0) {
        std::cerr << "fork for iw failed\n";
        return false;
    }
    if (child == 0) {
        execl(iwPath, "iw", "dev", interfaceName.c_str(), "set", "channel",
              channelText.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    pid_t waitResult = 0;
    do {
        waitResult = waitpid(child, &status, 0);
    } while (waitResult < 0 && errno == EINTR);

    return waitResult == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void channelHoppingLoop(const char* iwPath, const std::string& interfaceName,
                        const std::atomic<bool>& keepRunning) {
    constexpr std::array<unsigned int, 3> channels{1, 6, 11};
    constexpr auto dwellTime = std::chrono::milliseconds(500);

    while (keepRunning.load()) {
        for (const unsigned int channel : channels) {
            if (!keepRunning.load()) {
                return;
            }
            if (!setChannel(iwPath, interfaceName, channel)) {
                std::cerr << "Channel hopping stopped: iw could not set channel "
                          << channel << ". Packet capture will continue.\n";
                return;
            }

            // 짧게 나눠 자면 종료 요청에 최대 50ms 안에 반응할 수 있다.
            for (int elapsed = 0; elapsed < dwellTime.count(); elapsed += 50) {
                if (!keepRunning.load()) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
}

// Radiotap의 모든 필드는 little-endian이다. 정렬되지 않은 메모리를
// uint16_t*로 캐스팅하지 않고 바이트 단위로 읽어 UB를 피한다.
std::uint16_t readLittleEndian16(const u_char* data) {
    return static_cast<std::uint16_t>(data[0]) |
           (static_cast<std::uint16_t>(data[1]) << 8);
}

std::uint32_t readLittleEndian32(const u_char* data) {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

// Radiotap field의 alignment는 Radiotap 헤더 시작점을 기준으로 한다.
std::size_t alignOffset(std::size_t offset, std::size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

std::optional<int> parseAntennaSignal(const u_char* radiotap,
                                      std::size_t radiotapLength) {
    if (radiotap == nullptr || radiotapLength < kRadiotapMinimumLength ||
        radiotap[0] != 0) {
        return std::nullopt;
    }

    // 모든 extended present word 다음에서 실제 필드들이 시작한다.
    std::size_t fieldOffset = 4;
    std::uint32_t firstPresentWord = 0;
    bool firstWord = true;
    std::uint32_t presentWord = 0;
    do {
        if (fieldOffset > radiotapLength ||
            radiotapLength - fieldOffset < sizeof(std::uint32_t)) {
            return std::nullopt;
        }
        presentWord = readLittleEndian32(radiotap + fieldOffset);
        if (firstWord) {
            firstPresentWord = presentWord;
            firstWord = false;
        }
        fieldOffset += sizeof(std::uint32_t);
    } while ((presentWord & 0x80000000U) != 0);

    constexpr std::uint32_t kAntennaSignalPresent = 1U << 5;
    if ((firstPresentWord & kAntennaSignalPresent) == 0) {
        return std::nullopt;
    }

    struct FieldLayout {
        std::uint32_t presentBit;
        std::size_t alignment;
        std::size_t size;
    };
    // Antenna signal(bit 5)보다 앞에 올 수 있는 표준 필드들이다.
    constexpr std::array<FieldLayout, 5> precedingFields{{
        {1U << 0, 8, 8},  // TSFT
        {1U << 1, 1, 1},  // Flags
        {1U << 2, 1, 1},  // Rate
        {1U << 3, 2, 4},  // Channel
        {1U << 4, 2, 2},  // FHSS
    }};

    for (const FieldLayout& field : precedingFields) {
        if ((firstPresentWord & field.presentBit) == 0) {
            continue;
        }
        fieldOffset = alignOffset(fieldOffset, field.alignment);
        if (fieldOffset > radiotapLength ||
            field.size > radiotapLength - fieldOffset) {
            return std::nullopt;
        }
        fieldOffset += field.size;
    }

    if (fieldOffset >= radiotapLength) {
        return std::nullopt;
    }
    const int rawSignal = radiotap[fieldOffset];
    return rawSignal < 128 ? rawSignal : rawSignal - 256;
}

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

void displayAccessPoints(CaptureState& state) {
    const auto now = std::chrono::steady_clock::now();
    if (state.lastDisplay.time_since_epoch().count() != 0 &&
        now - state.lastDisplay < std::chrono::milliseconds(250)) {
        return;
    }
    state.lastDisplay = now;

    std::cout << "\033[2J\033[H"
              << std::left << std::setw(20) << "BSSID"
              << std::right << std::setw(12) << "Beacons"
              << std::setw(10) << "#Data"
              << std::setw(7) << "PWR"
              << std::setw(6) << "CH"
              << std::setw(12) << "ENC"
              << "  ESSID\n";
    for (const auto& [bssid, accessPoint] : state.accessPoints) {
        std::cout << std::left << std::setw(20) << formatMacAddress(bssid)
                  << std::right << std::setw(12) << accessPoint.beaconCount
                  << std::setw(10) << accessPoint.dataCount
                  << std::setw(7)
                  << (accessPoint.powerDbm
                          ? std::to_string(*accessPoint.powerDbm)
                          : "?")
                  << std::setw(6)
                  << (accessPoint.channel
                          ? std::to_string(*accessPoint.channel)
                          : "?")
                  << std::setw(12) << accessPoint.encryption
                  << "  " << accessPoint.essid << '\n';
    }
    std::cout << "\n"
              << std::left << std::setw(20) << "BSSID"
              << std::setw(20) << "STATION"
              << std::right << std::setw(10) << "Frames"
              << "  Probes\n";
    for (const auto& [stationAddress, station] : state.stations) {
        const std::string bssid = station.associatedBssid
                                      ? formatMacAddress(*station.associatedBssid)
                                      : "(not associated)";
        std::cout << std::left << std::setw(20) << bssid
                  << std::setw(20) << formatMacAddress(stationAddress)
                  << std::right << std::setw(10) << station.frameCount
                  << "  " << station.probedEssid << '\n';
    }
    std::cout << std::flush;
}

void handlePacket(u_char* user, const pcap_pkthdr* header,
                  const u_char* packet) {
    if (user == nullptr || header == nullptr || packet == nullptr) {
        return;
    }

    const std::size_t capturedLength = header->caplen;
    if (capturedLength < kRadiotapMinimumLength) {
        return;
    }

    // Radiotap: version(1), pad(1), length(2), present bitmap(4 이상).
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

    // Frame Control: bits 2..3 = type, bits 4..7 = subtype.
    const std::uint16_t frameType = frameControl & kTypeMask;

    if (frameType == kDataType) {
        const bool toDs = (frameControl & kToDsBit) != 0;
        const bool fromDs = (frameControl & kFromDsBit) != 0;
        if (toDs && fromDs) {
            return;  // WDS frame에는 단일 BSSID 필드가 없다.
        }

        // addr1=offset 4, addr2=offset 10, addr3=offset 16.
        const std::size_t dataBssidOffset = toDs ? 4 : (fromDs ? 10 : 16);
        const std::size_t stationOffset = toDs ? 10 : (fromDs ? 4 : 10);
        const MacAddress bssid = readMacAddress(dot11 + dataBssidOffset);
        const MacAddress stationAddress =
            readMacAddress(dot11 + stationOffset);
        const auto accessPoint = state.accessPoints.find(bssid);
        if (accessPoint != state.accessPoints.end()) {
            // subtype bit 6이 설정된 Null/CF 계열에는 payload가 없다.
            if ((frameControl & kNoDataSubtypeBit) == 0) {
                ++accessPoint->second.dataCount;
            }
            if (isUnicastAddress(stationAddress)) {
                Station& station = state.stations[stationAddress];
                station.associatedBssid = bssid;
                ++station.frameCount;
            }
            displayAccessPoints(state);
        }
        return;
    }

    if (frameType != kManagementType) {
        return;
    }

    const std::uint16_t subtype = frameControl & kSubtypeMask;
    if (subtype == kProbeRequestSubtype) {
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
        displayAccessPoints(state);
        return;
    }

    if (subtype != kBeaconSubtype) {
        return;
    }

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
            break;  // 잘린 IE의 payload를 읽지 않는다.
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
            // Microsoft OUI 00:50:f2, vendor type 1은 WPA IE이다.
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
    displayAccessPoints(state);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <monitor-interface>\n";
        return EXIT_FAILURE;
    }

    std::array<char, PCAP_ERRBUF_SIZE> errorBuffer{};
    pcap_t* handle = pcap_open_live(
        argv[1], BUFSIZ, 1, 1000, errorBuffer.data());
    if (handle == nullptr) {
        std::cerr << "pcap_open_live failed: " << errorBuffer.data() << '\n';
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "Error: interface does not provide Radiotap/802.11 packets "
                     "(DLT_IEEE802_11_RADIO required).\n";
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    gCaptureHandle = handle;
    if (std::signal(SIGINT, handleSignal) == SIG_ERR ||
        std::signal(SIGTERM, handleSignal) == SIG_ERR) {
        std::cerr << "Failed to install signal handler.\n";
        gCaptureHandle = nullptr;
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    const char* iwPath = findIwExecutable();
    std::atomic<bool> keepHopping{true};
    std::thread hoppingThread;
    if (iwPath != nullptr) {
        hoppingThread = std::thread(
            channelHoppingLoop, iwPath, std::string(argv[1]),
            std::cref(keepHopping));
    } else {
        std::cerr << "Warning: iw was not found; capturing on the current "
                     "channel only. Install it with: sudo apt install iw\n";
    }

    CaptureState state;
    std::cout << "Listening on " << argv[1] << "...\n";
    const int result = pcap_loop(
        handle, 0, handlePacket, reinterpret_cast<u_char*>(&state));

    keepHopping.store(false);
    if (hoppingThread.joinable()) {
        hoppingThread.join();
    }
    if (result == PCAP_ERROR) {
        std::cerr << "pcap_loop failed: " << pcap_geterr(handle) << '\n';
    }

    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
    gCaptureHandle = nullptr;
    pcap_close(handle);
    return result == PCAP_ERROR ? EXIT_FAILURE : EXIT_SUCCESS;
}
