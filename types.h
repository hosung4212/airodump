#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

constexpr std::size_t kMacAddressLength = 6;

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
};

enum class ActivePane { AccessPoints, Stations };

struct UiState {
    ActivePane activePane = ActivePane::AccessPoints;
    std::size_t accessPointOffset = 0;
    std::size_t stationOffset = 0;
};
