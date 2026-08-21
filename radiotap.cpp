#include "radiotap.h"

#include <array>
#include <cstdint>

#include "byte_utils.h"

namespace {

// Radiotap 필드의 정렬 기준점은 Radiotap 헤더의 시작(offset 0)이다.
// 따라서 지금까지 읽은 offset을 이 기준에 맞춰 재정렬해야 한다.
std::size_t alignOffset(std::size_t offset, std::size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

}  // namespace

std::optional<int> parseAntennaSignal(const u_char* radiotap,
                                      std::size_t radiotapLength) {
    if (radiotap == nullptr || radiotapLength < kRadiotapMinimumLength ||
        radiotap[0] != 0) {
        return std::nullopt;
    }

    // present word의 최상위 비트(0x80000000)가 설정되어 있으면 다음
    // present word가 이어진다는 뜻이므로 계속 읽는다. 실제 필드 데이터는
    // 이 present word들을 모두 지난 뒤부터 시작된다.
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
    // 필드들은 present bitmap의 비트 순서대로 앞에서부터 배치되므로,
    // Antenna Signal(bit 5)보다 앞에 위치할 수 있는 필드들은 모두 건너뛴다.
    // 필요한 값은 PWR 하나뿐이라 그 이후 필드는 다루지 않는다.
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
