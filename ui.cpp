#include "ui.h"

#include <ncurses.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "mac_utils.h"

namespace {

void addClippedLine(int row, const std::string& line) {
    if (row >= 0 && row < LINES && COLS > 1) {
        mvaddnstr(row, 0, line.c_str(), COLS - 1);
    }
}

std::string formatAccessPointRow(const MacAddress& bssid,
                                 const AccessPoint& accessPoint) {
    std::ostringstream output;
    output << std::left << std::setw(20) << formatMacAddress(bssid)
           << std::right << std::setw(12) << accessPoint.beaconCount
           << std::setw(10) << accessPoint.dataCount << std::setw(7)
           << (accessPoint.powerDbm ? std::to_string(*accessPoint.powerDbm)
                                    : "?")
           << std::setw(6)
           << (accessPoint.channel ? std::to_string(*accessPoint.channel)
                                   : "?")
           << std::setw(12) << accessPoint.encryption << "  "
           << accessPoint.essid;
    return output.str();
}

std::string formatStationRow(const MacAddress& stationAddress,
                             const Station& station) {
    const std::string bssid = station.associatedBssid
                                  ? formatMacAddress(*station.associatedBssid)
                                  : "(not associated)";
    std::ostringstream output;
    output << std::left << std::setw(20) << bssid << std::setw(20)
           << formatMacAddress(stationAddress) << std::right << std::setw(10)
           << station.frameCount << "  " << station.probedEssid;
    return output.str();
}

// 리스트 항목 수가 줄거나 터미널 리사이즈로 화면이 작아졌을 때 offset이
// 범위를 벗어날 수 있으므로, 매 프레임 그리기 전에 여기서 보정한다.
std::size_t clampOffset(std::size_t offset, std::size_t itemCount,
                        std::size_t visibleRows) {
    if (visibleRows == 0 || itemCount <= visibleRows) {
        return 0;
    }
    return std::min(offset, itemCount - visibleRows);
}

// offset이 unsigned 타입이라 amount를 그대로 빼면 underflow가 발생할 수
// 있으므로 부호에 따라 분기 처리한다.
void moveOffset(std::size_t& offset, std::size_t itemCount, int amount) {
    if (amount < 0) {
        const std::size_t distance = static_cast<std::size_t>(-amount);
        offset = distance > offset ? 0 : offset - distance;
    } else if (amount > 0 && itemCount != 0) {
        offset = std::min(offset + static_cast<std::size_t>(amount),
                          itemCount - 1);
    }
}

}  // namespace

void drawScreen(const CaptureState& state, UiState& ui,
                unsigned int currentChannel, int failedChannel,
                bool iwAvailable) {
    // map은 BSSID 순으로 정렬되어 있으므로 신호 세기 순으로 별도 정렬한다.
    // 매 프레임 map 전체를 복사 후 정렬해 다소 비효율적이지만, AP/Station
    // 수가 많지 않고 250ms마다 한 번만 그리므로 문제되지 않는다고 판단했다.
    std::vector<std::pair<MacAddress, AccessPoint>> accessPoints(
        state.accessPoints.begin(), state.accessPoints.end());
    std::sort(accessPoints.begin(), accessPoints.end(),
              [](const auto& left, const auto& right) {
                  // PWR 정보가 없는 AP는 -1000으로 취급되어 목록 맨 아래로 정렬된다.
                  const int leftPower = left.second.powerDbm.value_or(-1000);
                  const int rightPower = right.second.powerDbm.value_or(-1000);
                  if (leftPower != rightPower) {
                      return leftPower > rightPower;
                  }
                  return left.first < right.first;
              });

    std::vector<std::pair<MacAddress, Station>> stations(
        state.stations.begin(), state.stations.end());
    std::sort(stations.begin(), stations.end(),
              [](const auto& left, const auto& right) {
                  if (left.second.frameCount != right.second.frameCount) {
                      return left.second.frameCount > right.second.frameCount;
                  }
                  return left.first < right.first;
              });

    erase();
    if (LINES < 10 || COLS < 60) {
        addClippedLine(0, "Terminal is too small (minimum 60x10). Resize it.");
        addClippedLine(1, "Press q to quit.");
        refresh();
        return;
    }

    const int statusRow = LINES - 1;
    // 화면 상단 2/3는 AP 목록, 하단 1/3은 Station 목록에 할당한다.
    // AP 정보가 상대적으로 중요도가 높아 더 넓은 영역을 준다. 최소 4줄은
    // 확보해 헤더와 항목이 한 줄이라도 보이도록 한다.
    const int accessPointSectionHeight = std::max(4, statusRow * 2 / 3);
    const int stationStartRow = accessPointSectionHeight;
    const int accessPointVisibleRows = accessPointSectionHeight - 2;
    const int stationVisibleRows = statusRow - stationStartRow - 2;

    ui.accessPointOffset = clampOffset(
        ui.accessPointOffset, accessPoints.size(),
        static_cast<std::size_t>(accessPointVisibleRows));
    ui.stationOffset = clampOffset(
        ui.stationOffset, stations.size(),
        static_cast<std::size_t>(std::max(0, stationVisibleRows)));

    std::ostringstream title;
    title << " Access Points [" << accessPoints.size() << "] ";
    if (ui.activePane == ActivePane::AccessPoints) {
        attron(A_REVERSE);
    }
    addClippedLine(0, title.str());
    if (ui.activePane == ActivePane::AccessPoints) {
        attroff(A_REVERSE);
    }
    addClippedLine(1,
        "BSSID                   Beacons     #Data    PWR    CH         ENC  ESSID");
    for (int row = 0; row < accessPointVisibleRows; ++row) {
        const std::size_t index = ui.accessPointOffset +
                                  static_cast<std::size_t>(row);
        if (index >= accessPoints.size()) {
            break;
        }
        const auto& [bssid, accessPoint] = accessPoints[index];
        addClippedLine(row + 2, formatAccessPointRow(bssid, accessPoint));
    }

    title.str("");
    title.clear();
    title << " Stations [" << stations.size() << "] ";
    if (ui.activePane == ActivePane::Stations) {
        attron(A_REVERSE);
    }
    addClippedLine(stationStartRow, title.str());
    if (ui.activePane == ActivePane::Stations) {
        attroff(A_REVERSE);
    }
    addClippedLine(stationStartRow + 1,
                   "BSSID               STATION                 Frames  Probes");
    for (int row = 0; row < stationVisibleRows; ++row) {
        const std::size_t index = ui.stationOffset +
                                  static_cast<std::size_t>(row);
        if (index >= stations.size()) {
            break;
        }
        const auto& [stationAddress, station] = stations[index];
        addClippedLine(stationStartRow + 2 + row,
                       formatStationRow(stationAddress, station));
    }

    std::ostringstream status;
    status << " Tab: pane  Up/Down/PgUp/PgDn or mouse wheel: scroll  q: quit";
    if (!iwAvailable) {
        status << "  | iw not found: fixed channel";
    } else if (failedChannel != 0) {
        status << "  | hopping stopped at CH " << failedChannel;
    } else if (currentChannel != 0) {
        status << "  | hopping CH " << currentChannel;
    }
    attron(A_REVERSE);
    addClippedLine(statusRow, status.str());
    attroff(A_REVERSE);
    refresh();
}

bool processInput(UiState& ui, const CaptureState& state) {
    bool quit = false;
    int key = 0;
    while ((key = getch()) != ERR) {
        if (key == 'q' || key == 'Q') {
            quit = true;
            continue;
        }
        if (key == '\t') {
            ui.activePane = ui.activePane == ActivePane::AccessPoints
                                ? ActivePane::Stations
                                : ActivePane::AccessPoints;
            continue;
        }

        if (key == KEY_MOUSE) {
            MEVENT event{};
            if (getmouse(&event) == OK) {
                // stationStart 계산식은 drawScreen의 accessPointSectionHeight와
                // 반드시 동일하게 맞춰야 한다. 그렇지 않으면 마우스 위치로
                // 판단하는 pane 경계와 실제 화면 경계가 어긋난다.
                const int stationStart = std::max(4, (LINES - 1) * 2 / 3);
                ui.activePane = event.y >= stationStart
                                    ? ActivePane::Stations
                                    : ActivePane::AccessPoints;
                // ncurses에는 별도의 스크롤 이벤트가 없으므로, 마우스 버튼
                // 4/5번을 휠 업/다운으로 취급하는 일반적인 관례를 사용한다.
                const int amount = (event.bstate & BUTTON4_PRESSED) != 0
                                       ? -3
                                   : (event.bstate & BUTTON5_PRESSED) != 0
                                       ? 3
                                       : 0;
                if (ui.activePane == ActivePane::AccessPoints) {
                    moveOffset(ui.accessPointOffset,
                               state.accessPoints.size(), amount);
                } else {
                    moveOffset(ui.stationOffset, state.stations.size(), amount);
                }
            }
            continue;
        }

        std::size_t* offset = ui.activePane == ActivePane::AccessPoints
                                  ? &ui.accessPointOffset
                                  : &ui.stationOffset;
        const std::size_t itemCount = ui.activePane == ActivePane::AccessPoints
                                          ? state.accessPoints.size()
                                          : state.stations.size();
        const int pageSize = ui.activePane == ActivePane::AccessPoints
                                 ? std::max(1, (LINES - 1) * 2 / 3 - 2)
                                 : std::max(1, (LINES - 1) / 3 - 2);
        if (key == KEY_UP) {
            moveOffset(*offset, itemCount, -1);
        } else if (key == KEY_DOWN) {
            moveOffset(*offset, itemCount, 1);
        } else if (key == KEY_PPAGE) {
            moveOffset(*offset, itemCount, -pageSize);
        } else if (key == KEY_NPAGE) {
            moveOffset(*offset, itemCount, pageSize);
        } else if (key == KEY_HOME) {
            *offset = 0;
        } else if (key == KEY_END) {
            *offset = itemCount == 0 ? 0 : itemCount - 1;
        }
    }
    return quit;
}
