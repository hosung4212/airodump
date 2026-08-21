#include <pcap/pcap.h>
#include <ncurses.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "channel_hopper.h"
#include "dot11_frame.h"
#include "types.h"
#include "ui.h"

namespace {

// signal handler 내부에서는 async-signal-safe한 연산만 사용해야 하므로
// 전역 변수로 분리했다. gStopRequested는 sig_atomic_t 타입이라 handler
// 내에서 대입해도 안전하다.
pcap_t* gCaptureHandle = nullptr;
volatile std::sig_atomic_t gStopRequested = 0;

// Ctrl+C가 눌렸을 때 패킷이 들어오지 않으면 pcap_next_ex가 계속 블록될 수
// 있으므로 pcap_breakloop으로 강제로 깨운다. 이 처리가 없으면 다음 패킷이
// 도착할 때까지 종료되지 않는다.
void handleSignal(int) {
    gStopRequested = 1;
    if (gCaptureHandle != nullptr) {
        pcap_breakloop(gCaptureHandle);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <monitor-interface>\n";
        return EXIT_FAILURE;
    }

    std::array<char, PCAP_ERRBUF_SIZE> errorBuffer{};
    pcap_t* handle = pcap_open_live(
        argv[1], BUFSIZ, 1, 100, errorBuffer.data());
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

    gStopRequested = 0;
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
    std::atomic<unsigned int> currentChannel{0};
    std::atomic<int> failedChannel{0};
    std::thread hoppingThread;

    if (initscr() == nullptr) {
        std::cerr << "Failed to initialize ncurses.\n";
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGTERM, SIG_DFL);
        gCaptureHandle = nullptr;
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);  // getch()가 입력이 없을 때 블록하지 않고 즉시 ERR을 반환하도록 설정
    curs_set(0);
    mousemask(ALL_MOUSE_EVENTS, nullptr);

    if (iwPath != nullptr) {
        hoppingThread = std::thread(
            channelHoppingLoop, iwPath, std::string(argv[1]),
            std::cref(keepHopping), std::ref(currentChannel),
            std::ref(failedChannel));
    }

    CaptureState state;
    UiState ui;
    int result = 0;
    std::string captureError;
    // 패킷이 들어올 때마다 매번 다시 그리면 트래픽이 많을 때 화면이 깜빡이고
    // CPU도 낭비되므로, 250ms 간격으로만 실제로 draw한다. 데이터 집계는
    // 그 사이에도 계속 이루어진다.
    auto lastDraw = std::chrono::steady_clock::time_point{};
    while (gStopRequested == 0) {
        pcap_pkthdr* packetHeader = nullptr;
        const u_char* packet = nullptr;
        result = pcap_next_ex(handle, &packetHeader, &packet);
        if (result == 1) {
            handlePacket(reinterpret_cast<u_char*>(&state), packetHeader,
                         packet);
        } else if (result == PCAP_ERROR) {
            captureError = pcap_geterr(handle);
            break;
        } else if (result == PCAP_ERROR_BREAK) {
            break;
        }

        if (processInput(ui, state)) {
            gStopRequested = 1;
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (lastDraw.time_since_epoch().count() == 0 ||
            now - lastDraw >= std::chrono::milliseconds(250)) {
            drawScreen(state, ui, currentChannel.load(), failedChannel.load(),
                       iwPath != nullptr);
            lastDraw = now;
        }
    }

    keepHopping.store(false);
    if (hoppingThread.joinable()) {
        hoppingThread.join();
    }
    endwin();
    if (result == PCAP_ERROR) {
        std::cerr << "pcap_next_ex failed: " << captureError << '\n';
    }

    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
    gCaptureHandle = nullptr;
    pcap_close(handle);
    return result == PCAP_ERROR ? EXIT_FAILURE : EXIT_SUCCESS;
}
