#include "channel_hopper.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <thread>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

// `iw dev <iface> set channel N` 명령을 fork+exec으로 실행한다.
// 별도 라이브러리 없이 iw 바이너리를 직접 호출하는 방식이 가장 단순하다.
bool setChannel(const char* iwPath, const std::string& interfaceName,
                unsigned int channel) {
    const std::string channelText = std::to_string(channel);
    const pid_t child = fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        execl(iwPath, "iw", "dev", interfaceName.c_str(), "set", "channel",
              channelText.c_str(), static_cast<char*>(nullptr));
        _exit(127);  // execl이 실패한 경우에만 도달한다(성공 시에는 프로세스가 대체되어 반환하지 않는다).
    }

    int status = 0;
    pid_t waitResult = 0;
    do {
        waitResult = waitpid(child, &status, 0);
    } while (waitResult < 0 && errno == EINTR);  // 시그널로 인한 중단이면 재시도한다.

    return waitResult == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace

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

void channelHoppingLoop(const char* iwPath, const std::string& interfaceName,
                        const std::atomic<bool>& keepRunning,
                        std::atomic<unsigned int>& currentChannel,
                        std::atomic<int>& failedChannel) {
    constexpr std::array<unsigned int, 3> channels{1, 6, 11};
    constexpr auto dwellTime = std::chrono::milliseconds(500);

    while (keepRunning.load()) {
        for (const unsigned int channel : channels) {
            if (!keepRunning.load()) {
                return;
            }
            if (!setChannel(iwPath, interfaceName, channel)) {
                failedChannel.store(static_cast<int>(channel));
                return;
            }
            currentChannel.store(channel);

            // 500ms를 한 번에 sleep하지 않고 50ms 단위로 나누는 이유는,
            // 프로그램 종료 시 이 스레드가 최대 500ms까지 지연되는 것을
            // 방지하기 위함이다.
            for (int elapsed = 0; elapsed < dwellTime.count(); elapsed += 50) {
                if (!keepRunning.load()) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
}
