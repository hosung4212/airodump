#pragma once

#include <atomic>
#include <string>

// /usr/sbin, /usr/bin 두 경로에서만 iw 실행 파일을 찾는다(PATH 전체를
// 파싱하지 않고 일반적인 설치 경로만 확인). 찾지 못하면 nullptr을 반환하며,
// 이 경우 채널 호핑 기능은 비활성화된다.
const char* findIwExecutable();

// 1/6/11 채널을 순회하며 iw로 채널을 전환하고 currentChannel을 갱신한다.
// setChannel이 한 번이라도 실패하면(권한 부족, monitor 모드 미설정 등)
// failedChannel에 실패한 채널 번호를 기록하고 스레드를 종료한다(재시도하지
// 않음). keepRunning이 false가 되면 최대 50ms 이내에 반환하도록 sleep을
// 나누어 처리한다.
void channelHoppingLoop(const char* iwPath, const std::string& interfaceName,
                        const std::atomic<bool>& keepRunning,
                        std::atomic<unsigned int>& currentChannel,
                        std::atomic<int>& failedChannel);
