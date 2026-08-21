#pragma once

#include "types.h"

// 지금까지 수집한 AP/Station 정보를 ncurses 화면에 그린다. AP는 신호 세기
// 순, Station은 프레임 수 순으로 매 호출마다 다시 정렬한다(airodump-ng와
// 동일한 방식). 리스트 크기가 줄어 스크롤 offset이 범위를 벗어나면 내부에서
// 자동으로 clamp한다.
void drawScreen(const CaptureState& state, UiState& ui,
                unsigned int currentChannel, int failedChannel,
                bool iwAvailable);

// getch()로 대기 중인 입력을 모두 소진하며 ui를 갱신한다(한 프레임 내 여러
// 입력이 누락되지 않도록). q/Q가 입력되면 true를 반환하며, 메인 루프에서는
// 이를 받아 종료 처리한다.
bool processInput(UiState& ui, const CaptureState& state);
