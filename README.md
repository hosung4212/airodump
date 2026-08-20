# airodump

`airodump-ng`와 비슷한 형태로 주변 무선 AP와 Station 정보를 출력하는
IEEE 802.11 모니터링 프로그램입니다.

## 실행 영상

[airodump.mp4](./airodump.mp4)


## 의존성 설치

Ubuntu, Debian, Kali Linux에서 다음 명령으로 필요한 패키지를 설치합니다.

```bash
sudo apt update
sudo apt install build-essential libpcap-dev libncurses-dev iw
```

프로그램 실행에는 모니터 모드를 지원하는 무선 네트워크 어댑터와 드라이버가
필요합니다.

## 빌드

```bash
make
```

빌드가 완료되면 현재 디렉터리에 `airodump` 실행 파일이 생성됩니다.

빌드 결과를 삭제하려면 다음 명령을 사용합니다.

```bash
make clean
```

## 모니터 모드 설정

먼저 무선 인터페이스 이름을 확인합니다.

```bash
iw dev
```

아래 예시는 인터페이스 이름이 `wlan0`인 경우입니다. 모니터 모드로 변경하면
해당 인터페이스의 일반 Wi-Fi 연결이 끊길 수 있습니다.

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

다음 명령의 출력에 `type monitor`가 표시되는지 확인합니다.

```bash
iw dev wlan0 info
```

환경에 따라 모니터 모드로 전환된 인터페이스 이름이 `mon0` 또는 `wlan0mon`처럼
달라질 수 있습니다.

## 실행

```text
syntax : sudo ./airodump <interface>
sample : sudo ./airodump mon0
```

실행 예시는 다음과 같습니다.

```bash
sudo ./airodump wlan0
```

프로그램은 Radiotap 헤더가 포함된 IEEE 802.11 패킷을 제공하는 인터페이스만
사용할 수 있습니다.

## 조작법

- `Tab`: AP 목록과 Station 목록 전환
- `Up` / `Down`: 한 줄 스크롤
- `Page Up` / `Page Down`: 페이지 단위 스크롤
- 마우스 휠: 목록 스크롤
- `q`: 종료

## 일반 모드로 복구

사용이 끝난 뒤 인터페이스를 일반 managed 모드로 되돌릴 수 있습니다.

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
```
