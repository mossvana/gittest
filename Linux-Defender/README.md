# Linux Defender (리눅스 로컬 보안 백신 엔진)

**Linux Defender**는 C 언어로 개발된 경량화된 다계층 정적 분석 및 악성코드 탐지 엔진입니다. 
단순한 서명 기반 탐지를 넘어, VirusTotal 위협 인텔리전스, YARA 엔진, 그리고 정규표현식을 활용한 C2(명령 제어) 서버 통신 패턴 분석까지 하나의 파이프라인으로 통합하여 제공합니다.

## 주요 기능 (Core Features)

1. **[1단계] SHA256 해시 기반 무결성 검사**
   - 검사 대상 파일의 고유한 SHA256 해시값을 실시간으로 계산합니다.
2. **[2단계] VirusTotal API 연동 (Threat Intelligence)**
   - 추출된 해시값을 전 세계 최대 악성코드 데이터베이스인 VirusTotal에 조회하여 기존에 알려진 위협인지 즉시 판별합니다.
3. **[3단계] YARA 엔진 정밀 스캔 (로컬 시그니처 분석)**
   - `libyara`를 엔진 내부에 통합하여, VT DB에 없는 신종/변종 악성코드라도 내부의 악성 행위 패턴(웹셸, 백도어 등)을 분석해 잡아냅니다.
4. **[4단계] IP/URL 정규식 추출 및 블랙리스트 대조**
   - 파일 내부에 숨겨진 악성 C2 서버의 IP 주소나 URL 패턴을 정규표현식(Regex)으로 모두 추출한 뒤, 내부 블랙리스트와 대조하여 네트워크 탈취 시도를 사전 경고합니다.

## 🛠️ 개발 환경 및 의존성 (Prerequisites)

이 프로젝트를 빌드하고 실행하려면 아래의 라이브러리가 필요합니다.

* `GCC` (C 컴파일러)
* `libyara-dev` (YARA 엔진 스캐닝)
* `libcurl` / `jansson` (VirusTotal API 통신 및 JSON 파싱)
* `libssl-dev` (SHA256 해시 계산)

```bash
# Ubuntu/Debian 계열 라이브러리 설치 명령어
sudo apt update
sudo apt install build-essential libyara-dev libcurl4-openssl-dev libssl-dev libjansson-dev

# 1. 프로젝트 빌드
make

# 2. 특정 파일 정적 스캔 (scan 모드)
./linux-defender scan [검사할_파일_경로]

# 3. 감시 모드
# 루트 권한 필요 (inotify + /proc 접근)
sudo ./linux-defender monitor /home/user
