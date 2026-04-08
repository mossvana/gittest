#ifndef BEHAVIOR_MONITOR_H
#define BEHAVIOR_MONITOR_H

typedef void (*scan_callback_t)(const char *filepath);

// 지정 디렉터리를 실시간 감시 (블로킹 함수 — 별도 스레드 권장)
// 반환값: 0=정상 종료, -1=초기화 실패
int start_behavior_monitor(const char *watch_dir, scan_callback_t on_suspicious); // 인자 추가

#endif
