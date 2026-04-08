#define _GNU_SOURCE
#include "behavior_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <math.h>
#include <time.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

/* ═══════════════════════════════════════════════
 * 설정 상수
 * ═══════════════════════════════════════════════ */
#define RATE_THRESHOLD       20       /* 초당 이벤트 임계값                  */
#define ENTROPY_THRESHOLD    7.5      /* 엔트로피 절대값 기준                */
#define ENTROPY_DELTA        2.0      /* before→after 엔트로피 급상승 기준  */
#define ENTROPY_SAMPLE_BYTES 1024     /* 샘플 크기 1KB                       */
#define DECOY_FILENAME       ".decoy_sentinel.docx"
#define DECOY_CONTENT        "SENTINEL_DECOY_FILE - DO NOT TOUCH\n"
#define MAX_WATCHES          1024     /* 최대 inotify watch 수               */
#define MAX_FILE_RECORDS     2048     /* before 엔트로피 캐시 크기           */
#define MAX_PID_RECORDS      256      /* PID별 파일 카운트 테이블            */
#define PID_CACHE_SIZE       64       /* PID 경로 캐시 크기                  */
#define PID_CACHE_TTL        5        /* 캐시 유효 시간(초)                  */
#define EVENT_BUF_LEN        (4096 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define INOTIFY_MASK         (IN_MODIFY | IN_DELETE | IN_MOVED_FROM \
                              | IN_CREATE | IN_MOVED_TO | IN_ISDIR)

/* ─── 터미널 색상 ─── */
#define RED    "\033[1;31m"
#define YELLOW "\033[1;33m"
#define GREEN  "\033[1;32m"
#define CYAN   "\033[1;36m"
#define RESET  "\033[0m"

/* ═══════════════════════════════════════════════
 * 데이터 구조
 * ═══════════════════════════════════════════════ */

/* [개선 3] before/after 엔트로피 비교용 파일 레코드 */
typedef struct {
    char   path[PATH_MAX];
    double entropy_before;
    time_t recorded_at;
    int    valid;
} FileRecord;

/* [개선 2] PID별 파일 수정 횟수 추적 */
typedef struct {
    pid_t pid;
    int   file_count;
    time_t first_seen;
    int   valid;
} PidRecord;

/* [개선 6] PID→경로 매핑 캐시 */
typedef struct {
    char   filepath[PATH_MAX];
    pid_t  pid;
    time_t cached_at;
    int    valid;
} PidCache;

/* ═══════════════════════════════════════════════
 * 전역 상태
 * ═══════════════════════════════════════════════ */
static int      g_inotify_fd              = -1;
static volatile sig_atomic_t g_running   = 1;
static time_t   g_window_start           = 0;
static int      g_event_count            = 0;
static char     g_watch_dir[PATH_MAX];
static FILE    *g_log_fp                 = NULL;
static scan_callback_t g_scan_callback = NULL;  // 콜백 저장용 전역변수 추가

/* 테이블들 */
static FileRecord g_file_records[MAX_FILE_RECORDS];
static PidRecord  g_pid_records[MAX_PID_RECORDS];
static PidCache   g_pid_cache[PID_CACHE_SIZE];

/* watch descriptor → 경로 매핑 (재귀 watch용) */
static int  g_watch_fds[MAX_WATCHES];
static char g_watch_paths[MAX_WATCHES][PATH_MAX];
static int  g_watch_count = 0;

/* ═══════════════════════════════════════════════
 * 안전하지 않은 확장자 목록 (빌드/개발 파일 제외)
 * ═══════════════════════════════════════════════ */

/* [개선 2] 빌드 도구가 자주 건드리는 확장자 → Rate Limit 제외 */
static const char *SAFE_EXTENSIONS[] = {
    ".c", ".h", ".cpp", ".cc", ".hpp",
    ".o", ".a", ".so", ".d",
    ".py", ".pyc", ".go", ".rs",
    ".class", ".jar",
    ".log", ".tmp", ".swp",
    ".git", ".gitignore",
    NULL
};

/* [개선 3] 랜섬웨어가 붙이는 확장자 */
static const char *RANSOM_EXTENSIONS[] = {
    ".locked", ".encrypted", ".crypto", ".enc",
    ".pays", ".crypt", ".vault", ".cerber",
    ".locky", ".zepto", ".thor", ".aesir",
    ".zzzzz", ".fun", ".xxx",
    NULL
};

/* ═══════════════════════════════════════════════
 * 유틸리티
 * ═══════════════════════════════════════════════ */

static int is_safe_extension(const char *name)
{
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    for (int i = 0; SAFE_EXTENSIONS[i]; i++)
        if (strcasecmp(ext, SAFE_EXTENSIONS[i]) == 0) return 1;
    return 0;
}

static int has_ransom_extension(const char *name)
{
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    for (int i = 0; RANSOM_EXTENSIONS[i]; i++)
        if (strcasecmp(ext, RANSOM_EXTENSIONS[i]) == 0) return 1;
    return 0;
}

/* JSON 로그 한 줄 기록 */
static void log_json(const char *event_type, pid_t pid,
                     const char *filepath, double entropy)
{
    if (!g_log_fp) return;
    time_t now = time(NULL);
    char tbuf[32];
    struct tm *tm_info = localtime(&now);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", tm_info);

    fprintf(g_log_fp,
        "{\"time\":\"%s\",\"event\":\"%s\","
        "\"pid\":%d,\"file\":\"%s\",\"entropy\":%.4f}\n",
        tbuf, event_type, pid, filepath, entropy);
    fflush(g_log_fp);
}

/* ═══════════════════════════════════════════════
 * [개선 3] 섀넌 엔트로피 계산
 * ═══════════════════════════════════════════════ */
static double calculate_entropy(const char *filepath)
{
    uint8_t  buf[ENTROPY_SAMPLE_BYTES];
    uint64_t freq[256] = {0};
    double   entropy   = 0.0;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1.0;
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (n == 0) return 0.0;

    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)n;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* FileRecord 테이블 — before 엔트로피 저장/조회 */
static void record_entropy_before(const char *path, double entropy)
{
    int empty_slot = -1;
    for (int i = 0; i < MAX_FILE_RECORDS; i++) {
        if (!g_file_records[i].valid) { if (empty_slot < 0) empty_slot = i; continue; }
        if (strcmp(g_file_records[i].path, path) == 0) {
            g_file_records[i].entropy_before = entropy;
            g_file_records[i].recorded_at    = time(NULL);
            return;
        }
    }
    if (empty_slot >= 0) {
        strncpy(g_file_records[empty_slot].path, path, PATH_MAX - 1);
        g_file_records[empty_slot].entropy_before = entropy;
        g_file_records[empty_slot].recorded_at    = time(NULL);
        g_file_records[empty_slot].valid           = 1;
    }
}

/* 반환: before 엔트로피(-1.0 = 기록 없음) */
static double get_entropy_before(const char *path)
{
    for (int i = 0; i < MAX_FILE_RECORDS; i++) {
        if (g_file_records[i].valid &&
            strcmp(g_file_records[i].path, path) == 0)
            return g_file_records[i].entropy_before;
    }
    return -1.0;
}

/* ═══════════════════════════════════════════════
 * [개선 1] PID 추적 — realpath + inode 비교
 * ═══════════════════════════════════════════════ */

/* inode/device 구조체 */
typedef struct { ino_t ino; dev_t dev; int valid; } Inode;

static Inode get_inode(const char *path)
{
    Inode r = {0, 0, 0};
    struct stat st;
    if (stat(path, &st) == 0) {
        r.ino   = st.st_ino;
        r.dev   = st.st_dev;
        r.valid = 1;
    }
    return r;
}

/* [개선 6] PID 캐시 조회 */
static pid_t lookup_pid_cache(const char *filepath)
{
    time_t now = time(NULL);
    for (int i = 0; i < PID_CACHE_SIZE; i++) {
        if (!g_pid_cache[i].valid) continue;
        if (now - g_pid_cache[i].cached_at > PID_CACHE_TTL) {
            g_pid_cache[i].valid = 0; continue;
        }
        if (strcmp(g_pid_cache[i].filepath, filepath) == 0)
            return g_pid_cache[i].pid;
    }
    return -1;
}

static void store_pid_cache(const char *filepath, pid_t pid)
{
    int slot = 0;
    time_t oldest = time(NULL);
    for (int i = 0; i < PID_CACHE_SIZE; i++) {
        if (!g_pid_cache[i].valid) { slot = i; break; }
        if (g_pid_cache[i].cached_at < oldest) {
            oldest = g_pid_cache[i].cached_at; slot = i;
        }
    }
    strncpy(g_pid_cache[slot].filepath, filepath, PATH_MAX - 1);
    g_pid_cache[slot].pid       = pid;
    g_pid_cache[slot].cached_at = time(NULL);
    g_pid_cache[slot].valid     = 1;
}

/* /proc 순회로 PID 탐색 — realpath() + inode 이중 비교 */
static pid_t find_pid_accessing(const char *filepath)
{
    /* 캐시 먼저 확인 */
    pid_t cached = lookup_pid_cache(filepath);
    if (cached > 1) return cached;

    /* 목표 파일의 inode 얻기 */
    char real_filepath[PATH_MAX] = {0};
    if (!realpath(filepath, real_filepath))
        strncpy(real_filepath, filepath, PATH_MAX - 1);
    Inode target_inode = get_inode(real_filepath);

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;

    struct dirent *proc_entry;
    char   fd_dir[PATH_MAX];
    char   link_target[PATH_MAX];
    char   real_target[PATH_MAX];
    pid_t  found_pid = -1;

    while ((proc_entry = readdir(proc_dir)) != NULL) {
        pid_t pid = (pid_t)atoi(proc_entry->d_name);
        if (pid <= 1) continue;

        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
        DIR *fd_dir_p = opendir(fd_dir);
        if (!fd_dir_p) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir_p)) != NULL) {
            char fd_link[PATH_MAX];
            snprintf(fd_link, sizeof(fd_link), "/proc/%d/fd/%s",
                     pid, fd_entry->d_name);

            ssize_t len = readlink(fd_link, link_target, sizeof(link_target) - 1);
            if (len <= 0) continue;
            link_target[len] = '\0';

            /* [개선 1] 방법 A: realpath 정규화 후 문자열 비교 */
            if (realpath(link_target, real_target)) {
                if (strcmp(real_target, real_filepath) == 0) {
                    found_pid = pid; break;
                }
            }

            /* [개선 1] 방법 B: inode 번호 비교 (심볼릭/하드링크 케이스) */
            if (target_inode.valid) {
                Inode link_inode = get_inode(link_target);
                if (link_inode.valid &&
                    link_inode.ino == target_inode.ino &&
                    link_inode.dev == target_inode.dev) {
                    found_pid = pid; break;
                }
            }
        }
        closedir(fd_dir_p);
        if (found_pid != -1) break;
    }
    closedir(proc_dir);

    if (found_pid > 1) store_pid_cache(filepath, found_pid);
    return found_pid;
}

/* 프로세스 이름 읽기 */
static void get_proc_name(pid_t pid, char *buf, size_t buflen)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) { snprintf(buf, buflen, "unknown"); return; }
    if (fgets(buf, (int)buflen, fp)) {
        size_t l = strlen(buf);
        if (l > 0 && buf[l-1] == '\n') buf[l-1] = '\0';
    }
    fclose(fp);
}

/* ═══════════════════════════════════════════════
 * [개선 2] PID별 파일 카운트 추적
 * ═══════════════════════════════════════════════ */
static int increment_pid_count(pid_t pid)
{
    int empty_slot = -1;
    for (int i = 0; i < MAX_PID_RECORDS; i++) {
        if (!g_pid_records[i].valid) { if (empty_slot < 0) empty_slot = i; continue; }
        if (g_pid_records[i].pid == pid) {
            g_pid_records[i].file_count++;
            return g_pid_records[i].file_count;
        }
    }
    if (empty_slot >= 0) {
        g_pid_records[empty_slot].pid        = pid;
        g_pid_records[empty_slot].file_count = 1;
        g_pid_records[empty_slot].first_seen = time(NULL);
        g_pid_records[empty_slot].valid      = 1;
        return 1;
    }
    return 1;
}

static int get_pid_file_count(pid_t pid)
{
    for (int i = 0; i < MAX_PID_RECORDS; i++)
        if (g_pid_records[i].valid && g_pid_records[i].pid == pid)
            return g_pid_records[i].file_count;
    return 0;
}

/* ═══════════════════════════════════════════════
 * [개선 5] 위협 대응 — SIGSTOP → 분석 → 결정
 * ═══════════════════════════════════════════════ */
static void respond_to_threat(const char *reason, const char *filepath,
                               double entropy)
{
    fprintf(stderr,
        "\n" RED
        "╔══════════════════════════════════════════════╗\n"
        "║       ⚠  긴급 경고: 랜섬웨어 행위 탐지  ⚠      ║\n"
        "╚══════════════════════════════════════════════╝\n"
        RESET);
    fprintf(stderr, RED "  이유     : %s\n" RESET, reason);
    fprintf(stderr, RED "  파일     : %s\n" RESET, filepath);
    fprintf(stderr, RED "  엔트로피 : %.4f bits/byte\n" RESET, entropy);

    pid_t suspect = find_pid_accessing(filepath);

    if (suspect > 1) {
        char proc_name[256] = {0};
        get_proc_name(suspect, proc_name, sizeof(proc_name));
        int  file_cnt = get_pid_file_count(suspect);

        fprintf(stderr, RED "  PID       : %d (%s)\n" RESET, suspect, proc_name);
        fprintf(stderr, RED "  수정 파일 : %d개 (이 PID 기준)\n" RESET, file_cnt);

        /* [개선 5] 1단계: SIGSTOP으로 일단 멈춤 */
        if (kill(suspect, SIGSTOP) == 0) {
            fprintf(stderr, YELLOW "  조치      : SIGSTOP — 프로세스 일시정지\n" RESET);

            /* 2단계: 추가 분석 (멈춰있는 동안 시간 여유) */
            double entropy2     = calculate_entropy(filepath);
            int    high_entropy = (entropy2 >= ENTROPY_THRESHOLD);
            int    many_files   = (file_cnt >= 10);
            int    score        = (high_entropy ? 2 : 0) + (many_files ? 2 : 0)
                                  + (entropy2 - entropy >= ENTROPY_DELTA ? 1 : 0);

            fprintf(stderr, YELLOW
                "  재분석    : 엔트로피=%.4f, 파일수=%d, 위험점수=%d/5\n" RESET,
                entropy2, file_cnt, score);

            /* 3단계: 점수 기반 결정 */
            if (score >= 3) {
                if (kill(suspect, SIGKILL) == 0){
                    fprintf(stderr, RED
                        "  결정      : 위험 점수 %d/5 → SIGKILL 강제 종료\n" RESET, score);
                        
                        // ✅ SIGKILL 성공 후 → 파일 정적 분석
							      if (g_scan_callback != NULL) {
							      printf(YELLOW "[*] 정적 분석 시작: %s\n" RESET, filepath);
							      g_scan_callback(filepath);
						    }
					  }
                else
                    fprintf(stderr, YELLOW
                        "  결정      : SIGKILL 실패(권한 부족) — 수동 'kill -9 %d' 필요\n"
                        RESET, suspect);
            } else {
                kill(suspect, SIGCONT);
                fprintf(stderr, GREEN
                    "  결정      : 위험 점수 %d/5 → 오탐 가능성, SIGCONT 재개\n" RESET, score);
                fprintf(stderr, GREEN "              계속 모니터링 중...\n" RESET);
            }
        } else {
            fprintf(stderr, YELLOW
                "  조치      : SIGSTOP 실패(권한 부족) — 수동 처리 필요\n" RESET);
        }

        log_json("THREAT_DETECTED", suspect, filepath, entropy);
    } else {
        fprintf(stderr, YELLOW
            "  조치      : 접근 PID 특정 불가 — 즉시 시스템 점검 바람\n" RESET);
        log_json("THREAT_NO_PID", 0, filepath, entropy);
    }

    fprintf(stderr, RED
        "════════════════════════════════════════════════\n\n" RESET);
}

/* ═══════════════════════════════════════════════
 * [개선 4] 재귀 디렉터리 watch 등록
 * ═══════════════════════════════════════════════ */
static void watch_recursive(int ifd, const char *path)
{
    if (g_watch_count >= MAX_WATCHES) {
        fprintf(stderr, YELLOW "[!] watch 한도 도달(%d) — %s 건너뜀\n" RESET,
                MAX_WATCHES, path);
        return;
    }

    int wd = inotify_add_watch(ifd, path, INOTIFY_MASK);
    if (wd < 0) return;   /* 권한 없는 디렉터리 등 조용히 건너뜀 */

    g_watch_fds[g_watch_count]  = wd;
    strncpy(g_watch_paths[g_watch_count], path, PATH_MAX - 1);
    g_watch_count++;

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type != DT_DIR)  continue;

        char subpath[PATH_MAX];
        snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
        watch_recursive(ifd, subpath);
    }
    closedir(d);
}

/* wd → 경로 역조회 */
static const char *wd_to_path(int wd)
{
    for (int i = 0; i < g_watch_count; i++)
        if (g_watch_fds[i] == wd) return g_watch_paths[i];
    return g_watch_dir;
}

/* ═══════════════════════════════════════════════
 * 미끼 파일 생성
 * ═══════════════════════════════════════════════ */
static int create_decoy(const char *dir, char *decoy_path_out)
{
    snprintf(decoy_path_out, PATH_MAX, "%s/%s", dir, DECOY_FILENAME);
    if (access(decoy_path_out, F_OK) == 0) {
        printf(GREEN "[*] 기존 미끼 파일: %s\n" RESET, decoy_path_out);
        return 0;
    }
    FILE *fp = fopen(decoy_path_out, "w");
    if (!fp) { perror("decoy fopen"); return -1; }
    fputs(DECOY_CONTENT, fp);
    fclose(fp);

    /* before 엔트로피 기록 (낮아야 정상) */
    record_entropy_before(decoy_path_out, calculate_entropy(decoy_path_out));

    printf(GREEN "[*] 미끼 파일 생성: %s\n" RESET, decoy_path_out);
    return 0;
}

/* ═══════════════════════════════════════════════
 * 핵심 이벤트 처리 루프
 * ═══════════════════════════════════════════════ */
static void process_events(char *decoy_path)
{
    char buf[EVENT_BUF_LEN]
        __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len;
    time_t  now;

    while (g_running) {
        len = read(g_inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("inotify read");
            break;
        }

        const struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {

            event = (const struct inotify_event *)ptr;
            if (!event->len) continue;

            /* wd에서 실제 디렉터리 경로 역조회 (재귀 watch 지원) */
            const char *dir_path = wd_to_path(event->wd);
            char filepath[PATH_MAX];
            snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, event->name);

            /* ── [개선 4] 새 하위 디렉터리 자동 등록 ── */
            if ((event->mask & IN_CREATE) && (event->mask & IN_ISDIR)) {
                watch_recursive(g_inotify_fd, filepath);
                printf(CYAN "[*] 새 디렉터리 감시 추가: %s\n" RESET, filepath);
                continue;
            }

            /* ── Layer 1: Decoy 탐지 ── */
            if (*decoy_path && strcmp(filepath, decoy_path) == 0) {
                if (event->mask & (IN_MODIFY | IN_DELETE | IN_MOVED_FROM)) {
                    respond_to_threat("미끼 파일 접근/삭제", filepath, 0.0);
                    create_decoy(dir_path, decoy_path);
                    continue;
                }
            }

            /* 숨김 파일은 이후 레이어 제외 */
            if (event->name[0] == '.') continue;

            /* [개선 3] IN_CREATE 시점에 before 엔트로피 기록 */
            if (event->mask & IN_CREATE) {
                double e = calculate_entropy(filepath);
                if (e >= 0) record_entropy_before(filepath, e);
            }

            /* [개선 3] 랜섬웨어 확장자 즉시 탐지 */
            if (has_ransom_extension(event->name)) {
                double e = calculate_entropy(filepath);
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "랜섬웨어 의심 확장자 감지: %s", event->name);
                respond_to_threat(reason, filepath, e > 0 ? e : 0.0);
                continue;
            }

            /* [개선 2] 빌드 파일 제외 */
            if (is_safe_extension(event->name)) continue;

            /* ── Layer 2: Rate Limiting ── */
            now = time(NULL);
            if (now != g_window_start) { g_window_start = now; g_event_count = 0; }
            g_event_count++;

            printf(CYAN "[%s] %s/%s  [%d건/초]\n" RESET,
                   (event->mask & IN_MODIFY)    ? "MOD" :
                   (event->mask & IN_DELETE)    ? "DEL" :
                   (event->mask & IN_MOVED_FROM)? "MOV" :
                   (event->mask & IN_CREATE)    ? "CRE" : "OTH",
                   dir_path, event->name, g_event_count);

            if (g_event_count < RATE_THRESHOLD) continue;
            printf(YELLOW "[!] 속도 임계값 초과: %d건/초\n" RESET, g_event_count);

            /* ── Layer 3: Entropy 분석 ── */
            if (!(event->mask & (IN_MODIFY | IN_CREATE))) continue;

            double entropy_now = calculate_entropy(filepath);
            if (entropy_now < 0) continue;

            double entropy_before = get_entropy_before(filepath);

            printf(YELLOW "    엔트로피 before=%.4f  now=%.4f  delta=%.4f\n" RESET,
                   entropy_before < 0 ? 0.0 : entropy_before,
                   entropy_now,
                   entropy_before < 0 ? 0.0 : entropy_now - entropy_before);

            /* [개선 3] 조건 A: 절대값 기준 초과 */
            int cond_absolute = (entropy_now >= ENTROPY_THRESHOLD);

            /* [개선 3] 조건 B: before→after 급상승 (jpg/zip 오탐 방지) */
            int cond_delta = (entropy_before >= 0 &&
                              (entropy_now - entropy_before) >= ENTROPY_DELTA);

            if (cond_absolute && (cond_delta || entropy_before < 0)) {
                /* [개선 2] PID 카운트 갱신 */
                pid_t sus = find_pid_accessing(filepath);
                if (sus > 1) increment_pid_count(sus);

                char reason[256];
                snprintf(reason, sizeof(reason),
                         "고속 수정(%d건/초) + 엔트로피 급상승(%.2f→%.2f)",
                         g_event_count,
                         entropy_before < 0 ? 0.0 : entropy_before,
                         entropy_now);
                respond_to_threat(reason, filepath, entropy_now);
                g_event_count = 0;
            }

            /* 수정 후 엔트로피를 before로 갱신 */
            record_entropy_before(filepath, entropy_now);
        }
    }
}

/* ═══════════════════════════════════════════════
 * 시그널 핸들러
 * ═══════════════════════════════════════════════ */
static void sig_handler(int signo) { (void)signo; g_running = 0; }

/* main() 대신 이 함수로 진입 */
int start_behavior_monitor(const char *watch_dir, scan_callback_t on_suspicious)
{
    g_scan_callback = on_suspicious;  // 콜백 등록

    // 기존 main() 내용 그대로
    // (시그널 등록, inotify 초기화, watch_recursive, 미끼파일 생성, process_events)

    g_log_fp = fopen("/tmp/ransomware_detector.log", "a");  // LOG_FILE 상수 제거하고 직접 쓰기
    if (!g_log_fp) fprintf(stderr, YELLOW "[!] 로그 파일 열기 실패\n" RESET);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    
    g_inotify_fd = inotify_init();
    if (g_inotify_fd < 0) { perror("inotify_init"); return -1; }
    
    watch_recursive(g_inotify_fd, watch_dir);

    char decoy_path[PATH_MAX] = {0};
    create_decoy(watch_dir, decoy_path);

    process_events(decoy_path);

    // 정리
    for (int i = 0; i < g_watch_count; i++)
        inotify_rm_watch(g_inotify_fd, g_watch_fds[i]);
    close(g_inotify_fd);
    if (g_log_fp) fclose(g_log_fp);

    return 0;
}
