#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <errno.h>
#include <yara.h>

#define CHUNK_SIZE  4096
#define OVERLAP     256
#define MAX_SEEN    128

// ── 블랙리스트 (이 파일 안에서만 사용, static)
static const char *BLACKLIST[] = {
    "malware-c2.ru",
    "evil-payload.xyz",
    "185.220.101.45",
    "91.108.4.0",
    NULL
};

// ── 내부 함수 3개 (static = 이 파일 밖에서는 못 씀)
static int is_blacklisted(const char *addr) {
    for (int i = 0; BLACKLIST[i] != NULL; i++)
        if (strstr(addr, BLACKLIST[i]) != NULL) return 1;
    return 0;
}

static int is_already_seen(const char *addr,
                           char seen[][256], int seen_count) {
    for (int i = 0; i < seen_count; i++)
        if (strcmp(seen[i], addr) == 0) return 1;
    return 0;
}

static int scan_pattern(const char *buf,
                        const char *pat, const char *label,
                        char seen[][256], int *seen_count) {
    regex_t re;
    if (regcomp(&re, pat, REG_EXTENDED | REG_ICASE) != 0) return 0;

    int hits = 0;
    const char *cursor = buf;
    regmatch_t match;

    while (regexec(&re, cursor, 1, &match, 0) == 0) {
        int len = match.rm_eo - match.rm_so;
        if (len <= 0 || len >= 255) { cursor += match.rm_eo; continue; }

        char extracted[256];
        strncpy(extracted, cursor + match.rm_so, len);
        extracted[len] = '\0';

        if (!is_already_seen(extracted, seen, *seen_count)) {
            if (*seen_count < MAX_SEEN) {
                strncpy(seen[*seen_count], extracted, 255);
                (*seen_count)++;
            }
            if (is_blacklisted(extracted)) {
                printf("\033[1;31m[!] %s: %s\033[0m\n", label, extracted);
                hits++;
            } else {
                printf("\033[1;33m[~] 주소 발견 (정상): %s\033[0m\n", extracted);
            }
        }
        cursor += match.rm_eo;
    }
    regfree(&re);
    return hits;
}

// ── 공개 함수 (헤더에 선언된 것)
int scan_file_content(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[-] 파일 열기 실패 [%s]: %s\n",
                filepath, strerror(errno));
        return 0;
    }

    const char *ipv4_pat =
        "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\."
        "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\."
        "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\."
        "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";

    const char *url_pat =
        "https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+";

    char seen[MAX_SEEN][256];
    int  seen_count = 0;
    char buf[OVERLAP + CHUNK_SIZE + 1];
    size_t overlap_len = 0;
    int total_hits = 0;

    while (1) {
        size_t bytes_read = fread(buf + overlap_len, 1, CHUNK_SIZE, fp);
        if (bytes_read == 0) break;

        size_t total_len = overlap_len + bytes_read;
        for (size_t i = 0; i < total_len; i++)
            if (buf[i] == '\0') buf[i] = ' ';
        buf[total_len] = '\0';

        total_hits += scan_pattern(buf, ipv4_pat, "Suspicious C2 IP",
                                   seen, &seen_count);
        total_hits += scan_pattern(buf, url_pat,  "Suspicious C2 URL",
                                   seen, &seen_count);

        if (bytes_read == CHUNK_SIZE) {
            overlap_len = OVERLAP;
            memmove(buf, buf + total_len - OVERLAP, OVERLAP);
        } else {
            break;
        }
    }

    fclose(fp);
    return total_hits > 0;
}

// 💡 YARA 콜백 함수: 파일 스캔 중에 악성 패턴(룰)이 매칭될 때마다 이 함수가 자동 실행됨
int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    (void)context;  // 미사용 파라미터 경고 제거
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*) message_data;
        printf("    🚨 [YARA 탐지] 매칭된 악성코드 룰: %s\n", rule->identifier);
        
        // 탐지 카운트 증가
        int* match_count = (int*)user_data;
        (*match_count)++;
    }
    return CALLBACK_CONTINUE;
}

// YARA 엔진을 초기화하고 파일을 스캔하는 함수
int scan_with_yara(const char *file_path, const char *rule_path) {
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    int match_count = 0; // 발견된 악성 패턴 개수

    // 1. YARA 엔진 시동 걸기
    if (yr_initialize() != ERROR_SUCCESS) {
        return -1;
    }

    // 2. 컴파일러 준비 (텍스트로 된 룰을 YARA가 이해할 수 있게 변환)
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        return -1;
    }

    // 3. 룰 파일 열어서 컴파일러에 추가
    FILE *rule_file = fopen(rule_path, "r");
    if (rule_file == NULL) {
        printf("[-] YARA 룰 파일을 찾을 수 없습니다: %s\n", rule_path);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }
    // 이 함수의 반환값이 0(에러 없음)인지 반드시 확인해야 해!
    int compile_errors = yr_compiler_add_file(compiler, rule_file, NULL, rule_path);
    fclose(rule_file);

    if (compile_errors > 0) {
        printf("[-] 오류: YARA 룰 파일(%s)에 문법 에러가 있습니다!\n", rule_path);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    // 4. 컴파일된 룰 데이터 가져오기
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    // 5. 드디어 스캔 시작! (발견 시 yara_callback 함수 호출)
    printf("    🔎 YARA 현미경으로 내부 패턴 정밀 분석 중...\n");
    yr_rules_scan_file(rules, file_path, 0, yara_callback, &match_count, 0);

    // 6. 메모리 청소 (C언어의 기본!)
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return match_count;
}
