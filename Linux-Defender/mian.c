#include <stdio.h>
#include "hash_check.h"
#include "vt_check.h"
#include "yara_check.h" 
#include "static_analysis.h"
#include "quarantine.h"      

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("사용법: %s <검사할 파일 경로>\n", argv[0]);
        return 1;
    }

    const char *target_file = argv[1];
    const char *yara_rule_file = "test.yar"; // 우리가 만든 YARA 룰 파일
    char file_hash[65];

    printf("\n================================================\n");
    printf(" 🛡️  하이브리드 안티바이러스 엔진 가동 시작\n");
    printf("================================================\n");
    printf("📁 검사 대상: %s\n\n", target_file);

    // [1단계] 해시 추출
    if (calculate_sha256(target_file, file_hash)) {
        printf("[1단계] SHA256 지문: %s\n", file_hash);
        printf("[2단계] VirusTotal 서버에 평판 조회 중...\n");

        // [2단계] VT 서버 조회
        int vt_score = query_virustotal(file_hash);

        // VT에서 탐지한 경우 (빠른 차단)
        if (vt_score > 0) {
            // VT 악성 판정 → 즉시 격리 (YARA, 정적분석 스킵)
            printf("⛔ [최종 탐지] VirusTotal 악성 판정! (탐지 백신 수: %d개)\n", vt_score);
            printf("✅ 클라우드에서 확인된 널리 알려진 악성코드입니다. (로컬 검사 생략)\n");
            isolate_file(target_file);  // 추가: 격리 실행
        } 
        // VT가 모르거나 서버 통신에 실패한 경우 (YARA 검사로 폴백(Fallback))
        else {
            if (vt_score == 0) {
                printf("⚠️ [미확인] VirusTotal DB에 없는 신종 파일이거나 정상 파일입니다.\n");
            } else {
                printf("⚠️ [오류] 네트워크 문제로 VT 서버 통신에 실패했습니다.\n");
            }
            
            printf("\n[3단계] 로컬 YARA 엔진 정밀 검사로 전환합니다 ➡️\n");
            int yara_hits = scan_with_yara(target_file, yara_rule_file);
            
            if (yara_hits > 0) {
                // YARA 악성 판정 → 즉시 격리
                printf("⛔ [최종 탐지] YARA 엔진에서 악성 패턴을 %d개 발견했습니다!\n", yara_hits);
                isolate_file(target_file);  // 추가: 격리 실행
            } else if (yara_hits == 0) {
                // YARA 통과 → 3주차 정적 분석으로 넘어감
                printf("🟢 [안전] YARA 스캔 결과 특이점 없음. 파일이 안전해 보입니다.\n");
            } else {
                printf("[-] YARA 검사 중 오류가 발생했습니다.\n");
            }
            
            // [4단계] 정적 분석 — 3주차 추가
            printf("\n[4단계] 정적 분석 (IP/URL 블랙리스트 검사) ➡️\n");
            int sa_result = scan_file_content(target_file);  // 추가

            if (sa_result > 0) {
            printf("⛔ [최종 탐지] 악성 C2 주소 발견!\n");
            isolate_file(target_file);  // 추가: 격리 실행
            } else {
                printf("🟢 [안전] 정적 분석 이상 없음. 파일이 안전합니다.\n");
            }
        }
    } else {
        printf("[-] 오류: 파일을 읽을 수 없습니다.\n");
    }

    printf("================================================\n\n");
    return 0;
}
