#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// 파일의 SHA256 해시를 계산하여 output 배열(최소 65바이트)에 저장
// 반환값: 성공 시 1, 실패 시 0
int calculate_sha256(const char *path, char output[65]) {
    // 1. 메모리 초기화 (이전 쓰레기값 방지)
    memset(output, 0, 65);

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    // 2. OpenSSL 3.0 최신 방식: EVP Context 생성 및 초기화
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fclose(file);
        return 0;
    }

    // SHA256 알고리즘 사용 설정
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    unsigned char buffer[4096];
    size_t bytes;

    // 3. 파일 읽으면서 해시 업데이트
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 0;
        }
    }

    // 파일 읽기 에러 체크
    if (ferror(file)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    // 4. 최종 해시 추출
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    // Context 메모리 해제 및 파일 닫기
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // 5. 16진수 문자열로 변환 (snprintf로 버퍼 오버플로우 방지)
    for (unsigned int i = 0; i < hash_len; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }

    return 1;
}

// 💡 VT API 키를 여기에 입력하세요! (따옴표 안에 발급받은 키 삽입)
#define VT_API_KEY "your_key"

// libcurl에서 응답받은 데이터를 메모리에 저장하기 위한 구조체
struct MemoryStruct {
    char *memory;
    size_t size;
};

// libcurl 콜백 함수: 서버 응답(JSON)을 화면에 출력하지 않고 메모리에 차곡차곡 쌓음
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        printf("[-] 메모리 할당 부족 (realloc 실패)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0; // 널 종료 문자 추가

    return realsize;
}

// 해시값을 받아 VirusTotal에 검사하고 악성 판정(malicious) 개수를 반환하는 함수
// 반환값: 악성 판정 엔진 수 (정상/미확인은 0, 에러는 -1)
int query_virustotal(const char *file_hash) {
    CURL *curl;
    CURLcode res;
    int malicious_count = -1; // 기본값: 에러 상태

    // 데이터를 저장할 메모리 초기화
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (curl) {
        // 1. 요청할 URL 조립 (API v3 형식)
        char url[256];
        snprintf(url, sizeof(url), "https://www.virustotal.com/api/v3/files/%s", file_hash);

        // 2. HTTP 헤더에 API 키 세팅
        struct curl_slist *headers = NULL;
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", VT_API_KEY);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "accept: application/json");

        // 3. cURL 옵션 설정
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // 콜백 지정
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);          // 데이터 저장소 지정

        // 4. HTTP GET 요청 실행
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            printf("[-] cURL 요청 실패: %s\n", curl_easy_strerror(res));
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code == 200) {
                // 5. 응답 성공(200): cJSON으로 JSON 파싱 시작
                cJSON *json = cJSON_Parse(chunk.memory);
                if (json != NULL) {
                    // JSON 경로: data -> attributes -> last_analysis_stats -> malicious
                    cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
                    cJSON *attributes = cJSON_GetObjectItemCaseSensitive(data, "attributes");
                    cJSON *stats = cJSON_GetObjectItemCaseSensitive(attributes, "last_analysis_stats");
                    cJSON *malicious = cJSON_GetObjectItemCaseSensitive(stats, "malicious");

                    if (cJSON_IsNumber(malicious)) {
                        malicious_count = malicious->valueint; // 악성 판정 개수 추출!
                    }
                    cJSON_Delete(json); // JSON 메모리 해제 (매우 중요)
                }
            } else if (response_code == 404) {
                // VT DB에 없는 신종 파일인 경우
                malicious_count = 0; 
            } else if (response_code == 401) {
                printf("[-] API 키가 잘못되었습니다. (401 Unauthorized)\n");
            } else if (response_code == 429) {
                printf("[-] API 호출 한도를 초과했습니다. (429 Too Many Requests)\n");
            } else {
                printf("[-] 서버 응답 에러: HTTP %ld\n", response_code);
            }
        }

        // 6. cURL 자원 정리
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    free(chunk.memory); // 우리가 할당한 응답 저장용 메모리 해제
    return malicious_count;
}
