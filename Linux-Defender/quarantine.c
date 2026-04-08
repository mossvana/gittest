#include "quarantine.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

#define QUARANTINE_DIR "/tmp/quarantine/"

int isolate_file(const char *filepath) {
    char new_path[512];
    char path_copy[256];
    strncpy(path_copy, filepath, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    if (mkdir(QUARANTINE_DIR, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "[-] 격리 폴더 생성 실패: %s\n", strerror(errno));

    snprintf(new_path, sizeof(new_path), "%s%s.malware",
             QUARANTINE_DIR, basename(path_copy));

    if (rename(filepath, new_path) == 0) {
        printf("[+] Moved to Quarantine: %s\n", new_path);
        if (chmod(new_path, 0000) != 0)
            fprintf(stderr, "[-] chmod 실패: %s\n", strerror(errno));
        else
            printf("[+] Execution Blocked (chmod 0000)\n");
        return 0;   // 성공
    } else {
        fprintf(stderr, "[-] 격리 이동 실패 [%s]: %s\n",
                filepath, strerror(errno));
        return -1;  // 실패
    }
}
