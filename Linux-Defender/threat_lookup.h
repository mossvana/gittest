#ifndef THREAT_LOOKUP_H
#define THREAT_LOOKUP_H

int calculate_sha256(const char *path, char output[65]);
int query_virustotal(const char *file_hash);

#endif
