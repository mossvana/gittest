#ifndef FILE_ANALYSIS_H
#define FILE_ANALYSIS_H

int scan_file_content(const char *filepath); // yara_check
int scan_with_yara(const char *file_path, const char *rule_path); //static_analysis 

#endif
