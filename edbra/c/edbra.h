#pragma once

#ifdef __cplusplus
extern "C" {
#endif

char* edbGetCertificate(const char* host, const char* configFilename, char** certificate);
char* edbInsecureGetCertificate(const char* host, char** certificate);
char* edbGetManifestSignature(const char* host, char* certificate, char** signature);

#ifdef __cplusplus
}
#endif
