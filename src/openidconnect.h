#ifndef OPENIDCONNECT_H
#define OPENIDCONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

int openidconnect_create_verifyable_string(const char * secret, const char * salt, char ** output);
int openidconnect_verify_string(const char * secret, const char * input);

#ifdef __cplusplus
}
#endif

#endif // OPENIDCONNECT_H

