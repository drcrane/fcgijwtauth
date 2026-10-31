#ifndef FILEEDITOR_H
#define FILEEDITOR_H

#include "fcgiapp.h"
#include "querystring.h"
#include "appfileman.hpp"

#ifdef __cplusplus
extern "C" {
#endif

int fileeditor_renderpage(FCGX_Request * request, RequestContext * req_ctx);

#ifdef __cplusplus
}
#endif

#endif // FILEEDITOR_H

