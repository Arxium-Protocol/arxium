#ifndef ARX_ID_KIT_H
#define ARX_ID_KIT_H

#include <stddef.h>

// Returns a JSON C string. Call arx_id_free after copying its contents.
char *arx_id_json(const char *request);
void arx_id_free(char *result);

#endif
