#ifndef EVOCOIN_H
#define EVOCOIN_H

#include "miner.h"

#define INITIAL_DATE 1462060800
#define HASH_FUNC_COUNT 11
#define DEFAULT_NTIME "00000000"

extern int evocoin_test(unsigned char *pdata, const unsigned char *ptarget,	uint32_t nonce);
extern void evocoin_regenhash(struct work *work);
extern void evocoin_twisted_code(char *result, const char *ntime, uint8_t *code);

#endif /* EVOCOIN_H */
