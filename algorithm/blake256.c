/*
 * BLAKE implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 *
 * Modified for more speed by BlueDragon747 for the Blakecoin project
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "sph/sph_blake.h"
#include "algorithm/blake256.h"

static const uint32_t diff1targ_blake256 = 0x000000ff;

void blake256hash(void *state, const void *input)
{
  sph_blake256_context ctx_blake;
  sph_blake256_init(&ctx_blake);
  sph_blake256(&ctx_blake, input, 80);
  sph_blake256_close(&ctx_blake, state);
}

void blake256_midstate(struct work *work)
{
  sph_blake256_context     ctx_blake;
  uint32_t data[16];

  be32enc_vect(data, (const uint32_t *)work->data, 16);

  sph_blake256_init(&ctx_blake);
  sph_blake256 (&ctx_blake, (unsigned char *)data, 64);

  memcpy(work->midstate, ctx_blake.H, 32);
  endian_flip32(work->midstate, work->midstate);

  char *strdata, *strmidstate;
  strdata = bin2hex(work->data, 80);
  strmidstate = bin2hex(work->midstate, 32);
  applog(LOG_DEBUG, "data %s midstate %s", strdata, strmidstate);
}

void blake256_prepare_work(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata)
{
	blk->ctx_a = state[0];
	blk->ctx_b = state[1];
	blk->ctx_c = state[2];
	blk->ctx_d = state[3];
	blk->ctx_e = state[4];
	blk->ctx_f = state[5];
	blk->ctx_g = state[6];
	blk->ctx_h = state[7];

	blk->cty_a = pdata[16];
	blk->cty_b = pdata[17];
	blk->cty_c = pdata[18];
}


static const uint32_t diff1targ = 0x0000ffff;

/* Used externally as confirmation of correct OCL code */
int blake256_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
	blake256hash(ohash, data);
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
				(long unsigned int)Htarg,
				(long unsigned int)diff1targ,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

void blake256_regenhash(struct work *work)
{
        uint32_t data[20];
        uint32_t *nonce = (uint32_t *)(work->data + 76);
        uint32_t *ohash = (uint32_t *)(work->hash);

        be32enc_vect(data, (const uint32_t *)work->data, 19);
        data[19] = htobe32(*nonce);
        blake256hash(ohash, data);
}

bool scanhash_blake256(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		blake256hash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
					(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}
