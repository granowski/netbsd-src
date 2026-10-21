/* SPDX-License-Identifier: MIT */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/types.h>

#include "apfs_unicode.h"

struct apfs_unicode_mapping {
	uint32_t codepoint;
	uint32_t offset;
	uint8_t length;
};

struct apfs_unicode_combining {
	uint32_t codepoint;
	uint8_t combining_class;
};

#include "apfs_unicode_data.h"

static const struct apfs_unicode_mapping *
apfs_unicode_find_mapping(const struct apfs_unicode_mapping *table, size_t n,
    uint32_t codepoint)
{
	size_t lo = 0, hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (table[mid].codepoint < codepoint)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == n || table[lo].codepoint != codepoint)
		return NULL;
	return &table[lo];
}

static uint8_t
apfs_unicode_combining_class(uint32_t codepoint)
{
	size_t lo = 0, hi = __arraycount(apfs_unicode_combining_table);

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (apfs_unicode_combining_table[mid].codepoint < codepoint)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == __arraycount(apfs_unicode_combining_table) ||
	    apfs_unicode_combining_table[lo].codepoint != codepoint)
		return 0;
	return apfs_unicode_combining_table[lo].combining_class;
}

static int
apfs_unicode_append_decomposed(uint32_t codepoint, uint32_t *out,
    size_t capacity, size_t *length)
{
	const struct apfs_unicode_mapping *mapping;
	uint32_t sindex, l, v, t;
	int error;

	if (codepoint >= 0xac00 && codepoint <= 0xd7a3) {
		sindex = codepoint - 0xac00;
		l = 0x1100 + sindex / 588;
		v = 0x1161 + (sindex % 588) / 28;
		t = sindex % 28;
		size_t needed = t == 0 ? 2 : 3;
		if (*length > capacity || needed > capacity - *length)
			return EOVERFLOW;
		out[(*length)++] = l;
		out[(*length)++] = v;
		if (t != 0)
			out[(*length)++] = 0x11a7 + t;
		return 0;
	}

	mapping = apfs_unicode_find_mapping(apfs_unicode_decomposition_table,
	    __arraycount(apfs_unicode_decomposition_table), codepoint);
	if (mapping == NULL) {
		if (*length == capacity)
			return EOVERFLOW;
		out[(*length)++] = codepoint;
		return 0;
	}

	for (size_t i = 0; i < mapping->length; i++) {
		error = apfs_unicode_append_decomposed(
		    apfs_unicode_decomposition_values[mapping->offset + i],
		    out, capacity, length);
		if (error != 0)
			return error;
	}
	return 0;
}

static int
apfs_unicode_decode(const char *src, size_t srclen, uint32_t *out,
    size_t capacity, size_t *length)
{
	const uint8_t *p = (const uint8_t *)src;
	size_t remaining = srclen;

	*length = 0;
	while (remaining != 0) {
		uint32_t cp;
		size_t nbytes;

		if (p[0] < 0x80) {
			cp = p[0];
			nbytes = 1;
		} else if ((p[0] & 0xe0) == 0xc0) {
			cp = p[0] & 0x1f;
			nbytes = 2;
		} else if ((p[0] & 0xf0) == 0xe0) {
			cp = p[0] & 0x0f;
			nbytes = 3;
		} else if ((p[0] & 0xf8) == 0xf0) {
			cp = p[0] & 0x07;
			nbytes = 4;
		} else {
			return EILSEQ;
		}
		if (nbytes > remaining)
			return EILSEQ;
		for (size_t i = 1; i < nbytes; i++) {
			if ((p[i] & 0xc0) != 0x80)
				return EILSEQ;
			cp = (cp << 6) | (p[i] & 0x3f);
		}
		if ((nbytes == 2 && cp < 0x80) ||
		    (nbytes == 3 && cp < 0x800) ||
		    (nbytes == 4 && cp < 0x10000) ||
		    cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
			return EILSEQ;
		if (*length == capacity)
			return EOVERFLOW;
		out[(*length)++] = cp;
		p += nbytes;
		remaining -= nbytes;
	}
	return 0;
}

static void
apfs_unicode_reorder(uint32_t *text, size_t length)
{
	for (size_t i = 1; i < length; i++) {
		uint8_t ccc = apfs_unicode_combining_class(text[i]);
		size_t j = i;

		while (ccc != 0 && j > 0) {
			uint8_t previous_ccc =
			    apfs_unicode_combining_class(text[j - 1]);

			if (previous_ccc == 0 || previous_ccc <= ccc)
				break;
			uint32_t tmp = text[j];
			text[j] = text[j - 1];
			text[j - 1] = tmp;
			j--;
		}
	}
}

int
apfs_unicode_transform(const char *src, size_t srclen, unsigned int flags,
    uint32_t **outp, size_t *outlenp)
{
	const size_t expansion = 12;
	uint32_t *work, *result, *output;
	size_t capacity, length, result_length = 0;
	int error;

	if (src == NULL || outp == NULL || outlenp == NULL ||
	    (flags & ~(APFS_UNICODE_NFD | APFS_UNICODE_CASEFOLD)) != 0)
		return EINVAL;
	*outp = NULL;
	*outlenp = 0;
	if (srclen > SIZE_MAX / (expansion * sizeof(*work)))
		return EOVERFLOW;
	capacity = MAX((size_t)1, srclen * expansion);
	work = kmem_alloc(capacity * sizeof(*work), KM_SLEEP);
	result = kmem_alloc(capacity * sizeof(*result), KM_SLEEP);

	error = apfs_unicode_decode(src, srclen, work, capacity, &length);
	if (error != 0)
		goto out;

	if ((flags & APFS_UNICODE_NFD) != 0) {
		size_t decomposed_length = 0;

		for (size_t i = 0; i < length; i++) {
			error = apfs_unicode_append_decomposed(work[i], result,
			    capacity, &decomposed_length);
			if (error != 0)
				goto out;
		}
		memcpy(work, result, decomposed_length * sizeof(*work));
		length = decomposed_length;
		apfs_unicode_reorder(work, length);
	}

	if ((flags & APFS_UNICODE_CASEFOLD) != 0) {
		for (size_t i = 0; i < length; i++) {
			const struct apfs_unicode_mapping *mapping =
			    apfs_unicode_find_mapping(apfs_unicode_casefold_table,
			    __arraycount(apfs_unicode_casefold_table), work[i]);

			if (mapping == NULL) {
				if (result_length == capacity) {
					error = EOVERFLOW;
					goto out;
				}
				result[result_length++] = work[i];
				continue;
			}
			if (mapping->length > capacity - result_length) {
				error = EOVERFLOW;
				goto out;
			}
			memcpy(&result[result_length],
			    &apfs_unicode_casefold_values[mapping->offset],
			    mapping->length * sizeof(*result));
			result_length += mapping->length;
		}
	} else {
		memcpy(result, work, length * sizeof(*result));
		result_length = length;
	}

	if ((flags & (APFS_UNICODE_NFD | APFS_UNICODE_CASEFOLD)) ==
	    (APFS_UNICODE_NFD | APFS_UNICODE_CASEFOLD)) {
		size_t normalized_length = 0;

		for (size_t i = 0; i < result_length; i++) {
			error = apfs_unicode_append_decomposed(result[i], work,
			    capacity, &normalized_length);
			if (error != 0)
				goto out;
		}
		apfs_unicode_reorder(work, normalized_length);
		uint32_t *tmp = result;
		result = work;
		work = tmp;
		result_length = normalized_length;
	}

	output = NULL;
	if (result_length != 0) {
		output = kmem_alloc(result_length * sizeof(*output), KM_SLEEP);
		memcpy(output, result, result_length * sizeof(*output));
	}
	*outp = output;
	*outlenp = result_length;
	error = 0;
out:
	kmem_free(work, capacity * sizeof(*work));
	if (result != NULL)
		kmem_free(result, capacity * sizeof(*result));
	return error;
}
