/*
 * shl - Dynamic Hashtable
 *
 * Copyright (c) 2011-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * A dynamic hash table implementation
 */

#ifndef SHL_HASHTABLE_H
#define SHL_HASHTABLE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "external/tommyhashdyn.h"
#include "external/tommylist.h"

struct shl_hashtable;

typedef unsigned int (*shl_hash_cb) (const void *data);
typedef int (*shl_equal_cb) (const void *data1, const void *data2);
typedef void (*shl_free_cb) (void *data);

struct shl_hashentry {
	void *key;
	void *value;
        tommy_node node;
        tommy_hashdyn_node hashnode;
};

struct shl_hashtable {
        tommy_hashdyn tbl;
        tommy_list list;
	shl_hash_cb hash_cb;
	shl_equal_cb equal_cb;
	shl_free_cb free_key;
	shl_free_cb free_value;
};

static inline unsigned int shl_direct_hash(const void *data)
{
	return (unsigned int)(unsigned long)data;
}

static inline int shl_direct_equal(const void *data1, const void *data2)
{
	return (data1 != data2);
}

static inline int shl_hashtable_new(struct shl_hashtable **out,
				    shl_hash_cb hash_cb,
				    shl_equal_cb equal_cb,
				    shl_free_cb free_key,
				    shl_free_cb free_value)
{
	struct shl_hashtable *tbl;

	if (!out || !hash_cb || !equal_cb)
		return -EINVAL;

	tbl = malloc(sizeof(*tbl));
	if (!tbl)
		return -ENOMEM;
	memset(tbl, 0, sizeof(*tbl));
	tbl->hash_cb = hash_cb;
	tbl->equal_cb = equal_cb;
	tbl->free_key = free_key;
	tbl->free_value = free_value;

        tommy_list_init(&tbl->list);
        tommy_hashdyn_init(&tbl->tbl);

	*out = tbl;
	return 0;
}

static void shl_hashtable_free_entry(void *arg, void *obj)
{
        struct shl_hashtable *tbl = (struct shl_hashtable *)arg;
	struct shl_hashentry *entry = (struct shl_hashentry *)obj;
	if (tbl->free_key)
		tbl->free_key(entry->key);
	if (tbl->free_value)
		tbl->free_value(entry->value);
        tommy_list_remove_existing(&tbl->list, &entry->node);
        tommy_hashdyn_remove_existing(&tbl->tbl, &entry->hashnode);
	free(entry);
}

static inline void shl_hashtable_free(struct shl_hashtable *tbl)
{
	if (!tbl)
		return;

        tommy_list_foreach_arg(&tbl->list, shl_hashtable_free_entry, tbl);
        tommy_hashdyn_done(&tbl->tbl);
	free(tbl);
}

static inline int shl_hashtable_insert(struct shl_hashtable *tbl, void *key,
				       void *value)
{
	struct shl_hashentry *entry;
	size_t hash;

	if (!tbl)
		return -EINVAL;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;
	entry->key = key;
	entry->value = value;

	hash = tbl->hash_cb(key);

        tommy_list_insert_head(&tbl->list, &entry->node, entry);
        tommy_hashdyn_insert(&tbl->tbl, &entry->hashnode, entry, hash);

	return 0;
}

static inline void shl_hashtable_remove(struct shl_hashtable *tbl, void *key)
{
	struct shl_hashentry *entry;
	size_t hash;

	if (!tbl)
		return;

	hash = tbl->hash_cb(key);
        entry = tommy_hashdyn_search(&tbl->tbl, tbl->equal_cb, key, hash);
        if (entry) 
            shl_hashtable_free_entry(tbl, entry);
}

static inline bool shl_hashtable_find(struct shl_hashtable *tbl, void **out,
				      void *key)
{
	struct shl_hashentry *entry;
	unsigned int hash;

	if (!tbl)
		return false;

	hash = tbl->hash_cb(key);
        entry = tommy_hashdyn_search(&tbl->tbl, tbl->equal_cb, key, hash);
        if (entry) {
            if (out)
                *out = entry->value;
            return true;
        }
        return false;
}

#endif /* SHL_HASHTABLE_H */
