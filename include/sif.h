/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 * Copyright (c) 2020 Thesis projects
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 * Modified by: Laukik Hase
 *
 * Added Compatibility with ESP-IDF
 *
 * Copyright (c) 2021 Temcus Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef ESP_SIF_SIF_H
#define ESP_SIF_SIF_H

#include <stdint.h>

/* PARTITION LABELS */
#define DEFAULT_PARTITION_LABEL_SRC   "ota_0"
#define DEFAULT_PARTITION_LABEL_DEST  "ota_1"
#define DEFAULT_PARTITION_LABEL_PATCH "patch"

/* PAGE SIZE */
#define PARTITION_PAGE_SIZE (0x1000)

/* Error codes. */
#define SIF_OK                     0
#define SIF_OUT_OF_MEMORY          28
#define SIF_READING_PATCH_ERROR    29
#define SIF_READING_SOURCE_ERROR   30
#define SIF_WRITING_ERROR          31
#define SIF_SEEKING_ERROR          32
#define SIF_CASTING_ERROR          33
#define SIF_INVALID_BUF_SIZE       34
#define SIF_CLEARING_ERROR         35
#define SIF_PARTITION_ERROR        36
#define SIF_TARGET_IMAGE_ERROR     37
#define SIF_INVALID_ARGUMENT_ERROR 38
#define SIF_OUT_OF_BOUNDS_ERROR    39
#define SIF_CHECKSUM_ERROR         40

typedef enum sif_source_type_t
{
	SIF_SRC_PARTITION = 0,
	SIF_SRC_FILE,
} sif_source_type_t;

typedef struct
{
	sif_source_type_t type;
	const char *where;
} sif_source_t;

typedef struct
{
	sif_source_t src;
	sif_source_t dest;
	sif_source_t patch;
} sif_opts_t;

#define INIT_DEFAULT_SIF_OPTS_SRC()           \
	{                                         \
		.type = SIF_SRC_PARTITION,            \
		.where = DEFAULT_PARTITION_LABEL_SRC, \
	}

#define INIT_DEFAULT_SIF_OPTS_DEST()           \
	{                                          \
		.type = SIF_SRC_PARTITION,             \
		.where = DEFAULT_PARTITION_LABEL_DEST, \
	}

#define INIT_DEFAULT_SIF_OPTS_PATCH()           \
	{                                           \
		.type = SIF_SRC_PARTITION,              \
		.where = DEFAULT_PARTITION_LABEL_PATCH, \
	}

#define INIT_DEFAULT_SIF_OPTS()                \
	{                                          \
		.src = INIT_DEFAULT_SIF_OPTS_SRC(),    \
		.dest = INIT_DEFAULT_SIF_OPTS_DEST(),  \
		.patch = INIT_DEFAULT_SIF_OPTS_PATCH() \
	}

#define INIT_NEXT_OTA_PARTITION_SIF_OPTS()     \
	{                                          \
		.src = {                               \
			.type = SIF_SRC_PARTITION,         \
			.where = NULL,                     \
		},                                     \
		.dest = {                              \
			.type = SIF_SRC_PARTITION,         \
			.where = NULL,                     \
		},                                     \
		.patch = INIT_DEFAULT_SIF_OPTS_PATCH() \
	}

typedef struct sif_patch_writer sif_patch_writer_t;

int sif_patch_init(sif_patch_writer_t **writer, const char *partition, int patch_size);

int sif_patch_write(sif_patch_writer_t *writer, const char *buf, int size);

void sif_patch_free(sif_patch_writer_t *writer);

/**
 * Checks if there is patch in the patch partition
 * and applies that patch if it exists. Then restarts
 * the device and boots from the new image.
 *
 * @param[in] patch_size size of the patch.
 * @param[in] opts options for applying the patch.
 *
 * @return zero(0) if no patch or a negative error
 * code.
 */
int sif_check_and_apply(int patch_size, const sif_opts_t *opts, const uint8_t *digest);

/**
 * Get the error string for given error code.
 *
 * @param[in] Error code.
 *
 * @return Error string.
 */
const char *sif_error_as_string(int error);

#endif
