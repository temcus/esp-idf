// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: 0
//
//
// Copyright (c) 2020 Thesis projects
//
// SPDX-License-Identifier: Apache-2.0
//
//
// Modified by: Laukik Hase
//
// Added Compatibility with ESP-IDF
//
// Copyright (c) 2021 Temcus Limited
//
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "bootloader_common.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"

#include "esp_ota_ops.h"
#include "esp_partition.h"

#include "detools.h"

#include "sif.h"

#ifndef sif_assert
#define sif_assert(cond) assert(cond)
#endif

static const char *TAG = "sif";

typedef struct sif_patcher
{
	struct
	{
		size_t offset;
		union
		{
			const esp_partition_t *partition;
			int fd;
		};
	} src;
	struct
	{
		size_t offset;
		union
		{
			struct
			{
				const esp_partition_t *partition;
				esp_ota_handle_t ota_handle;
			} flash;
			int fd;
		};
	} dest;
	struct
	{
		size_t offset;
		union
		{
			const esp_partition_t *partition;
			int fd;
		};
	} patch;

	sif_opts_t opts;

	detools_read_t read_src;
	detools_seek_t seek_src;
	detools_read_t read_patch;
	detools_write_t write_dest;
	int (*write_done)(void *arg_p);

	uint8_t *buffer;
	size_t buffer_size;
} sif_patcher_t;

struct sif_patch_writer
{
	const char *name;
	union
	{
		const void *flash;
		int fd;
	};
	int offset;
	int size;
	sif_source_t type;
};

static int sif_all_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
	sif_assert(size > 0);

	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	size_t pos = patcher->dest.offset % patcher->buffer_size;
	size_t left = patcher->buffer_size - pos;
	size_t chunk = MIN(size, left);

	memcpy(patcher->buffer+pos, buf_p, chunk);
	patcher->dest.offset += chunk;

	pos = patcher->dest.offset % patcher->buffer_size;
	if (pos == 0)
	{
		if (patcher->write_dest(arg_p, patcher->buffer, patcher->buffer_size) < 0)
			return -SIF_WRITING_ERROR;
	}

	if (chunk < size)
	{
		return sif_all_write_dest(arg_p, buf_p+chunk, size-chunk);
	}

	return SIF_OK;
}

static int sif_all_write_done(void *arg_p)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	size_t pos = patcher->dest.offset % patcher->buffer_size;
	if (pos > 0)
	{
		if (patcher->write_dest(arg_p, patcher->buffer, pos) < 0)
			return -SIF_WRITING_ERROR;
	}

	if (patcher->write_done(arg_p) < 0)
		return -SIF_WRITING_ERROR;

	ESP_LOGI(TAG, "new image size: %u bytes", patcher->dest.offset);

	return SIF_OK;
}

static int sif_file_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
	sif_assert(size > 0);

	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	int res = write(patcher->dest.fd, buf_p, size);
	if (res < 0)
		return -SIF_PARTITION_ERROR;

	return SIF_OK;
}

static int sif_file_write_done(void *arg_p)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	close(patcher->dest.fd);
	patcher->dest.fd = 0;

	return SIF_OK;
}

static int sif_file_read_src(void *arg_p, uint8_t *buf_p, size_t size)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	int res = read(patcher->src.fd, buf_p, size);
	if (res < 0)
		return -SIF_READING_SOURCE_ERROR;

	patcher->src.offset += size;

	return SIF_OK;
}

static int sif_file_read_patch(void *arg_p, uint8_t *buf_p, size_t size)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	int res = read(patcher->patch.fd, buf_p, size);
	if (res < 0)
		return -SIF_READING_SOURCE_ERROR;

	patcher->patch.offset += size;

	return SIF_OK;
}

static int sif_file_seek_src(void *arg_p, int offset)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	off_t res = lseek(patcher->src.fd, offset, SEEK_CUR);
	if (res == -1)
		return -SIF_SEEKING_ERROR;

	patcher->src.offset += offset;

	return SIF_OK;
}

static int sif_flash_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
	sif_assert(arg_p && buf_p && size > 0);
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	if (esp_ota_write(patcher->dest.flash.ota_handle, buf_p, size) != ESP_OK)
		return -SIF_WRITING_ERROR;

	return SIF_OK;
}

static int sif_flash_write_done(void *arg_p)
{
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	if (esp_ota_end(patcher->dest.flash.ota_handle) != ESP_OK)
		return -SIF_WRITING_ERROR;

	return SIF_OK;
}

static int sif_flash_read_src(void *arg_p, uint8_t *buf_p, size_t size)
{
	sif_assert(arg_p && buf_p && size > 0);
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	if (esp_partition_read(patcher->src.partition, patcher->src.offset, buf_p, size) != ESP_OK)
		return -SIF_READING_SOURCE_ERROR;

	patcher->src.offset += size;
	if (patcher->src.offset >= patcher->src.partition->size)
		return -SIF_OUT_OF_MEMORY;

	return SIF_OK;
}

static int sif_flash_read_patch(void *arg_p, uint8_t *buf_p, size_t size)
{
	sif_assert(arg_p && buf_p && size > 0);
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	if (esp_partition_read(patcher->patch.partition, patcher->patch.offset, buf_p, size) != ESP_OK)
		return -SIF_READING_PATCH_ERROR;

	patcher->patch.offset += size;
	if (patcher->patch.offset >= patcher->patch.partition->size)
		return -SIF_READING_PATCH_ERROR;

	return SIF_OK;
}

static int sif_flash_seek_src(void *arg_p, int offset)
{
	sif_assert(arg_p);
	sif_patcher_t *patcher = (sif_patcher_t *)arg_p;

	patcher->src.offset += offset;
	if (patcher->src.offset >= patcher->src.partition->size)
		return -SIF_SEEKING_ERROR;

	return SIF_OK;
}

static int sif_patcher_init(sif_patcher_t *patcher, const sif_opts_t *opts)
{
	sif_assert(patcher && opts);

	// if src and dest are partitions, then both the partition labels need to be specified
	// OR neither.
	sif_assert(opts->src.type != SIF_SRC_PARTITION || opts->dest.type != SIF_SRC_PARTITION ||
		((opts->src.where && opts->dest.where) || (!opts->src.where && !opts->dest.where)));

	memset(patcher, 0, sizeof(*patcher));
	memcpy(&patcher->opts, opts, sizeof(*opts));

	patcher->buffer_size = CONFIG_SIF_PAGE_SIZE;
	patcher->buffer = malloc(patcher->buffer_size);
	if (!patcher->buffer)
		return -SIF_OUT_OF_MEMORY;

	if (opts->src.type == SIF_SRC_PARTITION)
	{
		const esp_partition_t *partition = opts->src.where ?
			esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->src.where) :
			esp_ota_get_running_partition();
		if (partition == NULL || partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
			return -SIF_PARTITION_ERROR;

		patcher->src.partition = partition;
		patcher->read_src = sif_flash_read_src;
		patcher->seek_src = sif_flash_seek_src;
	}
	else
	{
		int fd = open(opts->src.where, O_RDONLY);
		if (fd <= 0)
			return -SIF_PARTITION_ERROR;

		patcher->read_src = sif_file_read_src;
		patcher->seek_src = sif_file_seek_src;
		patcher->src.fd = fd;
	}

	if (opts->dest.type == SIF_SRC_PARTITION)
	{
		const esp_partition_t *partition = opts->dest.where ?
			esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->dest.where) :
			esp_ota_get_next_update_partition(NULL);
		if (partition == NULL || partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
			return -SIF_PARTITION_ERROR;

		if (esp_ota_begin(partition, OTA_SIZE_UNKNOWN,
			&(patcher->dest.flash.ota_handle)) != ESP_OK)
			return -SIF_PARTITION_ERROR;

		patcher->opts.dest.where = partition->label;
		patcher->dest.flash.partition = partition;
		patcher->write_dest = sif_flash_write_dest;
		patcher->write_done = sif_flash_write_done;
	}
	else
	{
		int fd = open(opts->dest.where, O_CREAT|O_TRUNC|O_RDWR);
		if (fd <= 0)
		{
			ESP_LOGE(TAG, "could not open: '%s': %d", opts->dest.where, errno);
			return -SIF_PARTITION_ERROR;
		}

		patcher->dest.fd = fd;
		patcher->write_dest = sif_file_write_dest;
		patcher->write_done = sif_file_write_done;
	}

	if (opts->patch.type == SIF_SRC_PARTITION)
	{
		const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, opts->patch.where);
		if (partition == NULL)
			return -SIF_PARTITION_ERROR;

		patcher->patch.partition = partition;
		patcher->read_patch = sif_flash_read_patch;
	}
	else
	{
		int fd = open(opts->patch.where, O_RDONLY);
		if (fd <= 0)
		{
			ESP_LOGE(TAG, "could not open '%s': %d", opts->patch.where, errno);
			return -SIF_PARTITION_ERROR;
		}

		patcher->patch.fd = fd;
		patcher->read_patch = sif_file_read_patch;
	}

	esp_log_level_set("esp_image", ESP_LOG_ERROR);

	return SIF_OK;
}

static int sif_set_boot_partition(sif_patcher_t *patcher)
{
	if (esp_ota_set_boot_partition(patcher->dest.flash.partition) != ESP_OK)
		return -SIF_TARGET_IMAGE_ERROR;

	const esp_partition_t *boot_partition = esp_ota_get_boot_partition();
	ESP_LOGI(TAG, "next boot partition: subtype %d offset 0x%x", boot_partition->subtype, boot_partition->address);
	ESP_LOGI(TAG, "ready to reboot");

	return SIF_OK;
}

typedef void *bootloader_sha256_handle_t;
bootloader_sha256_handle_t bootloader_sha256_start(void);
void bootloader_sha256_data(bootloader_sha256_handle_t handle, const void *data, size_t data_len);
void bootloader_sha256_finish(bootloader_sha256_handle_t handle, uint8_t *digest);

static int sif_compute_checksum(const sif_source_t source, uint8_t *buffer, size_t buffer_size, uint8_t *checksum)
{
	sif_assert(source.where && strlen(source.where) > 0);
	sif_assert(buffer && buffer_size > 0);
	sif_assert(checksum);

	if (source.type == SIF_SRC_PARTITION)
	{
		const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
			ESP_PARTITION_SUBTYPE_ANY, source.where);
		if (partition == NULL)
			return -SIF_PARTITION_ERROR;

		esp_err_t ret = bootloader_common_get_sha256_of_partition(partition->address,
			partition->size, ESP_PARTITION_TYPE_APP, checksum);
		if (ret != ESP_OK)
			return -SIF_CHECKSUM_ERROR;
	}
	else if (source.type == SIF_SRC_FILE)
	{
		struct stat st;
		stat(source.where, &st);

		size_t size = st.st_size;
		size_t left = size;
		if (size > 32)
			left -= 32;

		int fd = open(source.where, O_RDONLY);
		if (fd < 0)
			return -SIF_CHECKSUM_ERROR;

		bootloader_sha256_handle_t ctx = bootloader_sha256_start();

		int res;
		while ((res = read(fd, buffer, MIN(buffer_size, left))) > 0)
		{
			bootloader_sha256_data(ctx, buffer, res);
			left -= res;
		}

		bootloader_sha256_finish(ctx, checksum);

		close(fd);
		if (res < 0)
			return -SIF_CHECKSUM_ERROR;
	}

	return SIF_OK;
}

static int sif_patcher_finalise(sif_patcher_t *patcher, uint8_t *digest)
{
	int ret = sif_all_write_done(patcher);
	if (ret != SIF_OK)
	{
		free(patcher->buffer);
		return -SIF_TARGET_IMAGE_ERROR;
	}

	if (digest)
	{
		ESP_LOGI(TAG, "computing digest...");
		return sif_compute_checksum(patcher->opts.dest, patcher->buffer, patcher->buffer_size, digest);
	}

	free(patcher->buffer);

	return SIF_OK;
}

int sif_patch_init(sif_patch_writer_t **writer, const char *where, int patch_size)
{
	esp_err_t res = ESP_OK;

	sif_assert(writer && where && patch_size > 0);
	sif_assert(strlen(where) > 0);

	sif_patch_writer_t *out = malloc(sizeof(sif_patch_writer_t));
	if (!out)
		return -SIF_OUT_OF_MEMORY;

	out->offset = 0;
	out->size = patch_size;
	out->name = where;
	out->type.where = where;

	if (where[0] == '/')
	{
		out->type.type = SIF_SRC_FILE;

		int fd = open(out->name, O_CREAT | O_TRUNC | O_RDWR);
		if (fd < 0)
		{
			ESP_LOGE(TAG, "could not open file '%s': %d", out->name, errno);
			res = ESP_FAIL;
			goto ERROR;
		}

		out->fd = fd;
	}
	else
	{
		out->type.type = SIF_SRC_PARTITION;

		const esp_partition_t *flash = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
			ESP_PARTITION_SUBTYPE_DATA_SPIFFS, out->name);
		if (flash == NULL)
		{
			ESP_LOGE(TAG, "could not find '%s' partition", out->name);
			res = ESP_FAIL;
			goto ERROR;
		}

		size_t page_size = (patch_size + PARTITION_PAGE_SIZE) - (patch_size % PARTITION_PAGE_SIZE);
		res = esp_partition_erase_range(flash, 0, page_size);
		if (res != ESP_OK)
		{
			ESP_LOGE(TAG, "could not erase '%s' region!", out->name);
			goto ERROR;
		}

		out->flash = flash;
	}

	*writer = out;
	return res;

ERROR:
	free(out);
	return res;
}

int sif_patch_write(sif_patch_writer_t *writer, const char *buf, int size)
{
	sif_assert(writer && buf);

	if (writer->offset >= writer->size)
		return -SIF_OUT_OF_BOUNDS_ERROR;

	if (writer->type.type == SIF_SRC_PARTITION)
	{
		if (esp_partition_write(writer->flash, writer->offset, buf, size) != ESP_OK)
		{
			ESP_LOGE(TAG, "could not write to partition '%s'", writer->name);
			return ESP_FAIL;
		}
	}
	else
	{
		if (write(writer->fd, buf, size) < 0)
		{
			ESP_LOGE(TAG, "could not write to file '%s'", writer->name);
			return ESP_FAIL;
		}
	}

	writer->offset += size;
	return ESP_OK;
}

void sif_patch_free(sif_patch_writer_t *writer)
{
	if (writer && writer->type.type == SIF_SRC_FILE && writer->fd)
	{
		close(writer->fd);
		writer->fd = 0;
	}

	free(writer);
}

typedef struct digest_ctx
{
	uint8_t digest[32];
	char str[65];
} digest_ctx;


int sif_check_and_apply(int patch_size, const sif_opts_t *opts, const uint8_t *digest)
{
	static const sif_opts_t DEFAULT_SIF_OPTS = INIT_DEFAULT_SIF_OPTS();

	digest_ctx *ctx = NULL;

	int ret = SIF_OK;

	ESP_LOGI(TAG, "initialising sif update...");

	if (patch_size <= 0)
		return patch_size;

	sif_patcher_t *patcher = calloc(1, sizeof(sif_patcher_t));
	if (!patcher)
		return -SIF_OUT_OF_MEMORY;

	if (!opts)
		opts = &DEFAULT_SIF_OPTS;

	ret = sif_patcher_init(patcher, opts);
	if (ret != SIF_OK)
	{
		ret = -SIF_TARGET_IMAGE_ERROR;
		goto ERROR;
	}

	ESP_LOGI(TAG, "applying patch...");
	ret = detools_apply_patch_callbacks(patcher->read_src,
		patcher->seek_src, patcher->read_patch, (size_t)patch_size,
		sif_all_write_dest, patcher);
	if (ret <= 0)
	{
		ret = -SIF_TARGET_IMAGE_ERROR;
		goto ERROR;
	}

	ESP_LOGI(TAG, "finalising patch...");

	ctx = calloc(1, sizeof(digest_ctx));
	if (!ctx)
	{
		ret = -SIF_OUT_OF_MEMORY;
		goto ERROR;
	}

	ret = sif_patcher_finalise(patcher, ctx->digest);
	if (ret != SIF_OK)
		goto ERROR;

	for (size_t i = 0; i < 32; ++i)
		sprintf(ctx->str+i*2, "%02x", ctx->digest[i]);
	ESP_LOGI(TAG, "new image digest: %s", ctx->str);

	if (digest)
	{
		for (size_t i = 0; i < 32; ++i)
			sprintf(ctx->str+i*2, "%02x", (unsigned char)digest[i]);
		ESP_LOGI(TAG, "expected image digest: %s", ctx->str);

		if (memcmp(digest, ctx->digest, sizeof(ctx->digest)) != 0)
		{
			ESP_LOGE(TAG, "checksum mismatch!");
			ret = -SIF_CHECKSUM_ERROR;
			goto ERROR;
		}
	}

	if (opts->dest.type == SIF_SRC_PARTITION)
	{
		ret = sif_set_boot_partition(patcher);
		ESP_LOGI(TAG, "boot partition updated");
	}

	ESP_LOGI(TAG, "patch successful");
	ret = ESP_OK;

ERROR:
	free(patcher);
	free(ctx);
	return ret;
}

const char *sif_error_as_string(int error)
{
	if (error < 28)
		return detools_error_as_string(error);

	if (error < 0)
		error *= -1;

	switch (error)
	{
		case SIF_OUT_OF_MEMORY:
			return "Target partition out of memory.";
		case SIF_READING_PATCH_ERROR:
			return "Error reading patch binary.";
		case SIF_READING_SOURCE_ERROR:
			return "Error reading source image.";
		case SIF_WRITING_ERROR:
			return "Error writing to target image.";
		case SIF_SEEKING_ERROR:
			return "Seek error: source image.";
		case SIF_CASTING_ERROR:
			return "Error casting to patcher.";
		case SIF_INVALID_BUF_SIZE:
			return "Read/write buffer less or equal to 0.";
		case SIF_CLEARING_ERROR:
			return "Could not erase target region.";
		case SIF_PARTITION_ERROR:
			return "Flash partition not found.";
		case SIF_TARGET_IMAGE_ERROR:
			return "Invalid target image to boot from.";
		default:
			return "Unknown error.";
	}
}
