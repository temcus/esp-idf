/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: 0
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
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bootloader_common.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"

#include "esp_partition.h"
#include "esp_ota_ops.h"

#include "detools.h"
#include "delta.h"

#ifndef delta_assert
#define delta_assert(cond) assert(cond)
#endif

static const char *TAG = "delta";

typedef struct delta_patcher {
	union {
		struct {
    		const esp_partition_t *partition;
			size_t offset;
		} flash;
		struct {
			int fd;
			size_t offset;
		} file;
	} src;
	union {
		struct {
    		const esp_partition_t *partition;
    		esp_ota_handle_t ota_handle;
		} flash;
		struct {
			int fd;
			size_t offset;
		} file;
	} dest;
	union {
		struct {
    		const esp_partition_t *partition;
			size_t offset;
		} flash;
		struct {
			int fd;
			size_t offset;
		} file;
	} patch;

	delta_opts_t opts;

	detools_read_t read_src;
	detools_seek_t seek_src;
	detools_read_t read_patch;
	detools_write_t write_dest;
} delta_patcher_t;

struct delta_patch_writer {
    const char *name;
	union {
    	const void *flash;
		int fd;
	};
    int offset;
    int size;
	delta_source_t type;
};

static int delta_file_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;
	return DELTA_OK;
}

static int delta_file_read_src(void *arg_p, uint8_t *buf_p, size_t size)
{
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;
	return DELTA_OK;
}

static int delta_file_read_patch(void *arg_p, uint8_t *buf_p, size_t size)
{
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;
	return DELTA_OK;
}

static int delta_file_seek_src(void *arg_p, int offset)
{
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;
	return DELTA_OK;
}

static int delta_flash_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
	delta_assert(arg_p && buf_p && size > 0);
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;

    if (esp_ota_write(patcher->dest.flash.ota_handle, buf_p, size) != ESP_OK) {
        return -DELTA_WRITING_ERROR;
    }

    return DELTA_OK;
}

static int delta_flash_read_src(void *arg_p, uint8_t *buf_p, size_t size)
{
	delta_assert(arg_p && buf_p && size > 0);
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;

    if (esp_partition_read(patcher->src.flash.partition, patcher->src.flash.offset, buf_p, size) != ESP_OK) {
        return -DELTA_READING_SOURCE_ERROR;
    }

    patcher->src.flash.offset += size;
    if (patcher->src.flash.offset >= patcher->src.flash.partition->size) {
        return -DELTA_OUT_OF_MEMORY;
    }

    return DELTA_OK;
}

static int delta_flash_read_patch(void *arg_p, uint8_t *buf_p, size_t size)
{
	delta_assert(arg_p && buf_p && size > 0);
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;

    if (esp_partition_read(patcher->patch.flash.partition, patcher->patch.flash.offset, buf_p, size) != ESP_OK) {
        return -DELTA_READING_PATCH_ERROR;
    }

    patcher->patch.flash.offset += size;
    if (patcher->patch.flash.offset >= patcher->patch.flash.partition->size) {
        return -DELTA_READING_PATCH_ERROR;
    }

    return DELTA_OK;
}

static int delta_flash_seek_src(void *arg_p, int offset)
{
	delta_assert(arg_p);
    delta_patcher_t *patcher = (delta_patcher_t *)arg_p;

    patcher->src.flash.offset += offset;
    if (patcher->src.flash.offset >= patcher->src.flash.partition->size) {
        return -DELTA_SEEKING_ERROR;
    }

    return DELTA_OK;
}

static int delta_patcher_init(delta_patcher_t *patcher, const delta_opts_t *opts)
{
	delta_assert(patcher && opts);

    delta_assert(opts->src.type == DELTA_SRC_PARTITION &&
        opts->dest.type == DELTA_SRC_PARTITION &&
        opts->patch.type == DELTA_SRC_PARTITION);

    delta_assert((opts->src.where && opts->dest.where) || (!opts->src.where && !opts->dest.where));

    if (opts->src.where) {
        patcher->src.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->src.where);
    } else {
        patcher->src.flash.partition = esp_ota_get_running_partition();
    }

    if (opts->dest.where) {
        patcher->dest.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->dest.where);
    } else {
        patcher->dest.flash.partition = esp_ota_get_next_update_partition(NULL);
    }

    patcher->patch.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, opts->patch.where);

    if (patcher->src.flash.partition == NULL || patcher->dest.flash.partition == NULL || patcher->patch.flash.partition == NULL) {
        return -DELTA_PARTITION_ERROR;
    }

    if (patcher->src.flash.partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX ||
        patcher->dest.flash.partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
        return -DELTA_PARTITION_ERROR;
    }

    if (esp_ota_begin(patcher->dest.flash.partition, OTA_SIZE_UNKNOWN, &(patcher->dest.flash.ota_handle)) != ESP_OK) {
        return -DELTA_PARTITION_ERROR;
    }
    esp_log_level_set("esp_image", ESP_LOG_ERROR);

	memcpy(&patcher->opts, opts, sizeof(*opts));
    patcher->src.flash.offset = 0;
    patcher->patch.flash.offset = 0;
	patcher->read_src = delta_flash_read_src;
	patcher->seek_src = delta_flash_seek_src;
	patcher->read_patch = delta_flash_read_patch;
	patcher->write_dest = delta_flash_write_dest;

    return DELTA_OK;
}

static int delta_set_boot_partition(delta_patcher_t *patcher)
{
    if (esp_ota_set_boot_partition(patcher->dest.flash.partition) != ESP_OK) {
        return -DELTA_TARGET_IMAGE_ERROR;
    }
    free(patcher);

    const esp_partition_t *boot_partition = esp_ota_get_boot_partition();
    ESP_LOGI(TAG, "Next Boot Partition: Subtype %d at Offset 0x%x", boot_partition->subtype, boot_partition->address);
    ESP_LOGI(TAG, "Ready to reboot!!!");

    return DELTA_OK;
}

int delta_compute_checksum(const delta_source_t source, char *checksum)
{
    if (source.type != DELTA_SRC_PARTITION || !source.where || strlen(source.where) == 0) {
        return -DELTA_PARTITION_ERROR;
    }

    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
        ESP_PARTITION_SUBTYPE_ANY, source.where);
    if (partition == NULL) {
        return -DELTA_PARTITION_ERROR;
    }

    esp_err_t ret = bootloader_common_get_sha256_of_partition(partition->address,
        partition->size, ESP_PARTITION_TYPE_APP, (uint8_t *)checksum);
    if (ret != ESP_OK) {
        return -DELTA_CHECKSUM_ERROR;
    }

    return DELTA_OK;
}

int delta_patch_init(delta_patch_writer_t **writer, const char *partition, int patch_size)
{
	esp_err_t res = ESP_OK;

	delta_assert(writer && partition && patch_size > 0);
	delta_assert(strlen(partition) > 0);

	delta_patch_writer_t *out = malloc(sizeof(delta_patch_writer_t));
    if (!out) {
        return -DELTA_OUT_OF_MEMORY;
    }

    out->offset = 0;
    out->size = patch_size;
    out->name = partition;
	out->type.where = partition;

	if (partition[0] == '/') {
		out->type.type = DELTA_SRC_FILE;

		int fd = open(out->name, O_CREAT|O_TRUNC|O_RDWR);
		if (fd < 0) {
			ESP_LOGE(TAG, "could not open file '%s': %d", out->name, errno);
			res = ESP_FAIL;
			goto ERROR;
		}

		out->fd = fd;

	} else {
		out->type.type = DELTA_SRC_PARTITION;

		const esp_partition_t *flash = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
			ESP_PARTITION_SUBTYPE_DATA_SPIFFS, out->name);
		if (flash == NULL) {
			ESP_LOGE(TAG, "could not find '%s' partition", out->name);
			res = ESP_FAIL;
			goto ERROR;
		}

		size_t page_size = (patch_size + PARTITION_PAGE_SIZE) - (patch_size % PARTITION_PAGE_SIZE);
		res = esp_partition_erase_range(flash, 0, page_size);
		if (res != ESP_OK) {
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

int delta_patch_write(delta_patch_writer_t *writer, const char *buf, int size)
{
	delta_assert(writer && buf);

    if (writer->offset >= writer->size) {
        return -DELTA_OUT_OF_BOUNDS_ERROR;
    }

	if (writer->type.type == DELTA_SRC_PARTITION) {
		if (esp_partition_write(writer->flash, writer->offset, buf, size) != ESP_OK) {
			ESP_LOGE(TAG, "could not write to partition '%s'", writer->name);
			return ESP_FAIL;
		}
	} else {
		if (write(writer->fd, buf, size) < 0) {
			ESP_LOGE(TAG, "could not write to file '%s'", writer->name);
			return ESP_FAIL;
		}
	}

    writer->offset += size;
    return ESP_OK;
}

void delta_patch_free(delta_patch_writer_t *writer)
{
	if (writer) {
		if (writer->type.type == DELTA_SRC_FILE) {
			close(writer->fd);
		}
	}

    free(writer);
}

int delta_check_and_apply(int patch_size, const delta_opts_t *opts, const char *digest)
{
    static const delta_opts_t DEFAULT_DELTA_OPTS = INIT_DEFAULT_DELTA_OPTS();

    ESP_LOGI(TAG, "Initializing delta update...");

    delta_patcher_t *patcher = NULL;
    int ret = 0;

    if (patch_size < 0) {
        return patch_size;
    } else if (patch_size > 0) {
        patcher = calloc(1, sizeof(delta_patcher_t));
        if (!patcher) {
            return -DELTA_OUT_OF_MEMORY;
        }

        if (!opts) {
            opts = &DEFAULT_DELTA_OPTS;
        }

        ret = delta_patcher_init(patcher, opts);
        if (ret) {
            return ret;
        }

        ret = detools_apply_patch_callbacks(patcher->read_src,
                                            patcher->seek_src,
                                            patcher->read_patch,
                                            (size_t) patch_size,
                                            patcher->write_dest,
                                            patcher);

        if (ret <= 0) {
            return ret;
        }

		ret = esp_ota_end(patcher->dest.flash.ota_handle);
		if (ret != ESP_OK) {
        	return ret;
		}

        if (digest) {
            char new_digest[32];
            if (delta_compute_checksum(opts->dest, new_digest) != ESP_OK) {
                return ret;
            }

            if (memcmp(digest, new_digest, sizeof(new_digest)) != 0) {
                return -DELTA_CHECKSUM_ERROR;
            }
        }

        ESP_LOGI(TAG, "Patch Successful!!!");
        return delta_set_boot_partition(patcher);
    }

    return 0;
}

const char *delta_error_as_string(int error)
{
    if (error < 28) {
        return detools_error_as_string(error);
    }

    if (error < 0) {
        error *= -1;
    }

    switch (error) {
    case DELTA_OUT_OF_MEMORY:
        return "Target partition out of memory.";
    case DELTA_READING_PATCH_ERROR:
        return "Error reading patch binary.";
    case DELTA_READING_SOURCE_ERROR:
        return "Error reading source image.";
    case DELTA_WRITING_ERROR:
        return "Error writing to target image.";
    case DELTA_SEEKING_ERROR:
        return "Seek error: source image.";
    case DELTA_CASTING_ERROR:
        return "Error casting to patcher.";
    case DELTA_INVALID_BUF_SIZE:
        return "Read/write buffer less or equal to 0.";
    case DELTA_CLEARING_ERROR:
        return "Could not erase target region.";
    case DELTA_PARTITION_ERROR:
        return "Flash partition not found.";
    case DELTA_TARGET_IMAGE_ERROR:
        return "Invalid target image to boot from.";
    default:
        return "Unknown error.";
    }
}
