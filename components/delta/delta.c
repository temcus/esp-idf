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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

static const char *TAG = "delta";

typedef struct flash_mem {
	union {
		struct {
    		const esp_partition_t *partition;
			size_t offset;
		} flash;
	} src;
	union {
		struct {
    		const esp_partition_t *partition;
    		esp_ota_handle_t ota_handle;
		} flash;
	} dest;
	union {
		struct {
    		const esp_partition_t *partition;
			size_t offset;
		} flash;
	} patch;

	detools_read_t read_src;
	detools_seek_t seek_src;
	detools_read_t read_patch;
	detools_write_t write_dest;
} flash_mem_t;

typedef struct delta_patch_writer {
    const char *name;
    const void *patch;
    int offset;
    int size;
} delta_patch_writer_t;

static int delta_flash_write_dest(void *arg_p, const uint8_t *buf_p, size_t size)
{
    flash_mem_t *flash;
    flash = (flash_mem_t *)arg_p;

    if (!flash) {
        return -DELTA_CASTING_ERROR;
    }
    if (size <= 0) {
        return -DELTA_INVALID_BUF_SIZE;
    }

    if (esp_ota_write(flash->dest.flash.ota_handle, buf_p, size) != ESP_OK) {
        return -DELTA_WRITING_ERROR;
    }

    return DELTA_OK;
}

static int delta_flash_read_src(void *arg_p, uint8_t *buf_p, size_t size)
{
    flash_mem_t *flash;
    flash = (flash_mem_t *)arg_p;

    if (!flash) {
        return -DELTA_CASTING_ERROR;
    }
    if (size <= 0) {
        return -DELTA_INVALID_BUF_SIZE;
    }

    if (esp_partition_read(flash->src.flash.partition, flash->src.flash.offset, buf_p, size) != ESP_OK) {
        return -DELTA_READING_SOURCE_ERROR;
    }

    flash->src.flash.offset += size;
    if (flash->src.flash.offset >= flash->src.flash.partition->size) {
        return -DELTA_OUT_OF_MEMORY;
    }

    return DELTA_OK;
}

static int delta_flash_read_patch(void *arg_p, uint8_t *buf_p, size_t size)
{
    flash_mem_t *flash;
    flash = (flash_mem_t *)arg_p;

    if (!flash) {
        return -DELTA_CASTING_ERROR;
    }
    if (size <= 0) {
        return -DELTA_INVALID_BUF_SIZE;
    }

    if (esp_partition_read(flash->patch.flash.partition, flash->patch.flash.offset, buf_p, size) != ESP_OK) {
        return -DELTA_READING_PATCH_ERROR;
    }

    flash->patch.flash.offset += size;
    if (flash->patch.flash.offset >= flash->patch.flash.partition->size) {
        return -DELTA_READING_PATCH_ERROR;
    }

    return DELTA_OK;
}

static int delta_flash_seek_src(void *arg_p, int offset)
{
    flash_mem_t *flash;
    flash = (flash_mem_t *)arg_p;

    if (!flash) {
        return -DELTA_CASTING_ERROR;
    }

    flash->src.flash.offset += offset;
    if (flash->src.flash.offset >= flash->src.flash.partition->size) {
        return -DELTA_SEEKING_ERROR;
    }

    return DELTA_OK;
}

static int delta_init_flash_mem(flash_mem_t *flash, const delta_opts_t *opts)
{
    if (!flash || !opts) {
        return -DELTA_PARTITION_ERROR;
    }

    if (opts->src.type != DELTA_SRC_PARTITION ||
        opts->dest.type != DELTA_SRC_PARTITION ||
        opts->patch.type != DELTA_SRC_PARTITION) {
        return -DELTA_PARTITION_ERROR;
    }

    if ((opts->src.where && !opts->dest.where) || (!opts->src.where && opts->dest.where)) {
        return -DELTA_PARTITION_ERROR;
    }

    if (opts->src.where) {
        flash->src.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->src.where);
    } else {
        flash->src.flash.partition = esp_ota_get_running_partition();
    }

    if (opts->dest.where) {
        flash->dest.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, opts->dest.where);
    } else {
        flash->dest.flash.partition = esp_ota_get_next_update_partition(NULL);
    }

    flash->patch.flash.partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, opts->patch.where);

    if (flash->src.flash.partition == NULL || flash->dest.flash.partition == NULL || flash->patch.flash.partition == NULL) {
        return -DELTA_PARTITION_ERROR;
    }

    if (flash->src.flash.partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX ||
        flash->dest.flash.partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
        return -DELTA_PARTITION_ERROR;
    }

    if (esp_ota_begin(flash->dest.flash.partition, OTA_SIZE_UNKNOWN, &(flash->dest.flash.ota_handle)) != ESP_OK) {
        return -DELTA_PARTITION_ERROR;
    }
    esp_log_level_set("esp_image", ESP_LOG_ERROR);

    flash->src.flash.offset = 0;
    flash->patch.flash.offset = 0;
	flash->read_src = delta_flash_read_src;
	flash->seek_src = delta_flash_seek_src;
	flash->read_patch = delta_flash_read_patch;
	flash->write_dest = delta_flash_write_dest;

    return DELTA_OK;
}

static int delta_set_boot_partition(flash_mem_t *flash)
{
    if (esp_ota_set_boot_partition(flash->dest.flash.partition) != ESP_OK) {
        return -DELTA_TARGET_IMAGE_ERROR;
    }
    free(flash);

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
    delta_patch_writer_t *out = NULL;
    if (writer == NULL || partition == NULL) {
        return -DELTA_INVALID_ARGUMENT_ERROR;
    }

    const esp_partition_t *patch = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_DATA_SPIFFS, partition);
    if (patch == NULL) {
        ESP_LOGE(TAG, "Partition Error: Could not find '%s' partition", partition);
        return ESP_FAIL;
    }

    size_t patch_page_size = (patch_size + PARTITION_PAGE_SIZE) - (patch_size % PARTITION_PAGE_SIZE);
    if (esp_partition_erase_range(patch, 0, patch_page_size) != ESP_OK) {
        ESP_LOGE(TAG, "Partition Error: Could not erase '%s' region!", partition);
        return ESP_FAIL;
    }

    out = malloc(sizeof(delta_patch_writer_t));
    if (!out) {
        return -DELTA_OUT_OF_MEMORY;
    }

    out->name = partition;
    out->patch = patch;
    out->size = patch_size;
    out->offset = 0;

    *writer = out;

    return ESP_OK;
}

int delta_patch_write(delta_patch_writer_t *writer, const char *buf, int size)
{
    if (writer == NULL || buf == NULL) {
        return -DELTA_INVALID_ARGUMENT_ERROR;
    }

    if (writer->offset >= writer->size) {
        return -DELTA_OUT_OF_BOUNDS_ERROR;
    }

    if (esp_partition_write(writer->patch, writer->offset, buf, size) != ESP_OK) {
        ESP_LOGE(TAG, "Partition Error: Could not write to '%s' region!", writer->name);
        return ESP_FAIL;
    };

    writer->offset += size;
    return ESP_OK;
}

void delta_patch_free(delta_patch_writer_t *writer)
{
    free(writer);
}

int delta_check_and_apply(int patch_size, const delta_opts_t *opts, const char *digest)
{
    static const delta_opts_t DEFAULT_DELTA_OPTS = INIT_DEFAULT_DELTA_OPTS();

    ESP_LOGI(TAG, "Initializing delta update...");

    flash_mem_t *flash = NULL;
    int ret = 0;

    if (patch_size < 0) {
        return patch_size;
    } else if (patch_size > 0) {
        flash = calloc(1, sizeof(flash_mem_t));
        if (!flash) {
            return -DELTA_OUT_OF_MEMORY;
        }

        if (!opts) {
            opts = &DEFAULT_DELTA_OPTS;
        }

        ret = delta_init_flash_mem(flash, opts);
        if (ret) {
            return ret;
        }

        ret = detools_apply_patch_callbacks(flash->read_src,
                                            flash->seek_src,
                                            flash->read_patch,
                                            (size_t) patch_size,
                                            flash->write_dest,
                                            flash);

        if (ret <= 0) {
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
        return delta_set_boot_partition(flash);
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
        return "Error casting to flash_mem_t.";
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
