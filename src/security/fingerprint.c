/*
 * Fingerprint Authentication using libfprint-2
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "fingerprint.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_LIBFPRINT
#include <fprint.h>
#endif

/* Storage paths */
#define FP_STORAGE_DIR    ".riscv_wallet/fingerprints"
#define FP_PRINT_PREFIX   "print_"

#ifdef HAVE_LIBFPRINT

/* Libfprint context and device */
static FpContext *g_context = NULL;
static FpDevice *g_device = NULL;
static FpPrint *g_enrolled_prints[FP_MAX_SLOTS] = {0};
static int g_initialized = 0;
static int g_timeout = 30;  /* Default 30 second timeout */
static char g_device_name[128] = {0};
static char g_storage_path[256] = {0};

/* Forward declarations */
static int ensure_storage_directory(void);
static int save_print_to_file(FpPrint *print, int slot);
static FpPrint *load_print_from_file(int slot);
static void delete_print_file(int slot);

static int ensure_storage_directory(void)
{
    char parent_path[256];
    const char *home;
    struct stat st;

    home = getenv("HOME");
    if (home == NULL) {
        home = "/tmp";
    }

    /* Create parent .riscv_wallet directory */
    snprintf(parent_path, sizeof(parent_path), "%s/.riscv_wallet", home);
    if (stat(parent_path, &st) != 0) {
        if (mkdir(parent_path, 0700) != 0 && errno != EEXIST) {
            return -1;
        }
    }

    /* Create fingerprints subdirectory */
    snprintf(g_storage_path, sizeof(g_storage_path), "%s/%s", home, FP_STORAGE_DIR);
    if (stat(g_storage_path, &st) != 0) {
        if (mkdir(g_storage_path, 0700) != 0 && errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

static int save_print_to_file(FpPrint *print, int slot)
{
    char path[512];
    guchar *data = NULL;
    gsize data_len = 0;
    FILE *fp;
    GError *error = NULL;

    if (print == NULL || slot < 0 || slot >= FP_MAX_SLOTS) {
        return -1;
    }

    /* Serialize print to binary data */
    if (!fp_print_serialize(print, &data, &data_len, &error)) {
        fprintf(stderr, "[fingerprint] Failed to serialize print: %s\n",
                error ? error->message : "unknown error");
        if (error) g_error_free(error);
        return -1;
    }

    /* Write to file */
    snprintf(path, sizeof(path), "%s/%s%d.dat", g_storage_path, FP_PRINT_PREFIX, slot);
    fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "[fingerprint] Failed to open print file: %s\n", path);
        g_free(data);
        return -1;
    }

    if (fwrite(data, 1, data_len, fp) != data_len) {
        fprintf(stderr, "[fingerprint] Failed to write print data\n");
        fclose(fp);
        g_free(data);
        return -1;
    }

    fclose(fp);
    g_free(data);

    /* Set restrictive permissions */
    chmod(path, 0600);

    return 0;
}

static FpPrint *load_print_from_file(int slot)
{
    char path[512];
    FILE *fp;
    struct stat st;
    guchar *data = NULL;
    gsize data_len;
    FpPrint *print = NULL;
    GError *error = NULL;

    if (slot < 0 || slot >= FP_MAX_SLOTS) {
        return NULL;
    }

    snprintf(path, sizeof(path), "%s/%s%d.dat", g_storage_path, FP_PRINT_PREFIX, slot);

    if (stat(path, &st) != 0) {
        return NULL;  /* File doesn't exist */
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }

    data_len = st.st_size;
    data = g_malloc(data_len);
    if (data == NULL) {
        fclose(fp);
        return NULL;
    }

    if (fread(data, 1, data_len, fp) != data_len) {
        fclose(fp);
        g_free(data);
        return NULL;
    }
    fclose(fp);

    /* Deserialize print */
    print = fp_print_deserialize(data, data_len, &error);
    g_free(data);

    if (print == NULL) {
        if (error != NULL) {
            fprintf(stderr, "[fingerprint] Failed to deserialize print: %s\n",
                    error->message);
            g_error_free(error);
        }
        return NULL;
    }

    return print;
}

static void delete_print_file(int slot)
{
    char path[512];
    struct stat st;
    FILE *fp;
    size_t file_size;
    uint8_t *zeros;

    if (slot < 0 || slot >= FP_MAX_SLOTS) {
        return;
    }

    snprintf(path, sizeof(path), "%s/%s%d.dat", g_storage_path, FP_PRINT_PREFIX, slot);

    /* Securely overwrite before deleting */
    if (stat(path, &st) == 0) {
        file_size = st.st_size;
        zeros = calloc(1, file_size);
        if (zeros != NULL) {
            fp = fopen(path, "wb");
            if (fp != NULL) {
                fwrite(zeros, 1, file_size, fp);
                fclose(fp);
            }
            free(zeros);
        }
        remove(path);
    }
}

int fingerprint_init(void)
{
    GPtrArray *devices;

    if (g_initialized) {
        return FP_OK;
    }

    /* Ensure storage directory exists */
    if (ensure_storage_directory() != 0) {
        fprintf(stderr, "[fingerprint] Failed to create storage directory\n");
        return FP_ERR_INIT;
    }

    /* Create libfprint context */
    g_context = fp_context_new();
    if (g_context == NULL) {
        fprintf(stderr, "[fingerprint] Failed to create libfprint context\n");
        return FP_ERR_INIT;
    }

    /* Enumerate devices */
    devices = fp_context_get_devices(g_context);
    if (devices == NULL || devices->len == 0) {
        fprintf(stderr, "[fingerprint] No fingerprint devices found\n");
        g_object_unref(g_context);
        g_context = NULL;
        return FP_ERR_NO_DEVICE;
    }

    /* Use first available device */
    g_device = g_ptr_array_index(devices, 0);
    if (g_device == NULL) {
        fprintf(stderr, "[fingerprint] Failed to get device\n");
        g_object_unref(g_context);
        g_context = NULL;
        return FP_ERR_NO_DEVICE;
    }

    /* Reference the device so it's not freed when we're done with array */
    g_object_ref(g_device);

    /* Open device */
    GError *error = NULL;
    if (!fp_device_open_sync(g_device, NULL, &error)) {
        fprintf(stderr, "[fingerprint] Failed to open device: %s\n",
                error ? error->message : "unknown error");
        if (error) g_error_free(error);
        g_object_unref(g_device);
        g_object_unref(g_context);
        g_device = NULL;
        g_context = NULL;
        return FP_ERR_INIT;
    }

    /* Store device name */
    const char *name = fp_device_get_name(g_device);
    if (name != NULL) {
        strncpy(g_device_name, name, sizeof(g_device_name) - 1);
        g_device_name[sizeof(g_device_name) - 1] = '\0';
    } else {
        strcpy(g_device_name, "Unknown Device");
    }

    /* Load existing enrolled prints from storage */
    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        g_enrolled_prints[i] = load_print_from_file(i);
    }

    printf("[fingerprint] Initialized: %s\n", g_device_name);
    g_initialized = 1;

    return FP_OK;
}

void fingerprint_cleanup(void)
{
    GError *error = NULL;

    if (!g_initialized) {
        return;
    }

    /* Free enrolled prints */
    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        if (g_enrolled_prints[i] != NULL) {
            g_object_unref(g_enrolled_prints[i]);
            g_enrolled_prints[i] = NULL;
        }
    }

    /* Close device */
    if (g_device != NULL) {
        fp_device_close_sync(g_device, NULL, &error);
        if (error != NULL) {
            fprintf(stderr, "[fingerprint] Warning: error closing device: %s\n",
                    error->message);
            g_error_free(error);
        }
        g_object_unref(g_device);
        g_device = NULL;
    }

    /* Free context */
    if (g_context != NULL) {
        g_object_unref(g_context);
        g_context = NULL;
    }

    g_device_name[0] = '\0';
    g_initialized = 0;
    printf("[fingerprint] Cleaned up\n");
}

int fingerprint_is_available(void)
{
    return g_initialized && g_device != NULL;
}

const char *fingerprint_get_device_name(void)
{
    if (!g_initialized || g_device_name[0] == '\0') {
        return NULL;
    }
    return g_device_name;
}

/* Enrollment callback context */
typedef struct {
    fp_enroll_callback_t user_callback;
    void *user_data;
    int stage;
    int total_stages;
} enroll_cb_ctx_t;

static void enroll_progress_callback(FpDevice *device, gint completed_stages,
                                      FpPrint *print, gpointer user_data,
                                      GError *error)
{
    enroll_cb_ctx_t *ctx = (enroll_cb_ctx_t *)user_data;

    (void)device;
    (void)print;
    (void)error;

    ctx->stage = completed_stages;

    if (ctx->user_callback != NULL) {
        ctx->user_callback(completed_stages, ctx->total_stages, ctx->user_data);
    }

    printf("[fingerprint] Enrollment progress: %d/%d\n",
           completed_stages, ctx->total_stages);
}

int fingerprint_enroll(int slot, fp_enroll_callback_t callback, void *user_data)
{
    FpPrint *template_print = NULL;
    FpPrint *enrolled_print = NULL;
    GError *error = NULL;
    enroll_cb_ctx_t cb_ctx;
    char print_id[64];

    if (!g_initialized || g_device == NULL) {
        return FP_ERR_INIT;
    }

    if (slot < 0 || slot >= FP_MAX_SLOTS) {
        return FP_ERR_SLOT;
    }

    /* Delete existing print in this slot if any */
    if (g_enrolled_prints[slot] != NULL) {
        g_object_unref(g_enrolled_prints[slot]);
        g_enrolled_prints[slot] = NULL;
        delete_print_file(slot);
    }

    /* Create template for new print */
    snprintf(print_id, sizeof(print_id), "riscv_wallet_slot_%d", slot);
    template_print = fp_print_new(g_device);
    fp_print_set_username(template_print, "riscv_wallet");
    fp_print_set_description(template_print, print_id);

    /* Setup callback context */
    cb_ctx.user_callback = callback;
    cb_ctx.user_data = user_data;
    cb_ctx.stage = 0;
    cb_ctx.total_stages = fp_device_get_nr_enroll_stages(g_device);

    printf("[fingerprint] Starting enrollment (slot %d, %d stages)...\n",
           slot, cb_ctx.total_stages);
    printf("[fingerprint] Place your finger on the sensor...\n");

    /* Perform enrollment */
    enrolled_print = fp_device_enroll_sync(g_device,
                                           template_print,
                                           NULL,  /* cancellable */
                                           enroll_progress_callback,
                                           &cb_ctx,
                                           &error);

    g_object_unref(template_print);

    if (enrolled_print == NULL) {
        fprintf(stderr, "[fingerprint] Enrollment failed: %s\n",
                error ? error->message : "unknown error");
        if (error) g_error_free(error);
        return FP_ERR_ENROLL;
    }

    /* Save enrolled print */
    g_enrolled_prints[slot] = enrolled_print;

    /* Persist to file */
    if (save_print_to_file(enrolled_print, slot) != 0) {
        fprintf(stderr, "[fingerprint] Warning: failed to save print to storage\n");
    }

    printf("[fingerprint] Enrollment successful (slot %d)\n", slot);
    return FP_OK;
}

int fingerprint_verify(fp_verify_callback_t callback, void *user_data)
{
    GError *error = NULL;
    gboolean match = FALSE;
    FpPrint *matched_print = NULL;
    FpPrint *scanned_print = NULL;
    int retry_count = 0;
    const int max_retries = 3;

    if (!g_initialized || g_device == NULL) {
        return FP_ERR_INIT;
    }

    /* Check if any prints are enrolled */
    int enrolled_count = fingerprint_get_enrolled_count();
    if (enrolled_count == 0) {
        fprintf(stderr, "[fingerprint] No fingerprints enrolled\n");
        return FP_ERR_NO_MATCH;
    }

    /* Build array of enrolled prints for identification */
    GPtrArray *prints = g_ptr_array_new();
    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        if (g_enrolled_prints[i] != NULL) {
            g_ptr_array_add(prints, g_enrolled_prints[i]);
        }
    }

    printf("[fingerprint] Place your finger on the sensor to verify...\n");

    while (retry_count < max_retries) {
        if (callback != NULL) {
            callback(retry_count, user_data);
        }

        /* Try identification against all enrolled prints */
        match = fp_device_identify_sync(g_device,
                                         prints,
                                         NULL,  /* cancellable */
                                         NULL,  /* match callback */
                                         NULL,  /* match callback data */
                                         &matched_print,
                                         &scanned_print,
                                         &error);

        if (error != NULL) {
            fprintf(stderr, "[fingerprint] Verification error: %s\n", error->message);
            g_error_free(error);
            error = NULL;
            retry_count++;
            continue;
        }

        if (match && matched_print != NULL) {
            printf("[fingerprint] Verification successful\n");
            g_ptr_array_unref(prints);
            return FP_OK;
        }

        printf("[fingerprint] No match, try again (%d/%d)\n",
               retry_count + 1, max_retries);
        retry_count++;
    }

    g_ptr_array_unref(prints);

    fprintf(stderr, "[fingerprint] Verification failed after %d attempts\n",
            max_retries);
    return FP_ERR_NO_MATCH;
}

int fingerprint_identify(int *matched_slot)
{
    GError *error = NULL;
    gboolean match = FALSE;
    FpPrint *matched_print = NULL;
    FpPrint *scanned_print = NULL;

    if (matched_slot != NULL) {
        *matched_slot = -1;
    }

    if (!g_initialized || g_device == NULL) {
        return FP_ERR_INIT;
    }

    /* Check if any prints are enrolled */
    int enrolled_count = fingerprint_get_enrolled_count();
    if (enrolled_count == 0) {
        return FP_ERR_NO_MATCH;
    }

    /* Build array of enrolled prints */
    GPtrArray *prints = g_ptr_array_new();
    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        if (g_enrolled_prints[i] != NULL) {
            g_ptr_array_add(prints, g_enrolled_prints[i]);
        }
    }

    /* Identify */
    match = fp_device_identify_sync(g_device,
                                     prints,
                                     NULL,  /* cancellable */
                                     NULL,  /* match callback */
                                     NULL,  /* match callback data */
                                     &matched_print,
                                     &scanned_print,
                                     &error);

    g_ptr_array_unref(prints);

    if (error != NULL) {
        fprintf(stderr, "[fingerprint] Identify error: %s\n", error->message);
        g_error_free(error);
        return FP_ERR_VERIFY;
    }

    if (!match || matched_print == NULL) {
        return FP_ERR_NO_MATCH;
    }

    /* Find which slot matched */
    if (matched_slot != NULL) {
        for (int i = 0; i < FP_MAX_SLOTS; i++) {
            if (g_enrolled_prints[i] == matched_print) {
                *matched_slot = i;
                break;
            }
        }
    }

    return FP_OK;
}

int fingerprint_delete(int slot)
{
    if (!g_initialized) {
        return FP_ERR_INIT;
    }

    if (slot < 0 || slot >= FP_MAX_SLOTS) {
        return FP_ERR_SLOT;
    }

    if (g_enrolled_prints[slot] != NULL) {
        g_object_unref(g_enrolled_prints[slot]);
        g_enrolled_prints[slot] = NULL;
    }

    /* Delete from storage */
    delete_print_file(slot);

    printf("[fingerprint] Deleted print from slot %d\n", slot);
    return FP_OK;
}

int fingerprint_delete_all(void)
{
    if (!g_initialized) {
        return FP_ERR_INIT;
    }

    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        if (g_enrolled_prints[i] != NULL) {
            g_object_unref(g_enrolled_prints[i]);
            g_enrolled_prints[i] = NULL;
        }
        delete_print_file(i);
    }

    printf("[fingerprint] Deleted all enrolled prints\n");
    return FP_OK;
}

int fingerprint_get_enrolled_count(void)
{
    int count = 0;

    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        if (g_enrolled_prints[i] != NULL) {
            count++;
        }
    }

    return count;
}

int fingerprint_slot_enrolled(int slot)
{
    if (slot < 0 || slot >= FP_MAX_SLOTS) {
        return 0;
    }

    return g_enrolled_prints[slot] != NULL ? 1 : 0;
}

void fingerprint_set_timeout(int timeout)
{
    g_timeout = timeout;
}

#else /* !HAVE_LIBFPRINT */

/*
 * Stub implementations when libfprint is not available
 */

static int g_stub_initialized = 0;

int fingerprint_init(void)
{
    printf("[fingerprint] libfprint not available - fingerprint support disabled\n");
    g_stub_initialized = 1;
    return FP_ERR_NO_DEVICE;
}

void fingerprint_cleanup(void)
{
    g_stub_initialized = 0;
}

int fingerprint_is_available(void)
{
    return 0;
}

const char *fingerprint_get_device_name(void)
{
    return NULL;
}

int fingerprint_enroll(int slot, fp_enroll_callback_t callback, void *user_data)
{
    (void)slot;
    (void)callback;
    (void)user_data;
    return FP_ERR_NO_DEVICE;
}

int fingerprint_verify(fp_verify_callback_t callback, void *user_data)
{
    (void)callback;
    (void)user_data;
    return FP_ERR_NO_DEVICE;
}

int fingerprint_identify(int *matched_slot)
{
    if (matched_slot != NULL) {
        *matched_slot = -1;
    }
    return FP_ERR_NO_DEVICE;
}

int fingerprint_delete(int slot)
{
    (void)slot;
    return FP_ERR_NO_DEVICE;
}

int fingerprint_delete_all(void)
{
    return FP_ERR_NO_DEVICE;
}

int fingerprint_get_enrolled_count(void)
{
    return 0;
}

int fingerprint_slot_enrolled(int slot)
{
    (void)slot;
    return 0;
}

void fingerprint_set_timeout(int timeout)
{
    (void)timeout;
}

#endif /* HAVE_LIBFPRINT */
