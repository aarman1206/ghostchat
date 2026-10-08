/*
 * GhostChat's minimal JNI bridge to the public Tor embedding API.
 *
 * The Guardian payload is intentionally resolved at runtime instead of being
 * linked here. This keeps the bridge buildable while the pinned native
 * payload's provenance/licensing gate is reviewed, and makes a missing or
 * incompatible payload an explicit runtime failure. It never falls back to a
 * system executable, Orbot, another app, or a clearnet proxy.
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    TOR_BRIDGE_INVALID_ARGUMENT = -1000,
    TOR_BRIDGE_RUNTIME_UNAVAILABLE = -1001,
    TOR_BRIDGE_ALREADY_STARTED = -1002,
    TOR_BRIDGE_ALLOCATION_FAILED = -1003,
    TOR_BRIDGE_CONFIGURATION_FAILED = -1004,
};

typedef struct tor_main_configuration_t tor_main_configuration_t;
typedef tor_main_configuration_t *(*tor_configuration_new_fn)(void);
typedef int (*tor_configuration_set_command_line_fn)(
    tor_main_configuration_t *, int, char **);
typedef void (*tor_configuration_free_fn)(tor_main_configuration_t *);
typedef int (*tor_run_main_fn)(const tor_main_configuration_t *);
typedef const char *(*tor_provider_version_fn)(void);

typedef struct {
    void *handle;
    tor_configuration_new_fn configuration_new;
    tor_configuration_set_command_line_fn configuration_set_command_line;
    tor_configuration_free_fn configuration_free;
    tor_run_main_fn run_main;
    tor_provider_version_fn provider_version;
} tor_api_t;

static tor_api_t g_tor_api;
static pthread_mutex_t g_api_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool g_run_started = ATOMIC_VAR_INIT(false);

#define TOR_LOG_TAG "GhostChatTorNative"

static void *lookup_symbol(void *handle, const char *name) {
    return dlsym(handle, name);
}

static int resolve_tor_api(void) {
    int result = 0;

    pthread_mutex_lock(&g_api_mutex);
    if (g_tor_api.handle != NULL) {
        result = 1;
        goto done;
    }

    /* libtor.so is expected to be an APK-native library loaded in this
     * process. A missing library is a hard failure, not a fallback point. */
    void *handle = dlopen("libtor.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        const char *error = dlerror();
        __android_log_print(
            ANDROID_LOG_ERROR,
            TOR_LOG_TAG,
            "dlopen libtor.so failed: %s",
            error != NULL ? error : "no loader detail"
        );
        goto done;
    }

    g_tor_api.configuration_new =
        (tor_configuration_new_fn)lookup_symbol(handle, "tor_main_configuration_new");
    g_tor_api.configuration_set_command_line =
        (tor_configuration_set_command_line_fn)lookup_symbol(
            handle, "tor_main_configuration_set_command_line");
    g_tor_api.configuration_free =
        (tor_configuration_free_fn)lookup_symbol(handle, "tor_main_configuration_free");
    g_tor_api.run_main =
        (tor_run_main_fn)lookup_symbol(handle, "tor_run_main");
    g_tor_api.provider_version =
        (tor_provider_version_fn)lookup_symbol(handle, "tor_api_get_provider_version");

    if (g_tor_api.configuration_new == NULL ||
        g_tor_api.configuration_set_command_line == NULL ||
        g_tor_api.configuration_free == NULL ||
        g_tor_api.run_main == NULL ||
        g_tor_api.provider_version == NULL) {
        __android_log_print(
            ANDROID_LOG_ERROR,
            TOR_LOG_TAG,
            "libtor.so is missing one or more required embedding symbols"
        );
        memset(&g_tor_api, 0, sizeof(g_tor_api));
        dlclose(handle);
        goto done;
    }

    g_tor_api.handle = handle;
    result = 1;
    const char *provider_version = g_tor_api.provider_version();
    __android_log_print(
        ANDROID_LOG_INFO,
        TOR_LOG_TAG,
        "libtor.so loaded; required embedding symbols resolved; provider=%s",
        provider_version != NULL && provider_version[0] != '\0'
            ? provider_version
            : "unknown"
    );

done:
    pthread_mutex_unlock(&g_api_mutex);
    return result;
}

static void free_arguments(char **argv, jsize argc) {
    if (argv == NULL) {
        return;
    }
    for (jsize index = 0; index < argc; ++index) {
        free(argv[index]);
    }
    free(argv);
}

static int copy_java_arguments(JNIEnv *env, jobjectArray java_args,
                               char ***out_argv, jsize *out_argc) {
    if (java_args == NULL || out_argv == NULL || out_argc == NULL) {
        return TOR_BRIDGE_INVALID_ARGUMENT;
    }

    const jsize argc = (*env)->GetArrayLength(env, java_args);
    if (argc < 1 || argc > 128) {
        return TOR_BRIDGE_INVALID_ARGUMENT;
    }

    /* Keep the conventional argv[argc] sentinel as well as every argument;
     * Tor's command-line parser receives this array as a normal main() argv. */
    char **argv = (char **)calloc((size_t)argc + 1U, sizeof(char *));
    if (argv == NULL) {
        return TOR_BRIDGE_ALLOCATION_FAILED;
    }

    for (jsize index = 0; index < argc; ++index) {
        jstring java_arg = (jstring)(*env)->GetObjectArrayElement(env, java_args, index);
        if (java_arg == NULL) {
            free_arguments(argv, argc);
            return TOR_BRIDGE_INVALID_ARGUMENT;
        }

        const char *utf_arg = (*env)->GetStringUTFChars(env, java_arg, NULL);
        if (utf_arg == NULL) {
            (*env)->DeleteLocalRef(env, java_arg);
            free_arguments(argv, argc);
            return TOR_BRIDGE_ALLOCATION_FAILED;
        }

        const size_t length = strlen(utf_arg);
        if (length == 0 || length > 16384) {
            (*env)->ReleaseStringUTFChars(env, java_arg, utf_arg);
            (*env)->DeleteLocalRef(env, java_arg);
            free_arguments(argv, argc);
            return TOR_BRIDGE_INVALID_ARGUMENT;
        }

        argv[index] = (char *)malloc(length + 1);
        if (argv[index] == NULL) {
            (*env)->ReleaseStringUTFChars(env, java_arg, utf_arg);
            (*env)->DeleteLocalRef(env, java_arg);
            free_arguments(argv, argc);
            return TOR_BRIDGE_ALLOCATION_FAILED;
        }
        memcpy(argv[index], utf_arg, length + 1);
        (*env)->ReleaseStringUTFChars(env, java_arg, utf_arg);
        (*env)->DeleteLocalRef(env, java_arg);
    }

    *out_argv = argv;
    *out_argc = argc;
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_org_lord_ghostchat_tor_TorNativeBridge_nativeIsAvailable(
    JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return resolve_tor_api() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_org_lord_ghostchat_tor_TorNativeBridge_nativeProviderVersion(
    JNIEnv *env, jclass clazz) {
    (void)clazz;
    if (!resolve_tor_api()) {
        return NULL;
    }

    const char *version = g_tor_api.provider_version();
    if (version == NULL || version[0] == '\0') {
        return NULL;
    }
    return (*env)->NewStringUTF(env, version);
}

JNIEXPORT jint JNICALL
Java_org_lord_ghostchat_tor_TorNativeBridge_nativeRun(
    JNIEnv *env, jclass clazz, jobjectArray java_args, jboolean capture_diagnostics) {
    (void)clazz;
    if (!resolve_tor_api()) {
        return TOR_BRIDGE_RUNTIME_UNAVAILABLE;
    }
    if (atomic_exchange(&g_run_started, true)) {
        return TOR_BRIDGE_ALREADY_STARTED;
    }

    char **argv = NULL;
    jsize argc = 0;
    int result = copy_java_arguments(env, java_args, &argv, &argc);
    if (result != 0) {
        atomic_store(&g_run_started, false);
        return result;
    }

    tor_main_configuration_t *configuration = g_tor_api.configuration_new();
    if (configuration == NULL) {
        free_arguments(argv, argc);
        atomic_store(&g_run_started, false);
        return TOR_BRIDGE_ALLOCATION_FAILED;
    }

    if (g_tor_api.configuration_set_command_line(configuration, (int)argc, argv) != 0) {
        g_tor_api.configuration_free(configuration);
        free_arguments(argv, argc);
        atomic_store(&g_run_started, false);
        return TOR_BRIDGE_CONFIGURATION_FAILED;
    }

    int diagnostic_fd = -1;
    int saved_stdout = -1;
    int saved_stderr = -1;
    int capture_active = 0;
    if (capture_diagnostics == JNI_TRUE && argc >= 4 &&
        strlen(argv[3]) >= strlen("torrc")) {
        const size_t directory_length = strlen(argv[3]) - strlen("torrc");
        const char diagnostic_name[] = "tor-native.log";
        char *diagnostic_path =
            (char *)malloc(directory_length + sizeof(diagnostic_name));
        if (diagnostic_path != NULL) {
            memcpy(diagnostic_path, argv[3], directory_length);
            memcpy(diagnostic_path + directory_length, diagnostic_name,
                   sizeof(diagnostic_name));
            diagnostic_fd = open(diagnostic_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            free(diagnostic_path);
        }
        if (diagnostic_fd >= 0) {
            saved_stdout = dup(STDOUT_FILENO);
            saved_stderr = dup(STDERR_FILENO);
            if (saved_stdout >= 0 && saved_stderr >= 0 &&
                dup2(diagnostic_fd, STDOUT_FILENO) >= 0 &&
                dup2(diagnostic_fd, STDERR_FILENO) >= 0) {
                capture_active = 1;
            }
        }
    }

    /* argv and configuration remain live until tor_run_main returns, as
     * required by Tor's public API. This worker process performs no second
     * Tor run after this call. */
    result = g_tor_api.run_main(configuration);
    if (capture_active) {
        fflush(NULL);
        (void)dup2(saved_stdout, STDOUT_FILENO);
        (void)dup2(saved_stderr, STDERR_FILENO);
    }
    if (saved_stdout >= 0) {
        close(saved_stdout);
    }
    if (saved_stderr >= 0) {
        close(saved_stderr);
    }
    if (diagnostic_fd >= 0) {
        close(diagnostic_fd);
    }
    g_tor_api.configuration_free(configuration);
    free_arguments(argv, argc);
    return result;
}
