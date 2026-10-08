LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := ghostchat_tor_bridge
LOCAL_SRC_FILES := tor_bridge.c
LOCAL_CFLAGS := -std=c11 -Wall -Wextra -Werror -fvisibility=hidden
LOCAL_LDLIBS := -ldl -llog

include $(BUILD_SHARED_LIBRARY)
