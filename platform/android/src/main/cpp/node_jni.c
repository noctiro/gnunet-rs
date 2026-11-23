#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gnunet_node.h"

static GnNode *node_from_handle(jlong handle) {
    return (GnNode *)(uintptr_t)handle;
}

static GnVpn *vpn_from_handle(jlong handle) {
    return (GnVpn *)(uintptr_t)handle;
}

struct SocketProtection {
    JavaVM *vm;
    jobject target;
    jmethodID protect;
};

static JNIEnv *callback_env(JavaVM *vm, int *attached) {
    JNIEnv *env = NULL;
    const jint status = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    *attached = 0;
    if (status == JNI_OK) {
        return env;
    }
    if (status != JNI_EDETACHED) {
        return NULL;
    }
    if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) {
        return NULL;
    }
    *attached = 1;
    return env;
}

static int32_t protect_socket(void *context, int32_t fd) {
    struct SocketProtection *owner = context;
    int attached;
    JNIEnv *env = callback_env(owner->vm, &attached);
    if (env == NULL) {
        return 0;
    }
    jboolean allowed = (*env)->CallBooleanMethod(env, owner->target, owner->protect, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        allowed = JNI_FALSE;
    }
    if (attached) {
        (*owner->vm)->DetachCurrentThread(owner->vm);
    }
    return allowed == JNI_TRUE;
}

static void release_protection(void *context) {
    struct SocketProtection *owner = context;
    int attached;
    JNIEnv *env = callback_env(owner->vm, &attached);
    if (env != NULL) {
        (*env)->DeleteGlobalRef(env, owner->target);
    }
    if (attached) {
        (*owner->vm)->DetachCurrentThread(owner->vm);
    }
    free(owner);
}

static void throw_error(JNIEnv *env, const char *class_name, const char *message) {
    jclass error = (*env)->FindClass(env, class_name);
    if (error != NULL) {
        (*env)->ThrowNew(env, error, message);
    }
}

static int copy_range(JNIEnv *env, jbyteArray array, GnBytes *out) {
    if (array == NULL) {
        return 1;
    }
    jsize len = (*env)->GetArrayLength(env, array);
    if (len > 65535) {
        return 0;
    }
    if (len == 0) {
        return 1;
    }
    uint8_t *bytes = malloc((size_t)len);
    if (bytes == NULL) {
        throw_error(env, "java/lang/OutOfMemoryError", "GNUnet node options");
        return 0;
    }
    out->data = bytes;
    out->len = (size_t)len;
    (*env)->GetByteArrayRegion(env, array, 0, len, (jbyte *)bytes);
    return !(*env)->ExceptionCheck(env);
}

static struct SocketProtection *create_protection(JNIEnv *env, jobject target) {
    JavaVM *vm = NULL;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK) {
        return NULL;
    }
    jclass type = (*env)->GetObjectClass(env, target);
    if (type == NULL) {
        return NULL;
    }
    jmethodID protect = (*env)->GetMethodID(env, type, "protect", "(I)Z");
    (*env)->DeleteLocalRef(env, type);
    if (protect == NULL) {
        return NULL;
    }
    struct SocketProtection *owner = malloc(sizeof(*owner));
    if (owner == NULL) {
        throw_error(env, "java/lang/OutOfMemoryError", "GNUnet VPN socket protection");
        return NULL;
    }
    jobject global_target = (*env)->NewGlobalRef(env, target);
    if (global_target == NULL) {
        free(owner);
        return NULL;
    }
    *owner = (struct SocketProtection){vm, global_target, protect};
    return owner;
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_start(
    JNIEnv *env, jobject receiver, jbyteArray state_dir, jbyteArray ipc_dir,
    jbyteArray config_file, jbyteArray bootstrap_data_dir, jbyteArray tcp_bind, jbyteArray udp4_bind,
    jbyteArray udp6_bind, jbyteArray dns_servers, jint startup_timeout_ms,
    jint drain_timeout_ms, jobject protector, jint maximum_packet, jlongArray handle_out) {
    (void)receiver;
    const int vpn_enabled = protector != NULL;
    const jsize handle_count = vpn_enabled ? 2 : 1;
    if (startup_timeout_ms <= 0 || drain_timeout_ms <= 0 || handle_out == NULL ||
        (*env)->GetArrayLength(env, handle_out) != handle_count ||
        (vpn_enabled && (maximum_packet < 68 || maximum_packet > UINT16_MAX)) ||
        (!vpn_enabled && maximum_packet != 0)) {
        return GNUNET_NODE_INVALID;
    }

    GnNodeOptions options = {
        .startup_timeout_ms = (uint32_t)startup_timeout_ms,
        .drain_timeout_ms = (uint32_t)drain_timeout_ms,
    };
    jbyteArray arrays[] = {state_dir, ipc_dir, config_file, bootstrap_data_dir, tcp_bind, udp4_bind,
                          udp6_bind, dns_servers};
    GnBytes *ranges[] = {&options.state_dir, &options.ipc_dir, &options.config_file,
                         &options.bootstrap_data_dir, &options.tcp_bind, &options.udp4_bind, &options.udp6_bind,
                         &options.dns_servers};
    const size_t count = sizeof(arrays) / sizeof(arrays[0]);
    GnNode *node = NULL;
    GnVpn *vpn = NULL;
    jint status = GNUNET_NODE_SETUP_ERROR;
    for (size_t i = 0; i < count; ++i) {
        if (!copy_range(env, arrays[i], ranges[i])) {
            goto cleanup;
        }
    }
    if (vpn_enabled) {
        struct SocketProtection *owner = create_protection(env, protector);
        if (owner == NULL) {
            goto cleanup;
        }
        const GnSocketProtection protection = {owner, protect_socket, release_protection};
        const GnVpnOptions vpn_options = {
            GNUNET_VPN_PEERS_LISTENING, GNUNET_VPN_UNIX_DESCRIPTOR, (uint16_t)maximum_packet, 0
        };
        /* The Rust entry takes the context even on configuration failure. */
        status = gnunet_node_start_with_protected_vpn(&options, &vpn_options, &protection, &node, &vpn);
    } else {
        status = gnunet_node_start(&options, &node);
    }
cleanup:
    for (size_t i = 0; i < count; ++i) {
        free((void *)ranges[i]->data);
    }
    if (status == GNUNET_NODE_OK && node != NULL && (!vpn_enabled || vpn != NULL)) {
        const jlong handles[] = {(jlong)(uintptr_t)node, (jlong)(uintptr_t)vpn};
        (*env)->SetLongArrayRegion(env, handle_out, 0, handle_count, handles);
        if ((*env)->ExceptionCheck(env)) {
            status = GNUNET_NODE_SETUP_ERROR;
        } else {
            return status;
        }
    }
    gnunet_vpn_destroy(vpn);
    gnunet_node_destroy(node);
    return status == GNUNET_NODE_OK ? GNUNET_NODE_SETUP_ERROR : status;
}

static GnVpnToken route_token(jlong epoch, jlong revision) {
    GnVpnToken token;
    /* Java long carries the complete unsigned ABI bit patterns. */
    memcpy(&token.epoch, &epoch, sizeof(epoch));
    memcpy(&token.revision, &revision, sizeof(revision));
    return token;
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_vpnNext(
    JNIEnv *env, jobject receiver, jlong handle, jlongArray token, jintArray fields, jbyteArray addresses) {
    (void)receiver;
    if (token == NULL || fields == NULL || addresses == NULL ||
        (*env)->GetArrayLength(env, token) != 2 || (*env)->GetArrayLength(env, fields) != 6 ||
        (*env)->GetArrayLength(env, addresses) != 64) {
        return GNUNET_NODE_INVALID;
    }
    GnVpnCommand command = {0};
    const jint status = gnunet_vpn_next(vpn_from_handle(handle), 100, &command, NULL, 0);
    if (status != GNUNET_NODE_OK) {
        return status;
    }
    jlong id[2];
    memcpy(&id[0], &command.token.epoch, sizeof(jlong));
    memcpy(&id[1], &command.token.revision, sizeof(jlong));
    const jint values[] = {(jint)command.kind, (jint)command.mtu, (jint)command.ipv4.family,
                          (jint)command.ipv4.bits, (jint)command.ipv6.family, (jint)command.ipv6.bits};
    jbyte packed[64];
    memcpy(packed, command.ipv4.network, 16);
    memcpy(packed + 16, command.ipv4.interface_address, 16);
    memcpy(packed + 32, command.ipv6.network, 16);
    memcpy(packed + 48, command.ipv6.interface_address, 16);
    (*env)->SetLongArrayRegion(env, token, 0, 2, id);
    if (!(*env)->ExceptionCheck(env)) {
        (*env)->SetIntArrayRegion(env, fields, 0, 6, values);
    }
    if (!(*env)->ExceptionCheck(env)) {
        (*env)->SetByteArrayRegion(env, addresses, 0, 64, packed);
    }
    return status;
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_vpnInstalled(
    JNIEnv *env, jobject receiver, jlong handle, jlong epoch, jlong revision, jint fd) {
    (void)env;
    (void)receiver;
    return gnunet_vpn_install_descriptor(vpn_from_handle(handle), route_token(epoch, revision), fd);
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_vpnComplete(
    JNIEnv *env, jobject receiver, jlong handle, jlong epoch, jlong revision, jint outcome,
    jbyteArray diagnostic) {
    (void)receiver;
    GnBytes detail = {0};
    if (diagnostic != NULL && (*env)->GetArrayLength(env, diagnostic) > 4096) {
        return GNUNET_NODE_INVALID;
    }
    if (!copy_range(env, diagnostic, &detail)) {
        free((void *)detail.data);
        return GNUNET_NODE_SETUP_ERROR;
    }
    const jint status = gnunet_vpn_route_complete(
        vpn_from_handle(handle), route_token(epoch, revision), (uint32_t)outcome, detail);
    free((void *)detail.data);
    return status;
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_vpnRevoke(
    JNIEnv *env, jobject receiver, jlong handle, jboolean routes_absent) {
    (void)env;
    (void)receiver;
    return gnunet_vpn_revoke(vpn_from_handle(handle), routes_absent == JNI_TRUE, (GnBytes){0});
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_vpnFence(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)env;
    (void)receiver;
    return gnunet_vpn_fence(vpn_from_handle(handle));
}

JNIEXPORT void JNICALL Java_org_gnunet_sdk_NativeNode_vpnDestroy(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)env;
    (void)receiver;
    gnunet_vpn_destroy(vpn_from_handle(handle));
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_stop(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)env;
    (void)receiver;
    return gnunet_node_stop(node_from_handle(handle));
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_notifyNetworkChange(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)env;
    (void)receiver;
    return gnunet_node_notify_network_change(node_from_handle(handle));
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_setDnsServers(
    JNIEnv *env, jobject receiver, jlong handle, jbyteArray servers) {
    (void)receiver;
    if (servers == NULL || (*env)->GetArrayLength(env, servers) > 65535) {
        return GNUNET_NODE_INVALID;
    }
    GnBytes input = {0};
    if (!copy_range(env, servers, &input)) {
        free((void *)input.data);
        return GNUNET_NODE_SETUP_ERROR;
    }
    jint status = gnunet_node_set_dns_servers(node_from_handle(handle), input);
    free((void *)input.data);
    return status;
}

JNIEXPORT jint JNICALL Java_org_gnunet_sdk_NativeNode_snapshot(
    JNIEnv *env, jobject receiver, jlong handle, jintArray values, jbyteArray peer) {
    (void)receiver;
    if (values == NULL || peer == NULL || (*env)->GetArrayLength(env, values) != 8 ||
        (*env)->GetArrayLength(env, peer) != 32) {
        return GNUNET_NODE_INVALID;
    }
    GnNodeSnapshot snapshot;
    jint status = gnunet_node_snapshot(node_from_handle(handle), &snapshot);
    if (status != GNUNET_NODE_OK) {
        return status;
    }
    const jint fields[] = {(jint)snapshot.phase, (jint)snapshot.has_ready,
                          (jint)snapshot.tcp_port, (jint)snapshot.udp4_port,
                          (jint)snapshot.udp6_port, (jint)snapshot.quic_port,
                          (jint)snapshot.http3_port, (jint)snapshot.unix_mtu};
    (*env)->SetIntArrayRegion(env, values, 0, 8, fields);
    if (!(*env)->ExceptionCheck(env) && snapshot.has_ready != 0) {
        (*env)->SetByteArrayRegion(env, peer, 0, 32, (const jbyte *)snapshot.peer);
    }
    return status;
}

JNIEXPORT jbyteArray JNICALL Java_org_gnunet_sdk_NativeNode_error(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)receiver;
    const GnNode *node = node_from_handle(handle);
    size_t len = gnunet_node_error(node, NULL, 0);
    if (len > INT32_MAX) {
        throw_error(env, "java/lang/IllegalStateException", "GNUnet diagnostic exceeds JNI array limit");
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)len);
    if (result != NULL && len != 0) {
        jbyte *data = (*env)->GetByteArrayElements(env, result, NULL);
        if (data == NULL) {
            return NULL;
        }
        size_t observed = gnunet_node_error(node, (uint8_t *)data, len);
        (*env)->ReleaseByteArrayElements(env, result, data, 0);
        if (observed != len) {
            throw_error(env, "java/lang/IllegalStateException", "GNUnet terminal diagnostic changed");
            return NULL;
        }
    }
    return result;
}

JNIEXPORT void JNICALL Java_org_gnunet_sdk_NativeNode_destroy(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)env;
    (void)receiver;
    gnunet_node_destroy(node_from_handle(handle));
}
