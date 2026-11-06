//! Suporte nativo JNI para o aplicativo Android Anarchord.

use crate::c_api::{
    p2p_ffi_destroy, p2p_ffi_join_channel, p2p_ffi_listen_port, p2p_ffi_poll_event,
    p2p_ffi_poll_event_json, p2p_ffi_send_message, p2p_ffi_start_simple, p2p_ffi_stop,
};
use crate::engine::FfiEngine;
use crate::memory::p2p_ffi_free_buffer;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jobject, jstring};
use jni::JNIEnv;
use std::ffi::CString;

/// Inicia o nó P2P a partir do Kotlin. Retorna o ponteiro `jlong` da engine.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_startSimple(
    mut env: JNIEnv,
    _class: JClass,
    nick: JString,
    data_dir: JString,
    port: jint,
) -> jlong {
    let nick_str: String = match env.get_string(&nick) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let dir_str: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let c_nick = match CString::new(nick_str) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_dir = match CString::new(dir_str) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let engine = p2p_ffi_start_simple(c_nick.as_ptr(), c_dir.as_ptr(), port as u16);
    engine as jlong
}

/// Envia mensagem de chat no canal ativo.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_sendMessage(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    text: JString,
) -> jint {
    let text_str: String = match env.get_string(&text) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let c_text = match CString::new(text_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    p2p_ffi_send_message(engine as *mut FfiEngine, c_text.as_ptr())
}

/// Troca de canal de texto.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_joinChannel(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    channel: JString,
) -> jint {
    let channel_str: String = match env.get_string(&channel) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let c_channel = match CString::new(channel_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    p2p_ffi_join_channel(engine as *mut FfiEngine, c_channel.as_ptr())
}

/// Retorna a porta de escuta local do nó.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_listenPort(
    _env: JNIEnv,
    _class: JClass,
    engine: jlong,
) -> jint {
    p2p_ffi_listen_port(engine as *mut FfiEngine) as jint
}

/// Coleta o próximo evento e entrega diretamente em um `java.nio.ByteBuffer` (Zero-Copy Shared Memory).
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_pollEventDirect(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
) -> jobject {
    let buf = p2p_ffi_poll_event(engine as *mut FfiEngine);
    if buf.is_empty() {
        return std::ptr::null_mut();
    }

    match env.new_direct_byte_buffer(buf.ptr, buf.len) {
        Ok(byte_buf) => byte_buf.into_raw(),
        Err(_) => {
            p2p_ffi_free_buffer(buf);
            std::ptr::null_mut()
        }
    }
}

/// Coleta o próximo evento serializado em JSON String para conveniência no Kotlin.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_pollEventJson(
    env: JNIEnv,
    _class: JClass,
    engine: jlong,
) -> jstring {
    let buf = p2p_ffi_poll_event_json(engine as *mut FfiEngine);
    if buf.is_empty() {
        return std::ptr::null_mut();
    }

    let slice = buf.as_slice();
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => {
            p2p_ffi_free_buffer(buf);
            return std::ptr::null_mut();
        }
    };

    let result = match env.new_string(text) {
        Ok(jstr) => jstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    };

    p2p_ffi_free_buffer(buf);
    result
}

/// Envia sinal de encerramento para o nó.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_stop(
    _env: JNIEnv,
    _class: JClass,
    engine: jlong,
) {
    p2p_ffi_stop(engine as *mut FfiEngine);
}

/// Destrói a instância do motor FFI liberando sua memória na heap nativa.
#[no_mangle]
pub unsafe extern "system" fn Java_com_anarchord_mobile_NativeBridge_destroy(
    _env: JNIEnv,
    _class: JClass,
    engine: jlong,
) {
    p2p_ffi_destroy(engine as *mut FfiEngine);
}
