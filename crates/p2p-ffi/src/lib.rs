//! Anarchord P2P FFI & Shared Memory (Zero-Copy) Engine Library.
//!
//! Este crate fornece a camada universal de FFI compatível com C-ABI para:
//! - Android (Kotlin/Java via JNI ou DirectByteBuffer)
//! - Desktop UI (Electron / Node.js via N-API / Koffi)
//! - iOS / macOS (Swift nativo)
//! - CLI e aplicações nativas em Rust

pub mod c_api;
pub mod engine;
pub mod jni;
pub mod memory;

pub use c_api::*;
pub use engine::*;
pub use memory::*;

// Re-exporta os tipos e APIs fundamentais do core para consumidores Rust (como o p2p-cli)
pub use p2p_core::*;

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::identity::UserIdentity;
    use p2p_core::runtime::{CoreCommand, CoreConfig, CoreEvent};
    use std::ffi::CString;

    #[tokio::test]
    async fn test_engine_lifecycle_and_command_sending() {
        let temp_dir = std::env::temp_dir().join(format!("anarchord_ffi_test_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let identity = UserIdentity::generate_with_nick("FfiTester");
        let mut config = CoreConfig::new(
            identity,
            temp_dir.join("servers"),
            temp_dir.join("downloads"),
        );
        config.channel = "geral".into();

        let mut engine = FfiEngine::start(config).expect("Deve iniciar o motor FFI");

        // Envia comando tipado
        engine
            .send_command(CoreCommand::JoinChannel("testes".into()))
            .expect("Deve aceitar comando");

        // Envia comando codificado em binário Postcard (Zero-Copy)
        let cmd = CoreCommand::SendMessage("Olá via FFI!".into());
        let cmd_bytes = postcard::to_allocvec(&cmd).unwrap();
        engine
            .send_command_bytes(&cmd_bytes)
            .expect("Deve aceitar comando em bytes Postcard");

        // Envia comando codificado em JSON
        let cmd_json = serde_json::to_vec(&CoreCommand::ToggleMute).unwrap();
        engine
            .send_command_bytes(&cmd_json)
            .expect("Deve aceitar comando em bytes JSON");

        // Coleta eventos
        let mut got_started = false;
        for _ in 0..10 {
            if let Some(event) = engine.poll_event() {
                if matches!(event, CoreEvent::Started { .. }) {
                    got_started = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(got_started, "O motor deve emitir evento Started");

        engine.stop();
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_c_api_start_simple_and_memory_buffers() {
        let temp_dir = std::env::temp_dir().join(format!("anarchord_c_api_test_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let nick = CString::new("C_Tester").unwrap();
        let data_dir = CString::new(temp_dir.to_str().unwrap()).unwrap();

        unsafe {
            let engine_ptr = p2p_ffi_start_simple(nick.as_ptr(), data_dir.as_ptr(), 0);
            assert!(!engine_ptr.is_null(), "Engine deve ser alocado");

            // Envia mensagem via C helper
            let text = CString::new("Mensagem C").unwrap();
            let res = p2p_ffi_send_message(engine_ptr, text.as_ptr());
            assert_eq!(res, FFI_OK);

            // Envia comando via bytes brutos
            let cmd = CoreCommand::JoinChannel("dev".into());
            let bytes = postcard::to_allocvec(&cmd).unwrap();
            let res_bytes = p2p_ffi_send_command(engine_ptr, bytes.as_ptr(), bytes.len());
            assert_eq!(res_bytes, FFI_OK);

            // Aguarda e coleta evento com buffer de memória compartilhada
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let event_buf = p2p_ffi_poll_event(engine_ptr);
            if !event_buf.is_empty() {
                let slice = event_buf.as_slice();
                let decoded: Result<CoreEvent, _> = postcard::from_bytes(slice);
                assert!(decoded.is_ok(), "Evento binário deve ser decodificável");
                p2p_ffi_free_buffer(event_buf);
            }

            // Destroi a engine
            p2p_ffi_destroy(engine_ptr);
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
