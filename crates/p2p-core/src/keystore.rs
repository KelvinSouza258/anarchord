//! Cofre nativo do sistema operacional (*Best-Effort*) para proteção de chaves em repouso.
//!
//! - **Windows (`#[cfg(windows)]`):** utiliza a API nativa **Windows DPAPI** (`CryptProtectData` /
//!   `CryptUnprotectData` de `crypt32.dll`), atrelada à conta do usuário logado no Windows.
//!   Os arquivos de chaves (`identity.json` e `*.owner-key.json`) são gravados com um envelope
//!   JSON `{"version": 1, "keystore": "windows-dpapi", "ciphertext_b64": "..."}`, impedindo que
//!   scripts ou processos de outros usuários leiam as chaves privadas em texto claro.
//! - **Desativação / Modo Plaintext (`--no-keystore-encryption`):** permite persistir e converter
//!   arquivos diretamente em JSON claro sem cifra DPAPI, facilitando portabilidade e depuração.
//! - **Conversão Bidirecional Automática:**
//!   - Se `--no-keystore-encryption` for passado e o arquivo estiver cifrado via DPAPI, ele é
//!     descriptografado e regravado como JSON em texto claro.
//!   - Se a cifra estiver ativa (padrão) e o arquivo for um JSON em texto claro, ele é migrado
//!     automaticamente para o envelope protegido.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const KEYSTORE_MAGIC_FIELD: &str = "\"keystore\"";

/// Controle global para desativar a cifra do cofre nativo (ativado por `--no-keystore-encryption`)
static KEYSTORE_ENCRYPTION_DISABLED: AtomicBool = AtomicBool::new(false);

/// Desativa ou reativa a cifra do cofre nativo em tempo de execução
pub fn set_keystore_encryption_disabled(disabled: bool) {
    KEYSTORE_ENCRYPTION_DISABLED.store(disabled, Ordering::SeqCst);
}

/// Retorna se a cifra do cofre nativo está desativada
pub fn is_keystore_encryption_disabled() -> bool {
    KEYSTORE_ENCRYPTION_DISABLED.load(Ordering::SeqCst)
}

/// Envelope JSON persistido quando o cofre nativo do SO protege o arquivo em repouso
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedKeystoreEnvelope {
    pub version: u32,
    pub keystore: String,
    #[serde(with = "crate::b64")]
    pub ciphertext_b64: Vec<u8>,
}

/// Tenta proteger os bytes em repouso usando o cofre nativo do sistema operacional.
/// Se a cifra estiver desativada ou o cofre não estiver disponível, retorna `plaintext`.
pub fn seal_for_disk(plaintext: &[u8]) -> Vec<u8> {
    if is_keystore_encryption_disabled() {
        return plaintext.to_vec();
    }
    if let Some((provider, ciphertext)) = os_protect(plaintext) {
        let env = ProtectedKeystoreEnvelope {
            version: 1,
            keystore: provider.to_string(),
            ciphertext_b64: ciphertext,
        };
        if let Ok(json) = serde_json::to_vec_pretty(&env) {
            return json;
        }
    }
    plaintext.to_vec()
}

/// Abre bytes lidos do disco: se for um `ProtectedKeystoreEnvelope`, decifra via cofre nativo do SO;
/// se for um arquivo em texto claro (JSON v1/v2, PEM ou binário legado), devolve os bytes originais
/// indicando `was_protected = false` para permitir migração automática.
pub fn unseal_from_disk(raw: &[u8]) -> io::Result<(Vec<u8>, bool)> {
    if let Ok(text) = std::str::from_utf8(raw) {
        if text.contains(KEYSTORE_MAGIC_FIELD) {
            if let Ok(env) = serde_json::from_slice::<ProtectedKeystoreEnvelope>(raw) {
                let decrypted = os_unprotect(&env.keystore, &env.ciphertext_b64)?;
                return Ok((decrypted, true));
            }
        }
    }
    Ok((raw.to_vec(), false))
}

/// Grava `plaintext` em `path`, protegendo com o cofre nativo do SO quando disponível (a menos que desativado)
pub fn write_protected<P: AsRef<Path>>(path: P, plaintext: &[u8]) -> io::Result<()> {
    let sealed = seal_for_disk(plaintext);
    fs::write(path, sealed)
}

/// Grava forçadamente `plaintext` em `path` em formato de texto claro (sem DPAPI)
pub fn write_plain<P: AsRef<Path>>(path: P, plaintext: &[u8]) -> io::Result<()> {
    fs::write(path, plaintext)
}

/// Lê `path` decifrando do cofre nativo se estiver protegido, ou retornando os bytes em claro
pub fn read_protected_or_plaintext<P: AsRef<Path>>(path: P) -> io::Result<(Vec<u8>, bool)> {
    let raw = fs::read(path)?;
    unseal_from_disk(&raw)
}

/// Informa se o cofre nativo do SO está ativo na plataforma atual
pub fn is_native_keystore_available() -> bool {
    !is_keystore_encryption_disabled() && os_protect(b"probe").is_some()
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::ptr;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const ENTROPY: &[u8] = b"anarchord-native-keystore-dpapi-v1";

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *mut core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *mut core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    pub fn protect(plaintext: &[u8]) -> Option<(&'static str, Vec<u8>)> {
        unsafe {
            let in_blob = DataBlob {
                cb_data: plaintext.len() as u32,
                pb_data: plaintext.as_ptr() as *mut u8,
            };
            let entropy_blob = DataBlob {
                cb_data: ENTROPY.len() as u32,
                pb_data: ENTROPY.as_ptr() as *mut u8,
            };
            let mut out_blob = DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            };
            let ok = CryptProtectData(
                &in_blob,
                ptr::null(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 || out_blob.pb_data.is_null() {
                return None;
            }
            let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
            let result = slice.to_vec();
            LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
            Some(("windows-dpapi", result))
        }
    }

    pub fn unprotect(provider: &str, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        if provider != "windows-dpapi" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Provedor de keystore desconhecido: {}", provider),
            ));
        }
        unsafe {
            let in_blob = DataBlob {
                cb_data: ciphertext.len() as u32,
                pb_data: ciphertext.as_ptr() as *mut u8,
            };
            let entropy_blob = DataBlob {
                cb_data: ENTROPY.len() as u32,
                pb_data: ENTROPY.as_ptr() as *mut u8,
            };
            let mut out_blob = DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 || out_blob.pb_data.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Falha ao decifrar chave protegida pelo Windows DPAPI (outro usuário ou arquivo corrompido)",
                ));
            }
            let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
            let result = slice.to_vec();
            LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
            Ok(result)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    pub fn protect(_plaintext: &[u8]) -> Option<(&'static str, Vec<u8>)> {
        None
    }

    pub fn unprotect(provider: &str, _ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Provedor de keystore '{}' não suportado neste SO", provider),
        ))
    }
}

fn os_protect(plaintext: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    imp::protect(plaintext)
}

fn os_unprotect(provider: &str, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    imp::unprotect(provider, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let original = b"{\"user_id\":\"test-1234\",\"profile\":{\"display_name\":\"Alice\"}}";
        let sealed = seal_for_disk(original);
        let (unsealed, was_protected) = unseal_from_disk(&sealed).expect("deve decifrar");
        assert_eq!(unsealed, original);

        if cfg!(windows) && !is_keystore_encryption_disabled() {
            assert!(was_protected);
            let sealed_str = std::str::from_utf8(&sealed).unwrap();
            assert!(sealed_str.contains("\"keystore\": \"windows-dpapi\""));
        }
    }

    #[test]
    fn test_plaintext_unsealed_directly() {
        let legacy_plaintext = b"{\"version\": 2, \"user_id\": \"legacy-user\"}";
        let (unsealed, was_protected) = unseal_from_disk(legacy_plaintext).expect("leitura direta");
        assert_eq!(unsealed, legacy_plaintext);
        assert!(!was_protected);
    }

    #[test]
    fn test_disable_keystore_encryption_flag() {
        let original = b"{\"user_id\":\"plain-user\"}";
        set_keystore_encryption_disabled(true);
        let sealed = seal_for_disk(original);
        assert_eq!(sealed, original, "quando desativado deve retornar plaintext");
        let (unsealed, was_protected) = unseal_from_disk(&sealed).unwrap();
        assert_eq!(unsealed, original);
        assert!(!was_protected);
        set_keystore_encryption_disabled(false);
    }
}
