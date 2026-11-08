use p2p_core::identity::UserIdentity;
use p2p_core::keystore::{set_keystore_encryption_disabled, is_keystore_encryption_disabled};

#[test]
fn test_identity_bidirectional_conversion_plain_and_dpapi() {
    let temp_dir = std::env::temp_dir();
    let id_path = temp_dir.join("test_identity_bidirectional.json");

    // 1. Cria e salva com cifra nativa ativada (se Windows)
    set_keystore_encryption_disabled(false);
    let id1 = UserIdentity::generate_with_nick("Alice");
    id1.save_to(&id_path).expect("salvar com cifra");

    // 2. Agora ativa --no-keystore-encryption: ao carregar o arquivo, decifra e regrava em plaintext normal
    set_keystore_encryption_disabled(true);
    let id2 = UserIdentity::load_or_create(&id_path).expect("carregar e converter para plain");
    assert_eq!(id2.public_key_hex(), id1.public_key_hex());

    // Verifica que o arquivo no disco agora é um JSON em texto claro
    let disk_bytes = std::fs::read(&id_path).unwrap();
    let disk_text = std::str::from_utf8(&disk_bytes).unwrap();
    assert!(disk_text.contains("profile") || disk_text.contains("display_name"));
    assert!(!disk_text.contains("windows-dpapi"), "não deve conter o envelope dpapi");

    // 3. Vice-versa: reativa cifra e recarrega o arquivo plaintext -> deve migrar de volta para cofre nativo
    set_keystore_encryption_disabled(false);
    let id3 = UserIdentity::load_or_create(&id_path).expect("carregar e converter de volta para dpapi");
    assert_eq!(id3.public_key_hex(), id1.public_key_hex());

    if cfg!(windows) {
        let re_encrypted_bytes = std::fs::read(&id_path).unwrap();
        let re_encrypted_text = std::str::from_utf8(&re_encrypted_bytes).unwrap();
        assert!(re_encrypted_text.contains("windows-dpapi"), "deve ter voltado a ser protegido por dpapi");
    }

    let _ = std::fs::remove_file(id_path);
}
