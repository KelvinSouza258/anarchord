//! Nomes e destino seguros para arquivos recebidos de outros pares.
//! A transferência em si fica em [`crate::files`] (enxame).

use std::path::{Path, PathBuf};

/// Nome usado quando o nome recebido não sobra nada utilizável
const FALLBACK_NAME: &str = "arquivo.bin";
const MAX_NAME_CHARS: usize = 120;
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Transforma o nome de arquivo recebido de outro par num nome seguro para gravar:
/// - só o último componente (sem pastas, `..`, caminho absoluto ou letra de drive);
/// - sem caracteres de controle nem os proibidos no Windows (`<>:"/\|?*`);
/// - sem pontos/espaços no fim, sem nomes reservados do Windows (CON, NUL, COM1…);
/// - tamanho limitado, preservando a extensão; nome padrão se não sobrar nada.
pub fn sanitize_file_name(name: &str) -> String {
    // Último componente, considerando "/" e "\" como separadores em qualquer sistema
    let last = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
        .collect();
    let mut cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    if cleaned.chars().all(|c| c == '.') {
        cleaned.clear();
    }
    let stem = cleaned.split('.').next().unwrap_or_default().to_ascii_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        cleaned = format!("_{}", cleaned);
    }
    if cleaned.chars().count() > MAX_NAME_CHARS {
        let ext: String = Path::new(&cleaned)
            .extension()
            .and_then(|e| e.to_str())
            .filter(|e| e.chars().count() <= 16)
            .map(|e| format!(".{}", e))
            .unwrap_or_default();
        let keep = MAX_NAME_CHARS - ext.chars().count();
        cleaned = cleaned.chars().take(keep).collect::<String>() + &ext;
    }
    if cleaned.is_empty() {
        FALLBACK_NAME.to_string()
    } else {
        cleaned
    }
}

/// Cria (vazio) o arquivo de destino em `dir` com o nome sanitizado e sem sobrescrever nada,
/// reservando o nome. Retorna o caminho e o arquivo aberto para escrita.
pub fn create_unique_file(dir: &Path, received_name: &str) -> std::io::Result<(PathBuf, std::fs::File)> {
    std::fs::create_dir_all(dir)?;
    let base = dir.canonicalize()?;
    let name = sanitize_file_name(received_name);
    let path = Path::new(&name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(FALLBACK_NAME).to_string();
    let ext = path.extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e)).unwrap_or_default();
    for attempt in 0..10_000u32 {
        let candidate = if attempt == 0 { name.clone() } else { format!("{} ({}){}", stem, attempt, ext) };
        let target = base.join(&candidate);
        if target.parent() != Some(base.as_path()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "destino fora da pasta de downloads"));
        }
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&target) {
            Ok(file) => return Ok((target, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "nomes disponíveis esgotados"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_blocks_path_traversal_and_absolute_paths() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\..\\AppData\\Startup\\x.bat"), "x.bat");
        assert_eq!(sanitize_file_name("C:\\Windows\\System32\\evil.dll"), "evil.dll");
        assert_eq!(sanitize_file_name("/abs/olute.txt"), "olute.txt");
        assert_eq!(sanitize_file_name(".."), FALLBACK_NAME);
        assert_eq!(sanitize_file_name(""), FALLBACK_NAME);
        assert_eq!(sanitize_file_name("dir/"), FALLBACK_NAME);
    }

    #[test]
    fn test_sanitize_cleans_forbidden_and_reserved_names() {
        assert_eq!(sanitize_file_name("foto<1>?.png"), "foto1.png");
        assert_eq!(sanitize_file_name("nome com espaço. . "), "nome com espaço");
        assert_eq!(sanitize_file_name("a\u{0}b\u{7}c.txt"), "abc.txt");
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("férias 2026.png"), "férias 2026.png", "nomes normais ficam iguais");
        let long = format!("{}.png", "a".repeat(500));
        let cut = sanitize_file_name(&long);
        assert_eq!(cut.chars().count(), 120);
        assert!(cut.ends_with(".png"), "mantém a extensão");
    }

    #[test]
    fn test_unique_file_stays_in_dir_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("anarchord_downloads_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (first, _) = create_unique_file(&dir, "../../fora.txt").unwrap();
        std::fs::write(&first, b"um").unwrap();
        let (second, _) = create_unique_file(&dir, "fora.txt").unwrap();
        let base = dir.canonicalize().unwrap();
        assert_eq!(first, base.join("fora.txt"));
        assert_eq!(second, base.join("fora (1).txt"));
        assert_eq!(std::fs::read(&first).unwrap(), b"um", "não sobrescreve");
        assert!(!dir.parent().unwrap().join("fora.txt").exists(), "nada gravado fora da pasta");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
