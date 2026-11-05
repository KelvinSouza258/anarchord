//! Quebra de linha e rolagem horizontal com suporte a caracteres Unicode/emojis.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Quebra uma mensagem em linhas visuais respeitando a largura máxima `max_width`.
/// Linhas de continuação recebem um recuo (indent) para se alinharem com o texto após o nick/prefixo.
pub fn wrap_message(msg: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![msg.to_string()];
    }

    let indent_str = calculate_indent(msg, max_width);
    let indent_width = UnicodeWidthStr::width(indent_str.as_str());

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;
    let mut is_first_line = true;

    for word in msg.split(' ') {
        let word_width = UnicodeWidthStr::width(word);
        let space_width = if current_line.is_empty()
            || (is_first_line && current_width == 0)
            || (!is_first_line && current_width == indent_width)
        {
            0
        } else {
            1
        };

        let target_max = max_width;

        if current_width + space_width + word_width <= target_max {
            if space_width > 0 {
                current_line.push(' ');
                current_width += 1;
            }
            current_line.push_str(word);
            current_width += word_width;
        } else {
            // Se já há conteúdo nesta linha, fecha ela e inicia a próxima com indent
            if !current_line.is_empty() && (is_first_line || current_width > indent_width) {
                lines.push(current_line);
                current_line = indent_str.clone();
                current_width = indent_width;
                is_first_line = false;
            }

            // Se a palavra sozinha é mais larga que o espaço útil restante, quebra caractere a caractere
            let avail = max_width.saturating_sub(current_width);
            if word_width > avail && word_width > max_width.saturating_sub(indent_width) {
                for c in word.chars() {
                    let cw = c.width().unwrap_or(1);
                    if current_width + cw > max_width {
                        if !current_line.is_empty() {
                            lines.push(current_line);
                        }
                        current_line = indent_str.clone();
                        current_width = indent_width;
                        is_first_line = false;
                    }
                    current_line.push(c);
                    current_width += cw;
                }
            } else {
                current_line.push_str(word);
                current_width += word_width;
            }
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn calculate_indent(msg: &str, max_width: usize) -> String {
    let indent_cols = if let Some(pos) = msg.find(": ") {
        let prefix = &msg[..=pos + 1];
        UnicodeWidthStr::width(prefix)
    } else if msg.starts_with("⚙️") || msg.starts_with("📁") || msg.starts_with("🗑️") {
        4
    } else {
        2
    };

    let max_indent = (max_width / 3).max(2);
    let effective = indent_cols.min(max_indent);
    " ".repeat(effective)
}

/// Rola horizontalmente o texto de entrada para que o cursor esteja sempre visível dentro de `avail_width`.
/// Retorna a substring visível a ser desenhada e a coluna relativa onde posicionar o cursor (0..avail_width).
pub fn scroll_input(text: &str, cursor_char_idx: usize, avail_width: usize) -> (String, usize) {
    if avail_width == 0 {
        return (String::new(), 0);
    }

    let chars: Vec<char> = text.chars().collect();
    let cursor_clamped = cursor_char_idx.min(chars.len());

    let mut cursor_visual = 0;
    for &c in &chars[..cursor_clamped] {
        cursor_visual += c.width().unwrap_or(1);
    }

    if cursor_visual < avail_width {
        let mut out = String::new();
        let mut w = 0;
        for &c in &chars {
            let cw = c.width().unwrap_or(1);
            if w + cw > avail_width {
                break;
            }
            out.push(c);
            w += cw;
        }
        (out, cursor_visual)
    } else {
        let scroll_offset = cursor_visual.saturating_sub(avail_width.saturating_sub(1));
        let mut out = String::new();
        let mut current_v = 0;
        let mut cursor_rel = 0;

        for (i, &c) in chars.iter().enumerate() {
            let cw = c.width().unwrap_or(1);
            let next_v = current_v + cw;
            if next_v > scroll_offset && UnicodeWidthStr::width(out.as_str()) + cw <= avail_width {
                out.push(c);
            }
            if i < cursor_clamped && next_v > scroll_offset {
                cursor_rel += cw;
            }
            current_v = next_v;
        }
        (out, cursor_rel.min(avail_width.saturating_sub(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_short_message_remains_single_line() {
        let lines = wrap_message("Olá mundo", 40);
        assert_eq!(lines, vec!["Olá mundo"]);
    }

    #[test]
    fn test_wrap_long_message_with_continuation_indent() {
        let msg = "[#geral] Bob: Esta é uma mensagem bastante longa que deve quebrar em várias linhas";
        let lines = wrap_message(msg, 30);
        assert!(lines.len() >= 3);
        assert!(lines[0].starts_with("[#geral] Bob: "));
        // Linhas de continuação devem ter espaços de indentação
        assert!(lines[1].starts_with("  "));
        assert!(lines[2].starts_with("  "));
    }

    #[test]
    fn test_wrap_unbroken_long_word() {
        let long_word = "a".repeat(50);
        let lines = wrap_message(&long_word, 20);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].len(), 20);
        assert_eq!(lines[1].len(), 20);
        assert_eq!(lines[2].len(), 14); // 2 espaços de indent + 12 'a's
        let total_a: usize = lines.iter().map(|l| l.trim().len()).sum();
        assert_eq!(total_a, 50);
    }

    #[test]
    fn test_wrap_with_emojis_and_accents() {
        let msg = "⚙️  Sistema atualizado com êxito e caracteres especiais: coração ❤️ e café ☕";
        let lines = wrap_message(msg, 25);
        assert!(lines.len() > 1);
    }

    #[test]
    fn test_scroll_input_short_and_long() {
        let (view, col) = scroll_input("abc", 2, 10);
        assert_eq!(view, "abc");
        assert_eq!(col, 2);

        let long = "0123456789abcdefghij";
        let (view, col) = scroll_input(long, 20, 10);
        assert!(col < 10);
        assert!(view.len() <= 10);
        assert!(view.ends_with('j'));
    }
}
