//! The key map's vocabulary: terminal events reduced to the keys the state
//! machine understands, so [`crate::app::App`] is driven the same way by the
//! terminal and by the headless tests.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// A key the TUI reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character (letters keep their case).
    Char(char),
    /// Enter / Return.
    Enter,
    /// Escape.
    Esc,
    /// Tab.
    Tab,
    /// Shift-Tab.
    BackTab,
    /// Backspace.
    Backspace,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Home.
    Home,
    /// End.
    End,
    /// Ctrl-C: quit at once (logs out, restores the terminal).
    CtrlC,
    /// Ctrl-L: lock now.
    CtrlL,
}

/// Map a crossterm key event; `None` for releases, repeats of non-text keys
/// and anything the TUI ignores.
#[must_use]
pub fn from_crossterm(ev: KeyEvent) -> Option<Key> {
    if ev.kind == KeyEventKind::Release {
        return None;
    }
    let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
    Some(match ev.code {
        KeyCode::Char('c' | 'C') if ctrl => Key::CtrlC,
        KeyCode::Char('l' | 'L') if ctrl => Key::CtrlL,
        KeyCode::Char(_) if ctrl || ev.modifiers.contains(KeyModifiers::ALT) => return None,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab if ev.modifiers.contains(KeyModifiers::SHIFT) => Key::BackTab,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_chords_map_to_their_actions_and_releases_are_ignored() {
        let k = |code, m| from_crossterm(KeyEvent::new(code, m));
        assert_eq!(
            k(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(Key::CtrlC)
        );
        assert_eq!(
            k(KeyCode::Char('l'), KeyModifiers::CONTROL),
            Some(Key::CtrlL)
        );
        assert_eq!(k(KeyCode::Char('x'), KeyModifiers::CONTROL), None);
        assert_eq!(
            k(KeyCode::Char('A'), KeyModifiers::SHIFT),
            Some(Key::Char('A'))
        );
        assert_eq!(k(KeyCode::Tab, KeyModifiers::SHIFT), Some(Key::BackTab));
        let mut release = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert_eq!(from_crossterm(release), None);
    }
}
