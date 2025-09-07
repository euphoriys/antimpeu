//! Terminal UI (TUI) for the chat.
//!
//! Responsibilities:
//! - render message list and input box
//! - capture keyboard and mouse events
//! - forward user-entered messages to a provided send function

use crossterm::{event, execute, terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use std::io::stdout;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use ratatui::{prelude::*, widgets::*};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct Message {
    pub sender: String,
    pub text: String,
    pub time: String,
}

pub struct ChatState {
    pub messages: Vec<Message>,
    pub input: String,
    pub input_focused: bool,
    pub vertical_scroll: usize,
}

impl ChatState {
    pub fn new() -> Self {
        Self {
            messages: vec![],
            input: String::new(),
            input_focused: false,
            vertical_scroll: 0,
        }
    }
}

pub fn run_tui_with_sender<F>(send_fn: F, messages: Arc<Mutex<Vec<Message>>>, shutdown: Arc<AtomicBool>) -> std::io::Result<()>
where
    F: Fn(String) + Send + Sync + 'static,
{
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let mut state = ChatState::new();
    let mut frame_count: usize = 0;
    execute!(terminal.backend_mut(), crossterm::event::EnableMouseCapture)?;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        frame_count += 1;
        // Synchronize messages from network
        {
            let msgs = messages.lock().unwrap();
            let new_len = msgs.len();
            // Autoscroll: Always scroll to bottom when new messages arrive
            if new_len > state.messages.len() {
                let chat_area_height = terminal.size()?.height as usize - 5;
                state.vertical_scroll = new_len.saturating_sub(chat_area_height);
            }
            state.messages = msgs.clone();
        }
        terminal.draw(|f| {
            draw_chat_scrollbar_minimal(f, &mut state, frame_count);
        })?;

    if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                event::Event::Key(key) => {
                    if key.code == event::KeyCode::Esc {
                        break;
                    }
                    match key.code {
                        event::KeyCode::Up => {
                            if state.vertical_scroll > 0 {
                                state.vertical_scroll -= 1;
                            }
                        }
                        event::KeyCode::Down => {
                            state.vertical_scroll += 1;
                        }
                        event::KeyCode::Tab => {
                            state.input_focused = !state.input_focused;
                        }
                        event::KeyCode::Char(c) => {
                            if state.input_focused {
                                state.input.push(c);
                            }
                        }
                        event::KeyCode::Enter => {
                            if state.input_focused {
                                let trimmed = state.input.trim();
                                if trimmed.is_empty() {
                                    state.input.clear();
                                } else {
                                    let time = chrono::Local::now().format("%H:%M").to_string();
                                    let msg = Message {
                                        sender: username.clone(),
                                        text: trimmed.to_string(),
                                        time,
                                    };
                                    send_fn(trimmed.to_string());
                                    {
                                        let mut msgs = messages.lock().unwrap();
                                        msgs.push(msg);
                                    }
                                    state.input.clear();
                                }
                            }
                        }
                        event::KeyCode::Backspace => {
                            if state.input_focused {
                                state.input.pop();
                            }
                        }
                        _ => {}
                    }
                }
                event::Event::Mouse(me) => {
                    match me.kind {
                        event::MouseEventKind::ScrollDown => {
                            state.vertical_scroll += 1;
                        }
                        event::MouseEventKind::ScrollUp => {
                            if state.vertical_scroll > 0 {
                                state.vertical_scroll -= 1;
                            }
                        }
                        event::MouseEventKind::Down(event::MouseButton::Left) => {
                            let area = terminal.get_frame().area();
                            let chat_chunks = Layout::default()
                                .direction(Direction::Vertical)
                                .constraints([
                                    Constraint::Min(20),
                                    Constraint::Length(3),
                                ])
                                .split(area);
                            // me.column and me.row are already u16
                            let x = me.column;
                            let y = me.row;
                            let mut input_clicked = false;
                            if x >= chat_chunks[1].x && x < chat_chunks[1].x + chat_chunks[1].width && y >= chat_chunks[1].y && y < chat_chunks[1].y + chat_chunks[1].height {
                                state.input_focused = true;
                                input_clicked = true;
                            }
                            if !input_clicked {
                                state.input_focused = false;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    execute!(terminal.backend_mut(), crossterm::event::DisableMouseCapture)?;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

pub fn draw_chat_scrollbar_minimal(f: &mut Frame, state: &mut ChatState, frame_count: usize) {
    let chat_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(20),   // Messages
            Constraint::Length(3), // Input bar
        ])
        .split(f.area());

    // Messages
    let msg_lines: Vec<Line> = state.messages.iter().map(|m| {
        // Format: [time] <user> ➢ <message>
        let time = Span::styled(
            format!("[{}]", m.time),
        // bright green time accent (keep similar to gotop green)
        Style::default().fg(Color::Rgb(80, 250, 123)),
        );
        let spacer = Span::raw(" ");
        // render username without angle brackets
        let sender = Span::styled(
            m.sender.to_string(),
            // magenta-like user color (gotop-inspired)
            Style::default().fg(Color::Rgb(198, 120, 221)).add_modifier(Modifier::BOLD),
        );
        // arrow with no surrounding spaces; we keep spacer spans around fields
        let arrow = Span::styled(
            "➢",
            // warm accent for arrow
            Style::default().fg(Color::Rgb(255, 168, 64)).add_modifier(Modifier::BOLD),
        );
        let text = Span::styled(
            m.text.to_string(),
            // softer 'normal' foreground color
            Style::default().fg(Color::Rgb(200, 200, 210)),
        );
        Line::from(vec![time, spacer.clone(), sender, spacer.clone(), arrow, spacer.clone(), text])
    }).collect();

    // Ensure scroll position is valid
    let max_scroll = msg_lines.len().saturating_sub(chat_chunks[0].height as usize - 2);
    state.vertical_scroll = state.vertical_scroll.min(max_scroll);

    // gotop-like palette: cyan titles, darker background
    let chat_title_style = Style::default()
        .fg(Color::Rgb(50, 230, 230))
        .add_modifier(Modifier::BOLD);
    let chat_border_style = Style::default().fg(Color::Rgb(50, 230, 230)).add_modifier(Modifier::BOLD);
    let msg_paragraph = Paragraph::new(msg_lines.clone())
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Chat ", chat_title_style))
            .title_alignment(Alignment::Center)
            .border_style(chat_border_style)
        )
        .style(Style::default()
            .fg(Color::Rgb(200, 200, 210))
            .bg(Color::Rgb(20, 18, 28)) // darker, purple-tinged background like gotop
        )
        .scroll((state.vertical_scroll as u16, 0));
    f.render_widget(msg_paragraph, chat_chunks[0]);

    // Scrollbar
    let mut scrollbar_state = ScrollbarState::new(msg_lines.len())
        .viewport_content_length(chat_chunks[0].height.saturating_sub(2) as usize)
        .position(state.vertical_scroll);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));
    f.render_stateful_widget(scrollbar, chat_chunks[0], &mut scrollbar_state);

    // Input bar
    // input title/border: use cyan to match gotop-style panels
    let input_title_style = Style::default()
        .fg(Color::Rgb(50, 230, 230))
        .add_modifier(Modifier::BOLD);
    let input_border_style = Style::default().fg(Color::Rgb(50, 230, 230)).add_modifier(Modifier::BOLD);
    let blink_on = (frame_count / 10) % 2 == 0;
    let input_text = if state.input_focused {
        if blink_on {
            format!("{}|", state.input)
        } else {
            format!("{} ", state.input)
        }
    } else {
        state.input.clone()
    };
    let input = Paragraph::new(input_text)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Enter Message ", input_title_style))
            .title_alignment(Alignment::Center)
            .border_style(input_border_style)
        )
        .style(Style::default()
            .fg(Color::Rgb(200, 200, 210))
            .bg(Color::Rgb(20, 18, 28)) // match main chat background
        );
    f.render_widget(input, chat_chunks[1]);
}
