// Cargo.toml
/*
[package]
name = "isotope-tui"
version = "0.1.0"
edition = "2021"

[dependencies]
ratatui = "0.25.0"
crossterm = "0.27.0"
rfd = "0.14.0"
tokio = { version = "1.36.0", features = ["full"] }
ndarray = "0.15.6"
statistical = "1.0.0"
*/

// src/main.rs
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{
        BarChart, Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs, Widget,
    },
};
use rfd::AsyncFileDialog;
use std::{error::Error, fs, io, path::PathBuf, time::Duration};
use tokio::sync::mpsc;

// Represents a section in the binary
#[derive(Clone)]
struct BinarySection {
    start: usize,
    end: usize,
    entropy: f64,
    section_type: SectionType,
    name: String,
}

#[derive(Debug, Clone, Copy)]
enum SectionType {
    Code,
    Data,
    String,
    Compressed,
    Encrypted,
    Unknown,
}

// Analysis results
struct AnalysisResults {
    sections: Vec<BinarySection>,
    entropy_map: Vec<f64>,        // Entropy values by chunks
    byte_frequency: [usize; 256], // Frequency of each byte value
    clusters: Vec<Vec<usize>>,    // Clusters of similar bytes
}

impl AnalysisResults {
    fn new() -> Self {
        Self {
            sections: Vec::new(),
            entropy_map: Vec::new(),
            byte_frequency: [0; 256],
            clusters: Vec::new(),
        }
    }

    // Calculate entropy for a chunk of bytes
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Count frequencies
        let mut counts = [0.0; 256];
        for &byte in data {
            counts[byte as usize] += 1.0;
        }

        // Calculate entropy
        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.iter() {
            if count > 0.0 {
                let p = count / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    // Identify sections based on entropy and patterns
    fn identify_sections(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Calculate entropy in chunks
        const CHUNK_SIZE: usize = 256;
        self.entropy_map.clear();
        self.sections.clear();

        for chunk in data.chunks(CHUNK_SIZE) {
            let entropy = Self::calculate_entropy(chunk);
            self.entropy_map.push(entropy);
        }

        // Simple section identification based on entropy thresholds
        let mut current_section_start = 0;
        let mut current_type = SectionType::Unknown;
        let mut current_entropy = self.entropy_map.get(0).copied().unwrap_or(0.0);

        for (i, &entropy) in self.entropy_map.iter().enumerate() {
            let byte_offset = i * CHUNK_SIZE;
            let section_type = if entropy > 7.5 {
                // High entropy suggests encryption or compression
                SectionType::Encrypted
            } else if entropy > 6.0 {
                // Medium-high entropy could be compressed data
                SectionType::Compressed
            } else if entropy > 4.5 {
                // Medium entropy often indicates code
                SectionType::Code
            } else if entropy > 3.0 {
                // Lower entropy could be regular data
                SectionType::Data
            } else {
                // Very low entropy might be strings or padding
                SectionType::String
            };

            // If section type changes, record the previous section
            if i > 0 && (entropy - current_entropy).abs() > 0.5 {
                self.sections.push(BinarySection {
                    start: current_section_start,
                    end: byte_offset - 1,
                    entropy: current_entropy,
                    section_type: current_type,
                    name: format!(
                        "{:?} (0x{:X}-0x{:X})",
                        current_type,
                        current_section_start,
                        byte_offset - 1
                    ),
                });

                current_section_start = byte_offset;
                current_type = section_type;
                current_entropy = entropy;
            }
        }

        // Add the final section
        if !self.entropy_map.is_empty() {
            let end = data.len();
            self.sections.push(BinarySection {
                start: current_section_start,
                end,
                entropy: current_entropy,
                section_type: current_type,
                name: format!(
                    "{:?} (0x{:X}-0x{:X})",
                    current_type, current_section_start, end
                ),
            });
        }
    }

    // Calculate byte frequency distribution
    fn calculate_byte_frequency(&mut self, data: &[u8]) {
        self.byte_frequency = [0; 256];
        for &byte in data {
            self.byte_frequency[byte as usize] += 1;
        }
    }

    // Run simple clustering on the binary data
    fn cluster_data(&mut self, data: &[u8], k: usize) {
        // Skip if data is too small
        if data.len() < k * 10 {
            return;
        }

        // Prepare data for clustering
        let chunk_size = 16;
        let num_chunks = data.len() / chunk_size;

        // For simplicity, we'll just create basic clusters based on entropy ranges
        // In a real implementation, you'd use proper k-means or other algorithms

        self.clusters = vec![Vec::new(); k];
        for (i, chunk) in data.chunks(chunk_size).enumerate().take(num_chunks) {
            if chunk.len() < chunk_size {
                continue;
            }

            let entropy = Self::calculate_entropy(chunk);

            // Assign to a cluster based on entropy range
            let cluster_idx = match entropy {
                e if e < 2.0 => 0, // Very low entropy (repetitive/zeros)
                e if e < 4.0 => 1, // Low entropy (strings/simple data)
                e if e < 6.0 => 2, // Medium entropy (code/structures)
                _ => 3,            // High entropy (compressed/encrypted)
            };

            if cluster_idx < self.clusters.len() {
                self.clusters[cluster_idx].push(i * chunk_size);
            }
        }
    }

    // Analyze the binary data
    fn analyze(&mut self, data: &[u8]) {
        self.calculate_byte_frequency(data);
        self.identify_sections(data);
        self.cluster_data(data, 4); // 4 clusters
    }
}

// Define the app state
struct Isotope {
    bytes: Vec<u8>,
    selected: Option<usize>,
    file_path: Option<PathBuf>,
    should_quit: bool,
    active_tab: usize,
    scroll_position: usize,
    analysis_results: AnalysisResults,
}

// App events
enum AppEvent {
    Tick,
    Key(crossterm::event::KeyEvent),
    LoadFile(PathBuf),
    FileLoaded(Vec<u8>),
}

// Initialize the application
impl Isotope {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            selected: None,
            file_path: None,
            should_quit: false,
            active_tab: 0,
            scroll_position: 0,
            analysis_results: AnalysisResults::new(),
        }
    }

    // Open file dialog
    async fn pick_file(&self) -> Option<PathBuf> {
        AsyncFileDialog::new()
            .pick_file()
            .await
            .map(|h| h.path().to_path_buf())
    }

    // Load file content and analyze it
    fn load_file(&mut self, path: PathBuf) {
        self.file_path = Some(path.clone());
        match fs::read(&path) {
            Ok(content) => {
                self.bytes = content;
                self.selected = None;
                self.scroll_position = 0;
                self.active_tab = 0;
                // Analyze the binary
                self.analysis_results.analyze(&self.bytes);
            }
            Err(e) => {
                eprintln!("Failed to read file: {}", e);
            }
        }
    }

    // Update app state based on events
    fn update(&mut self, event: AppEvent) -> io::Result<()> {
        match event {
            AppEvent::Key(key) => {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                        }
                        KeyCode::Char('o') => {
                            // This is handled in the main loop
                        }
                        KeyCode::Char('t') => {
                            // Cycle through tabs
                            self.active_tab = (self.active_tab + 1) % 4;
                        }
                        KeyCode::Left => {
                            if let Some(idx) = self.selected {
                                if idx > 0 {
                                    self.selected = Some(idx - 1);
                                }
                            } else if !self.bytes.is_empty() {
                                self.selected = Some(0);
                            }
                        }
                        KeyCode::Right => {
                            if let Some(idx) = self.selected {
                                if idx < self.bytes.len() - 1 {
                                    self.selected = Some(idx + 1);
                                }
                            } else if !self.bytes.is_empty() {
                                self.selected = Some(0);
                            }
                        }
                        KeyCode::Up => {
                            if let Some(idx) = self.selected {
                                if idx >= 16 {
                                    self.selected = Some(idx - 16);
                                }
                            } else if !self.bytes.is_empty() {
                                self.selected = Some(0);
                            }

                            // Scroll up in entropy view
                            if self.active_tab == 2 && self.scroll_position > 0 {
                                self.scroll_position -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if let Some(idx) = self.selected {
                                let new_idx = idx + 16;
                                if new_idx < self.bytes.len() {
                                    self.selected = Some(new_idx);
                                }
                            } else if !self.bytes.is_empty() {
                                self.selected = Some(0);
                            }

                            // Scroll down in entropy view
                            if self.active_tab == 2 {
                                self.scroll_position += 1;
                            }
                        }
                        KeyCode::Tab => {
                            // Switch tab
                            self.active_tab = (self.active_tab + 1) % 4;
                        }
                        KeyCode::BackTab => {
                            // Switch tab backward
                            self.active_tab = (self.active_tab + 3) % 4;
                        }
                        _ => {}
                    }
                }
            }
            AppEvent::LoadFile(path) => {
                self.load_file(path);
            }
            AppEvent::FileLoaded(_) | AppEvent::Tick => {}
        }
        Ok(())
    }
}

// Byte color helpers
fn byte_color(b: u8) -> Color {
    match b {
        0x00 => Color::Black,
        0x01..=0x1F | 0x7F => Color::Blue,
        0x20..=0x7E => Color::Green,
        0x80..=0xFE => Color::Red,
        0xFF => Color::White,
    }
}

// Renders the UI
fn ui(app: &Isotope, frame: &mut Frame) {
    // Split the screen into sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Footer
        ])
        .split(frame.size());

    // Header with title and controls
    let title = format!(
        "Isotope Binary Analyzer - {}",
        app.file_path
            .as_ref()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .unwrap_or_else(|| "No file loaded".to_string())
    );

    let header = Paragraph::new(format!(
        "{}\nPress 'o' to open file, arrows to navigate, 't' or Tab to change tab, 'q' to quit",
        title
    ))
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default());

    frame.render_widget(header, chunks[0]);

    // Split content area for byte map and analysis
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60), // Byte map
            Constraint::Percentage(40), // Analysis panel
        ])
        .split(chunks[1]);

    // Render byte map (visualization)
    render_byte_map(app, frame, content_chunks[0]);

    // Render analysis panel with tabs
    render_analysis_panel(app, frame, content_chunks[1]);

    // Footer with color legend
    let footer = create_color_legend();
    frame.render_widget(footer, chunks[2]);
}

// Render the byte visualization map
fn render_byte_map(app: &Isotope, frame: &mut Frame, area: Rect) {
    let block = Block::default().title("Byte Map").borders(Borders::ALL);

    frame.render_widget(block.clone(), area);

    // Adjusted area for content inside the block
    let inner_area = block.inner(area);

    if app.bytes.is_empty() {
        let empty_msg = Paragraph::new("No data to display")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(empty_msg, inner_area);
        return;
    }

    // Calculate grid dimensions
    let width = inner_area.width as usize;
    let bytes_per_row = 16.min(width / 2); // 2 chars per byte for display
    let visible_height = inner_area.height as usize;

    // Create a buffer to hold our visualization
    let mut cells = Vec::new();

    // Build rows of cells to visualize bytes
    for row in 0..visible_height {
        let mut line = Vec::new();
        for col in 0..bytes_per_row {
            let idx = row * bytes_per_row + col;
            if idx < app.bytes.len() {
                let byte = app.bytes[idx];
                let color = byte_color(byte);

                // Highlight the selected byte
                let style = if app.selected == Some(idx) {
                    Style::default()
                        .fg(Color::Yellow)
                        .bg(color)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().bg(color)
                };

                // Use block characters to represent the byte
                line.push(Span::styled("  ", style));
            } else {
                // Empty space
                line.push(Span::raw("  "));
            }
        }
        cells.push(Line::from(line));
    }

    let paragraph = Paragraph::new(cells).block(Block::default());
    frame.render_widget(paragraph, inner_area);
}

// Render hex dump of the file
fn render_hex_dump(app: &Isotope, frame: &mut Frame, area: Rect) {
    let block = Block::default().title("Hex Dump").borders(Borders::ALL);

    // If no data, show a message
    if app.bytes.is_empty() {
        let empty = Paragraph::new("No data to display")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray))
            .block(block);
        frame.render_widget(empty, area);
        return;
    }

    // Generate hex dump table
    const ROW_SIZE: usize = 16;
    let mut rows = Vec::new();

    for (i, chunk) in app.bytes.chunks(ROW_SIZE).enumerate() {
        let offset = i * ROW_SIZE;
        let offset_text = format!("{:06x}", offset);
        let mut hex_values = Vec::new();

        // Add offset column
        hex_values.push(Cell::from(offset_text));

        for (j, &byte) in chunk.iter().enumerate() {
            let idx = offset + j;
            let style = if app.selected == Some(idx) {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(byte_color(byte))
            };

            hex_values.push(Cell::from(format!("{:02x}", byte)).style(style));
        }

        // Pad the row if needed
        while hex_values.len() < ROW_SIZE + 1 {
            hex_values.push(Cell::from("  "));
        }

        rows.push(Row::new(hex_values).height(1));
    }

    // Create column constraints
    let mut column_constraints = vec![Constraint::Length(8)]; // Offset column
    for _ in 0..ROW_SIZE {
        column_constraints.push(Constraint::Length(2));
    }

    // Create header row
    let header_cells = (0..ROW_SIZE + 1).map(|i| {
        if i == 0 {
            "Offset".to_string()
        } else {
            format!("{:x}", i - 1)
        }
    });

    let table = Table::new(rows, column_constraints)
        .header(Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD)))
        .block(block);

    frame.render_widget(table, area);
}

// Create color legend for the footer
fn create_color_legend() -> impl Widget {
    let legend = Line::from(vec![
        Span::styled(
            " 0x00 ",
            Style::default().fg(Color::Black).bg(Color::DarkGray),
        ),
        Span::raw(" "),
        Span::styled(" LOW ", Style::default().fg(Color::Blue)),
        Span::raw(" "),
        Span::styled(" ASCII ", Style::default().fg(Color::Green)),
        Span::raw(" "),
        Span::styled(" HIGH ", Style::default().fg(Color::Red)),
        Span::raw(" "),
        Span::styled(
            " 0xFF ",
            Style::default().fg(Color::White).bg(Color::DarkGray),
        ),
    ]);

    Paragraph::new(legend).alignment(Alignment::Center)
}

// Render the analysis panel with tabs
fn render_analysis_panel(app: &Isotope, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title("Binary Analysis")
        .borders(Borders::ALL);

    frame.render_widget(block.clone(), area);
    let inner_area = block.inner(area);

    // Create tabs
    let titles = vec!["Hex", "Stats", "Entropy", "Sections"];
    let tabs = Tabs::new(titles)
        .block(Block::default())
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .select(app.active_tab);

    // Split area for tabs and content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(inner_area);

    frame.render_widget(tabs, chunks[0]);

    // Render the selected tab content
    match app.active_tab {
        0 => render_hex_dump(app, frame, chunks[1]),
        1 => render_stats_tab(app, frame, chunks[1]),
        2 => render_entropy_tab(app, frame, chunks[1]),
        3 => render_sections_tab(app, frame, chunks[1]),
        _ => {}
    }
}

// Render statistics tab
fn render_stats_tab(app: &Isotope, frame: &mut Frame, area: Rect) {
    if app.bytes.is_empty() {
        let empty = Paragraph::new("No data to display")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    }

    // Create byte category counts
    let null_bytes = app.analysis_results.byte_frequency[0];
    let control_bytes: usize = (1..32)
        .chain(std::iter::once(127))
        .map(|i| app.analysis_results.byte_frequency[i])
        .sum();
    let printable_bytes: usize = (32..127)
        .map(|i| app.analysis_results.byte_frequency[i])
        .sum();
    let high_bytes: usize = (128..255)
        .map(|i| app.analysis_results.byte_frequency[i])
        .sum();
    let ff_bytes = app.analysis_results.byte_frequency[255];

    // Data for bar chart
    let data = vec![
        ("Null", null_bytes as u64),
        ("Ctrl", control_bytes as u64),
        ("ASCII", printable_bytes as u64),
        ("High", high_bytes as u64),
        ("0xFF", ff_bytes as u64),
    ];

    // Create bar chart
    let barchart = BarChart::default()
        .block(Block::default().title("Byte Distribution"))
        .data(&data)
        .bar_width(7)
        .bar_gap(3)
        .bar_style(Style::default().fg(Color::Green))
        .value_style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(barchart, area);
}

// Render entropy visualization
fn render_entropy_tab(app: &Isotope, frame: &mut Frame, area: Rect) {
    if app.bytes.is_empty() || app.analysis_results.entropy_map.is_empty() {
        let empty = Paragraph::new("No entropy data available")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    }

    // Create a simple ASCII visualization of entropy
    let mut lines = Vec::new();
    for (i, &entropy) in app.analysis_results.entropy_map.iter().enumerate() {
        // Convert entropy (0-8) to a bar length
        let bar_len = (entropy * area.width as f64 / 10.0) as usize;
        let offset = i * 256; // Each entropy value represents 256 bytes

        // Create a bar with color based on entropy
        let color = if entropy > 7.0 {
            Color::Red
        } else if entropy > 6.0 {
            Color::Yellow
        } else if entropy > 4.0 {
            Color::Green
        } else {
            Color::Blue
        };

        let bar = "█".repeat(bar_len.min(area.width as usize));
        let entropy_text = format!("{:.2}", entropy);

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:08X}: ", offset),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(bar, Style::default().fg(color)),
            Span::raw(" "),
            Span::styled(entropy_text, Style::default().fg(Color::White)),
        ]));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Entropy Map"))
        .scroll((app.scroll_position as u16, 0));

    frame.render_widget(paragraph, area);
}

// Render sections tab
fn render_sections_tab(app: &Isotope, frame: &mut Frame, area: Rect) {
    if app.bytes.is_empty() || app.analysis_results.sections.is_empty() {
        let empty = Paragraph::new("No sections identified")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    }

    // Create a list of sections
    let items: Vec<ListItem> = app
        .analysis_results
        .sections
        .iter()
        .map(|section| {
            // Color based on section type
            let color = match section.section_type {
                SectionType::Code => Color::Cyan,
                SectionType::Data => Color::Yellow,
                SectionType::String => Color::Green,
                SectionType::Compressed => Color::Magenta,
                SectionType::Encrypted => Color::Red,
                SectionType::Unknown => Color::Gray,
            };

            let size = section.end - section.start;
            let size_text = if size < 1024 {
                format!("{} bytes", size)
            } else if size < 1024 * 1024 {
                format!("{:.2} KB", size as f64 / 1024.0)
            } else {
                format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
            };

            let text = Line::from(vec![
                Span::styled(
                    format!("{:?}", section.section_type),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("0x{:X}-0x{:X}", section.start, section.end),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::raw(size_text),
                Span::raw(" "),
                Span::styled(
                    format!("(Entropy: {:.2})", section.entropy),
                    Style::default().fg(Color::White),
                ),
            ]);

            ListItem::new(text)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Identified Sections"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    frame.render_widget(list, area);
}

// Event handling setup
async fn handle_events() -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(100);
    let tick_tx = tx.clone();

    // Handle keyboard events
    tokio::spawn(async move {
        loop {
            if let Ok(true) = event::poll(Duration::from_millis(100)) {
                if let crossterm::event::Event::Key(key) =
                    event::read().expect("Failed to read event")
                {
                    if tx.send(AppEvent::Key(key)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Send tick events
    tokio::spawn(async move {
        loop {
            if tick_tx.send(AppEvent::Tick).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    rx
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    // Create app state
    let mut app = Isotope::new();

    // Event loop
    let mut events = handle_events().await;

    loop {
        // Draw UI
        terminal.draw(|f| ui(&app, f))?;

        // Handle events
        if let Some(event) = events.recv().await {
            // Special case for file picking - must be in the main thread
            if let AppEvent::Key(key) = &event {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('o') {
                    // Spawn the file dialog
                    if let Some(path) = app.pick_file().await {
                        app.update(AppEvent::LoadFile(path))?;
                    }
                    continue;
                }
            }

            app.update(event)?;

            if app.should_quit {
                break;
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

