//! Full-text search over everything the content view can show as text:
//! classes (smali), text files, decoded binary XML and the generated resource
//! files.
//!
//! The searchable text is built once per package (in parallel, in the
//! background) from exactly the lines the content view displays, so match
//! line numbers can be used to jump to the match.

use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use crate::formats::detect::{FileKind, detect};
use crate::inspect::{Content, inspect};
use crate::package::{NodeId, NodeKind, Package};

/// Results beyond this are not collected (the count says so).
pub const MAX_MATCHES: usize = 20_000;
const PREVIEW_BEFORE: usize = 40;
const PREVIEW_AFTER: usize = 160;
/// Searching starts this long after the last edit of the query.
const DEBOUNCE: Duration = Duration::from_millis(250);

pub struct Doc {
    pub node: NodeId,
    text: String,
    line_starts: Vec<usize>,
}

impl Doc {
    fn new(node: NodeId, lines: &[String]) -> Self {
        let mut text = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
        let mut line_starts = Vec::with_capacity(lines.len());
        for line in lines {
            line_starts.push(text.len());
            text.push_str(line);
            text.push('\n');
        }
        Self {
            node,
            text,
            line_starts,
        }
    }

    pub fn text_len(&self) -> usize {
        self.text.len()
    }

    fn line_of(&self, offset: usize) -> usize {
        self.line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1)
    }

    fn line_range(&self, line: usize) -> Range<usize> {
        let start = self.line_starts[line];
        // Every line, including the last, is followed by a '\n'.
        let end = self
            .line_starts
            .get(line + 1)
            .map_or(self.text.len() - 1, |next| next - 1);
        start..end
    }
}

pub struct Corpus {
    pub docs: Vec<Doc>,
}

/// The text the content view shows for `node`, if it is searchable.
pub fn searchable_lines(pkg: &Package, node: NodeId) -> Option<Vec<String>> {
    match &pkg.nodes[node].kind {
        NodeKind::File(f) => {
            let data = pkg.read_file(*f).ok()?;
            if !matches!(
                detect(pkg.files[*f].name(), &data.bytes),
                FileKind::Text | FileKind::BinaryXml
            ) {
                return None;
            }
        }
        NodeKind::Class(_) | NodeKind::ResourceFile(..) => {}
        _ => return None,
    }
    match inspect(pkg, node).content {
        Content::Text { lines, .. } => Some(lines),
        _ => None,
    }
}

/// Builds the corpus using all CPU cores. Returns `None` when cancelled.
pub fn build_corpus(pkg: &Package, cancel: &AtomicBool, progress: &Progress) -> Option<Corpus> {
    let candidates: Vec<NodeId> = (0..pkg.nodes.len())
        .filter(|&n| {
            matches!(
                pkg.nodes[n].kind,
                NodeKind::File(_) | NodeKind::Class(_) | NodeKind::ResourceFile(..)
            )
        })
        .collect();
    progress.total.store(candidates.len(), Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .clamp(1, 16);
    let chunk = candidates.len().div_ceil(threads).max(1);
    let parts: Vec<Option<Vec<Doc>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|nodes| {
                scope.spawn(move || {
                    let mut docs = Vec::new();
                    for &node in nodes {
                        if cancel.load(Ordering::Relaxed) {
                            return None;
                        }
                        let lines = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            searchable_lines(pkg, node)
                        }))
                        .ok()
                        .flatten();
                        if let Some(lines) = lines {
                            docs.push(Doc::new(node, &lines));
                        }
                        progress.done.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(docs)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().ok().flatten())
            .collect()
    });
    let mut docs = Vec::new();
    for part in parts {
        docs.extend(part?);
    }
    Some(Corpus { docs })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub text: String,
    pub match_case: bool,
    pub whole_word: bool,
    pub regex: bool,
}

impl Query {
    pub fn compile(&self) -> Result<Regex, String> {
        let mut pattern = if self.regex {
            self.text.clone()
        } else {
            regex::escape(&self.text)
        };
        if self.whole_word {
            pattern = format!(r"\b(?:{pattern})\b");
        }
        RegexBuilder::new(&pattern)
            .case_insensitive(!self.match_case)
            .multi_line(true)
            .size_limit(16 << 20)
            .build()
            .map_err(|e| match e {
                regex::Error::Syntax(s) => s.lines().last().unwrap_or(&s).trim().to_owned(),
                other => other.to_string(),
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineMatch {
    /// 0-based line in the document.
    pub line: usize,
    /// Byte range of the match within the line.
    pub range: Range<usize>,
    pub preview: String,
    /// Byte range of the match within `preview`.
    pub preview_range: Range<usize>,
}

#[derive(Clone, Debug)]
pub struct FileResult {
    pub node: NodeId,
    pub matches: Vec<LineMatch>,
}

#[derive(Clone, Debug, Default)]
pub struct Results {
    pub files: Vec<FileResult>,
    pub total_matches: usize,
    pub truncated: bool,
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// A short excerpt of `line` around `range`, without leading indentation.
fn preview(line: &str, range: &Range<usize>) -> (String, Range<usize>) {
    let indent = line.len() - line.trim_start().len();
    let start = floor_boundary(
        line,
        range
            .start
            .saturating_sub(PREVIEW_BEFORE)
            .max(indent.min(range.start)),
    );
    let end = ceil_boundary(line, (range.end + PREVIEW_AFTER).min(line.len()));
    let mut text = String::new();
    if start > indent {
        text.push('…');
    }
    let offset = text.len();
    text.push_str(&line[start..end]);
    if end < line.len() {
        text.push('…');
    }
    let match_start = offset + range.start - start;
    let match_end = offset + range.end.min(end) - start;
    (text, match_start..match_end)
}

pub fn search(corpus: &Corpus, regex: &Regex, cancel: &AtomicBool) -> Option<Results> {
    let mut results = Results::default();
    for doc in &corpus.docs {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let mut matches = Vec::new();
        for m in regex.find_iter(&doc.text) {
            if m.start() == m.end() {
                continue;
            }
            results.total_matches += 1;
            if results.total_matches > MAX_MATCHES {
                results.truncated = true;
                continue;
            }
            let line = doc.line_of(m.start());
            let line_range = doc.line_range(line);
            let line_text = &doc.text[line_range.clone()];
            let range =
                (m.start() - line_range.start)..(m.end().min(line_range.end) - line_range.start);
            let (preview, preview_range) = preview(line_text, &range);
            matches.push(LineMatch {
                line,
                range,
                preview,
                preview_range,
            });
        }
        if !matches.is_empty() {
            results.files.push(FileResult {
                node: doc.node,
                matches,
            });
        }
    }
    Some(results)
}

#[derive(Default)]
pub struct Progress {
    pub indexing: AtomicBool,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
}

struct Job {
    query: Query,
    rx: Receiver<Option<Results>>,
    cancel: Arc<AtomicBool>,
}

#[derive(Default)]
struct IndexState {
    corpus: Option<Arc<Corpus>>,
    /// Indexing has ended (successfully or not).
    finished: bool,
}

/// The package's search index, built once in the background and shared by
/// all searches. Changing the query never restarts it.
struct Index {
    state: Arc<(Mutex<IndexState>, Condvar)>,
    cancel: Arc<AtomicBool>,
    progress: Arc<Progress>,
}

impl Index {
    fn start(pkg: Arc<Package>) -> Self {
        let state: Arc<(Mutex<IndexState>, Condvar)> = Arc::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        progress.indexing.store(true, Ordering::Relaxed);
        let (s, c, p) = (state.clone(), cancel.clone(), progress.clone());
        std::thread::spawn(move || {
            let corpus = build_corpus(&pkg, &c, &p).map(Arc::new);
            p.indexing.store(false, Ordering::Relaxed);
            let (lock, ready) = &*s;
            if let Ok(mut st) = lock.lock() {
                st.corpus = corpus;
                st.finished = true;
            }
            ready.notify_all();
        });
        Self {
            state,
            cancel,
            progress,
        }
    }

    /// Waits until the corpus is ready; `None` if indexing failed or the
    /// search was cancelled meanwhile.
    fn wait(state: &(Mutex<IndexState>, Condvar), cancel: &AtomicBool) -> Option<Arc<Corpus>> {
        let (lock, ready) = state;
        let mut st = lock.lock().ok()?;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            if st.finished {
                return st.corpus.clone();
            }
            st = ready.wait_timeout(st, Duration::from_millis(50)).ok()?.0;
        }
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    Indexing { done: usize, total: usize },
    Searching,
}

/// Runs searches in the background as the query changes.
pub struct SearchController {
    pub query: Query,
    pub results: Option<Arc<Results>>,
    /// The query `results` belong to.
    pub results_query: Option<Query>,
    pub error: Option<String>,
    index: Option<Index>,
    job: Option<Job>,
    edited: Option<Instant>,
}

impl Default for SearchController {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchController {
    pub fn new() -> Self {
        Self {
            query: Query::default(),
            results: None,
            results_query: None,
            error: None,
            index: None,
            job: None,
            edited: None,
        }
    }

    /// Call after the query changed; the search starts after a short delay.
    pub fn query_changed(&mut self) {
        self.edited = Some(Instant::now());
    }

    /// Starts searching immediately (e.g. on Enter).
    pub fn search_now(&mut self) {
        self.edited = Some(Instant::now() - DEBOUNCE);
    }

    pub fn status(&self) -> Status {
        match (&self.job, &self.index) {
            (None, _) => Status::Idle,
            (Some(_), Some(index)) if index.progress.indexing.load(Ordering::Relaxed) => {
                Status::Indexing {
                    done: index.progress.done.load(Ordering::Relaxed),
                    total: index.progress.total.load(Ordering::Relaxed),
                }
            }
            (Some(_), _) => Status::Searching,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some() || self.edited.is_some()
    }

    fn cancel(&mut self) {
        if let Some(job) = self.job.take() {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Advances the state machine; call once per frame.
    pub fn poll(&mut self, pkg: &Arc<Package>, ctx: &eframe::egui::Context) {
        if let Some(job) = &self.job {
            match job.rx.try_recv() {
                Ok(Some(results)) => {
                    self.results = Some(Arc::new(results));
                    self.results_query = Some(job.query.clone());
                    self.job = None;
                }
                Ok(None) | Err(TryRecvError::Disconnected) => self.job = None,
                Err(TryRecvError::Empty) => {}
            }
        }

        if let Some(edited) = self.edited {
            let wait = DEBOUNCE.saturating_sub(edited.elapsed());
            if wait.is_zero() {
                self.edited = None;
                self.start(pkg, ctx);
            } else {
                ctx.request_repaint_after(wait);
            }
        }
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn start(&mut self, pkg: &Arc<Package>, ctx: &eframe::egui::Context) {
        self.cancel();
        self.error = None;
        if self.query.text.is_empty() {
            self.results = None;
            self.results_query = None;
            return;
        }
        let regex = match self.query.compile() {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(e);
                self.results = None;
                self.results_query = None;
                return;
            }
        };
        let index = self.index.get_or_insert_with(|| Index::start(pkg.clone()));
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (state, job_cancel, ctx) = (index.state.clone(), cancel.clone(), ctx.clone());
        std::thread::spawn(move || {
            let results = Index::wait(&state, &job_cancel)
                .and_then(|corpus| search(&corpus, &regex, &job_cancel));
            let _ = tx.send(results);
            ctx.request_repaint();
        });
        self.job = Some(Job {
            query: self.query.clone(),
            rx,
            cancel,
        });
    }
}

impl Drop for SearchController {
    fn drop(&mut self) {
        // Dropping `index` cancels indexing too.
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::write_stored_zip;
    use std::path::Path;

    fn package() -> Package {
        let zip = write_stored_zip(&[
            ("assets/a.txt", b"hello World\n  indented hello\nnothing"),
            ("assets/b.json", br#"{"greeting":"Hello"}"#),
            ("assets/img.png", b"\x89PNG\r\n\x1a\nhello"),
        ]);
        Package::from_bytes(Path::new("t.apk"), zip.into()).unwrap()
    }

    fn query(text: &str) -> Query {
        Query {
            text: text.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn indexes_what_the_content_view_shows() {
        let pkg = package();
        let corpus = build_corpus(&pkg, &AtomicBool::new(false), &Progress::default()).unwrap();
        let names: Vec<&str> = corpus
            .docs
            .iter()
            .map(|d| pkg.nodes[d.node].label.as_str())
            .collect();
        // The PNG is not searchable; the JSON is indexed beautified.
        assert_eq!(names, ["a.txt", "b.json"]);
        assert!(corpus.docs[1].text.contains("\"greeting\": \"Hello\""));
    }

    #[test]
    fn finds_matches_with_options() {
        let pkg = package();
        let corpus = build_corpus(&pkg, &AtomicBool::new(false), &Progress::default()).unwrap();
        let run =
            |q: Query| search(&corpus, &q.compile().unwrap(), &AtomicBool::new(false)).unwrap();

        let r = run(query("hello"));
        assert_eq!(r.total_matches, 3);
        assert_eq!(r.files.len(), 2);
        let a = &r.files[0].matches;
        assert_eq!((a[0].line, a[0].range.clone()), (0, 0..5));
        assert_eq!((a[1].line, a[1].range.clone()), (1, 11..16));
        // Previews drop indentation and keep the match range aligned.
        assert_eq!(a[1].preview, "indented hello");
        assert_eq!(&a[1].preview[a[1].preview_range.clone()], "hello");

        let r = run(Query {
            match_case: true,
            ..query("Hello")
        });
        assert_eq!(r.total_matches, 1);
        let r = run(Query {
            whole_word: true,
            ..query("ell")
        });
        assert_eq!(r.total_matches, 0);
        let r = run(Query {
            regex: true,
            ..query(r"^\s+\w+")
        });
        assert_eq!(r.total_matches, 1);
        assert!(
            Query {
                regex: true,
                ..query("(")
            }
            .compile()
            .is_err()
        );
        // Without the regex option, special characters are literal.
        assert_eq!(run(query("(")).total_matches, 0);
    }

    #[test]
    fn last_line_has_no_newline() {
        let doc = Doc::new(0, &["a".to_owned(), "last".to_owned()]);
        assert_eq!(&doc.text[doc.line_range(1)], "last");
        assert_eq!(&doc.text[doc.line_range(0)], "a");
        assert_eq!(doc.line_of(doc.text.len() - 1), 1);
    }

    #[test]
    fn previews_long_lines() {
        let line = format!("{}needle{}", "a".repeat(100), "é".repeat(200));
        let (text, range) = preview(&line, &(100..106));
        assert!(text.starts_with('…') && text.ends_with('…'));
        assert_eq!(&text[range], "needle");
    }

    #[test]
    fn caps_results() {
        let lines: Vec<String> = (0..MAX_MATCHES + 10).map(|_| "x".to_owned()).collect();
        let corpus = Corpus {
            docs: vec![Doc::new(0, &lines)],
        };
        let r = search(
            &corpus,
            &query("x").compile().unwrap(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(r.truncated);
        assert_eq!(r.total_matches, MAX_MATCHES + 10);
        assert_eq!(r.files[0].matches.len(), MAX_MATCHES);
    }

    #[test]
    fn cancelling_a_search_keeps_indexing() {
        let pkg = Arc::new(package());
        let index = Index::start(pkg);
        // A cancelled waiter returns immediately…
        assert!(Index::wait(&index.state, &AtomicBool::new(true)).is_none());
        // …while the index still completes for the next search.
        let corpus = Index::wait(&index.state, &AtomicBool::new(false)).unwrap();
        assert_eq!(corpus.docs.len(), 2);
    }

    #[test]
    fn controller_searches_in_background() {
        let pkg = Arc::new(package());
        let ctx = eframe::egui::Context::default();
        let mut c = SearchController::new();
        c.query = query("hello");
        c.search_now();
        let deadline = Instant::now() + Duration::from_secs(10);
        while c.results.is_none() && Instant::now() < deadline {
            c.poll(&pkg, &ctx);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(c.results.as_ref().unwrap().total_matches, 3);
        assert_eq!(c.status(), Status::Idle);

        // Changing the query reuses the index instead of rebuilding it.
        let index_state = c.index.as_ref().map(|i| Arc::as_ptr(&i.state));
        c.query = query("world");
        c.search_now();
        c.poll(&pkg, &ctx);
        assert_eq!(c.index.as_ref().map(|i| Arc::as_ptr(&i.state)), index_state);
        let deadline = Instant::now() + Duration::from_secs(10);
        while c.results_query.as_ref().is_none_or(|q| q.text != "world")
            && Instant::now() < deadline
        {
            c.poll(&pkg, &ctx);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(c.results.as_ref().unwrap().total_matches, 1);

        c.query = Query {
            regex: true,
            ..query("[")
        };
        c.search_now();
        c.poll(&pkg, &ctx);
        assert!(c.error.is_some() && c.results.is_none());
    }
}
