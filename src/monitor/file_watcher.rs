use anyhow::Result;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::sync::RwLock;

/// File watcher for monitoring changes in files and directories
pub struct FileWatcher {
    // Path -> event count within the aggregation window
    event_counts: Arc<RwLock<HashMap<String, PathEvents>>>,
    
    // notify watcher (Send+Sync bounds required for tokio::spawn)
    _watcher: Box<dyn Watcher + Send + Sync>,
    
    // Configuration
    max_events_per_path: usize,
    aggregation_window: Duration,
}

#[derive(Debug, Clone)]
struct PathEvents {
    events: Vec<Instant>,
    last_cleanup: Instant,
}

impl FileWatcher {
    pub fn new(max_events_per_path: usize, aggregation_window: Duration) -> Result<Self> {
        let event_counts = Arc::new(RwLock::new(HashMap::new()));
        let event_counts_clone = event_counts.clone();

        // Capture the tokio handle before entering the notify callback thread.
        // notify fires events from its own OS thread (inotify/kqueue), which is
        // not a tokio thread, so `tokio::spawn` would panic there.
        let handle = tokio::runtime::Handle::current();

        // Create notify watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Handle file event
                    if let Some(path) = event.paths.first() {
                        let path_str = path.to_string_lossy().to_string();

                        // Spawn async task to update counts
                        let event_counts = event_counts_clone.clone();
                        handle.spawn(async move {
                            let mut counts = event_counts.write().await;
                            counts.entry(path_str.clone())
                                .and_modify(|pe: &mut PathEvents| pe.events.push(Instant::now()))
                                .or_insert(PathEvents {
                                    events: vec![Instant::now()],
                                    last_cleanup: Instant::now(),
                                });
                            
                            tracing::debug!("File event: {} on {}", 
                                Self::event_kind_name(&event.kind), path_str);
                        });
                    }
                }
                Err(e) => {
                    tracing::error!("File watcher error: {}", e);
                }
            }
        })?;
        
        Ok(Self {
            event_counts,
            _watcher: Box::new(watcher),
            max_events_per_path,
            aggregation_window,
        })
    }
    
    /// Start watching a path
    pub fn watch_path(&mut self, path: &str) -> Result<()> {
        use std::path::Path;
        
        let path_obj = Path::new(path);
        self._watcher.watch(path_obj, RecursiveMode::Recursive)?;
        
        tracing::info!("Started watching: {}", path);
        Ok(())
    }
    
    /// Stop watching a path
    pub fn unwatch_path(&mut self, path: &str) -> Result<()> {
        use std::path::Path;
        
        let path_obj = Path::new(path);
        self._watcher.unwatch(path_obj)?;
        
        tracing::info!("Stopped watching: {}", path);
        Ok(())
    }
    
    /// Get event count for paths.
    ///
    /// `paths` are usually directories from the config (e.g. /etc/nginx/),
    /// but notify stores each event under the FILE that changed
    /// (/etc/nginx/nginx.conf). Bug #24: previously this used exact-match
    /// HashMap lookup, so a configured directory path never matched any
    /// stored file event — count was always 0.
    ///
    /// Now we match an event path if it equals the configured path OR is
    /// a child of it. Each user path is checked against every stored
    /// event_path; this is O(P*E) but P (configured paths) and E (active
    /// recent events) are both small in practice.
    pub async fn get_event_count(&self, paths: &[String]) -> u64 {
        use std::path::Path;

        let mut counts = self.event_counts.write().await;
        let now = Instant::now();
        let mut total = 0u64;
        let max_per_path = self.max_events_per_path;
        let agg_window = self.aggregation_window;

        for (event_path, path_events) in counts.iter_mut() {
            // Match event_path against any configured path: exact or under-dir
            let any_match = paths.iter().any(|user_path| {
                if event_path == user_path {
                    return true;
                }
                // Treat user_path as a directory: event_path is `user_path/<...>`
                let event = Path::new(event_path);
                let user = Path::new(user_path);
                event.starts_with(user)
            });

            if !any_match {
                continue;
            }

            // Cleanup old events lazily (at most once per minute per entry)
            if now.duration_since(path_events.last_cleanup) > Duration::from_secs(60) {
                path_events.events.retain(|&t| now.duration_since(t) < agg_window);
                path_events.last_cleanup = now;
            }

            let recent = path_events.events.iter()
                .filter(|&&t| now.duration_since(t) < agg_window)
                .count();
            total += recent as u64;

            // Cap stored events per file to avoid unbounded growth
            if path_events.events.len() > max_per_path {
                let drain_count = path_events.events.len() - max_per_path;
                path_events.events.drain(0..drain_count);
            }
        }

        total
    }
    
    fn event_kind_name(kind: &EventKind) -> &'static str {
        match kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "remove",
            EventKind::Access(_) => "access",
            _ => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_watcher() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        
        let mut watcher = FileWatcher::new(1000, Duration::from_secs(60)).unwrap();
        watcher.watch_path(temp_dir.path().to_str().unwrap()).unwrap();
        
        // Create file
        fs::write(&test_file, "test").unwrap();
        
        // Wait for event
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check count — events are stored by FILE path, not by directory path.
        let count = watcher.get_event_count(&[test_file.to_string_lossy().to_string()]).await;
        assert!(count > 0);
    }
}