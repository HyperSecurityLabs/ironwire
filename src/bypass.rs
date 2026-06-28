/// IronWire — Adaptive Bypass Engine
///
/// Auto-tuning stealth profiles, jitter injection, loss-based
/// rate adaptation, and silent scan type selection.
/// Makes IronWire alive — it learns and adjusts mid-operation.

use std::collections::VecDeque;
use std::time::Instant;
use rand::Rng;

/// Operational profiles balancing stealth vs throughput.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BypassProfile {
    /// FIN/XMAS/NULL only, slow bursts, max jitter, minimal footprint
    Silent,
    /// Starts slow, monitors loss rate, ramps up when conditions allow
    Adaptive,
    /// Full throughput, all variations, max randomization
    Aggressive,
}

impl BypassProfile {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "silent" => BypassProfile::Silent,
            "adaptive" => BypassProfile::Adaptive,
            "aggressive" => BypassProfile::Aggressive,
            _ => BypassProfile::Adaptive,
        }
    }

    pub fn base_delay(&self) -> u64 {
        match self {
            BypassProfile::Silent => 50,
            BypassProfile::Adaptive => 20,
            BypassProfile::Aggressive => 0,
        }
    }

    pub fn burst_size(&self) -> usize {
        match self {
            BypassProfile::Silent => 5,
            BypassProfile::Adaptive => 20,
            BypassProfile::Aggressive => 50,
        }
    }

    pub fn jitter_max(&self) -> u64 {
        match self {
            BypassProfile::Silent => 100,
            BypassProfile::Adaptive => 50,
            BypassProfile::Aggressive => 5,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            BypassProfile::Silent => "minimum footprint — FIN/XMAS/NULL only, slow, jittered",
            BypassProfile::Adaptive => "self-tuning — starts slow, adjusts to network conditions",
            BypassProfile::Aggressive => "maximum throughput — all variations, no delay",
        }
    }
}

/// Sliding-window monitor that tracks send success/failure and
/// dynamically computes the optimal delay.
pub struct AdaptiveMonitor {
    hits: VecDeque<(Instant, bool)>,
    window_secs: f64,
    current_delay: u64,
    min_delay: u64,
    max_delay: u64,
    jitter_max: u64,
    consecutive_good: u64,
    consecutive_bad: u64,
}

impl AdaptiveMonitor {
    pub fn new(initial_delay: u64, jitter_max: u64) -> Self {
        Self {
            hits: VecDeque::new(),
            window_secs: 10.0,
            current_delay: initial_delay,
            min_delay: 0,
            max_delay: 200,
            jitter_max,
            consecutive_good: 0,
            consecutive_bad: 0,
        }
    }

    /// Record a send outcome (true = success, false = failure).
    pub fn record(&mut self, success: bool) {
        let now = Instant::now();
        self.hits.push_back((now, success));
        if success {
            self.consecutive_good += 1;
            self.consecutive_bad = 0;
        } else {
            self.consecutive_bad += 1;
            self.consecutive_good = 0;
        }
        // Trim old entries
        while let Some(&(t, _)) = self.hits.front() {
            if now.duration_since(t).as_secs_f64() > self.window_secs {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    /// Current loss rate (0.0 - 1.0) over the sliding window.
    pub fn loss_rate(&self) -> f64 {
        if self.hits.is_empty() { return 0.0; }
        let failures = self.hits.iter().filter(|&(_, s)| !s).count();
        failures as f64 / self.hits.len() as f64
    }

    /// Adjust delay based on loss rate and consecutive outcomes.
    /// Returns the new delay in milliseconds.
    pub fn tick(&mut self) -> u64 {
        let loss = self.loss_rate();

        if loss > 0.3 {
            // High loss — back off aggressively
            self.current_delay = (self.current_delay * 2).min(self.max_delay);
            self.consecutive_good = 0;
        } else if loss > 0.1 {
            // Moderate loss — gentle backoff
            self.current_delay = (self.current_delay + 10).min(self.max_delay);
        } else if self.consecutive_good > 20 && self.current_delay > self.min_delay {
            // Sustained success — cautiously ramp up
            self.current_delay = self.current_delay.saturating_sub(5).max(self.min_delay);
        } else if self.consecutive_bad > 5 {
            // Burst of failures — immediate throttle
            self.current_delay = (self.current_delay * 3).min(self.max_delay);
            self.consecutive_bad = 0;
        }

        // Add jitter to avoid clockwork pattern detection
        let mut rng = rand::thread_rng();
        let jitter = if self.jitter_max > 0 {
            rng.gen_range(0..=self.jitter_max)
        } else {
            0
        };

        self.current_delay + jitter
    }

}

/// The main bypass engine: combines a profile with an adaptive monitor.
pub struct BypassEngine {
    pub profile: BypassProfile,
    pub monitor: AdaptiveMonitor,
    pub burst_size: usize,
}

impl BypassEngine {
    pub fn new(profile_name: &str, aggression: u8) -> Self {
        let profile = BypassProfile::from_str(profile_name);
        let base = if aggression > 0 && aggression <= 5 {
            // If user explicitly set aggression, use that as baseline
            match aggression {
                1 => 50, 2 => 20, 3 => 5, 4 => 1, 5 => 0,
                _ => 20,
            }
        } else {
            profile.base_delay()
        };

        let monitor = AdaptiveMonitor::new(base, profile.jitter_max());
        let burst = profile.burst_size();

        Self { profile, monitor, burst_size: burst }
    }

    /// Returns the delay for the next burst (auto-tuned).
    pub fn next_delay(&mut self) -> u64 {
        if self.profile == BypassProfile::Aggressive {
            return 0;
        }
        self.monitor.tick()
    }

    /// Record a send outcome for adaptive tuning.
    pub fn record(&mut self, success: bool) {
        self.monitor.record(success);
    }

    pub fn description(&self) -> &str {
        self.profile.description()
    }
}
