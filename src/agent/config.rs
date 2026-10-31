//! AI agent configuration: providers (Grok, Gemini, Claude, OpenAI, Custom),
//! models, API keys, endpoints, and persistence.

use std::path::{Path, PathBuf};

use super::json::JsonValue;

/// Supported AI providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Provider {
    #[default]
    Claude,
    Gemini,
    Grok,
    OpenAi,
    Custom,
}

impl Provider {
    pub const ALL: [Provider; 5] = [
        Provider::Grok,
        Provider::Gemini,
        Provider::Claude,
        Provider::OpenAi,
        Provider::Custom,
    ];

    pub fn index(self) -> usize {
        match self {
            Provider::Grok => 0,
            Provider::Gemini => 1,
            Provider::Claude => 2,
            Provider::OpenAi => 3,
            Provider::Custom => 4,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Provider::Grok => "grok",
            Provider::Gemini => "gemini",
            Provider::Claude => "claude",
            Provider::OpenAi => "openai",
            Provider::Custom => "custom",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id.trim().to_ascii_lowercase().as_str() {
            "grok" | "xai" => Some(Provider::Grok),
            "gemini" | "google" => Some(Provider::Gemini),
            "claude" | "anthropic" => Some(Provider::Claude),
            "openai" | "chatgpt" | "gpt" => Some(Provider::OpenAi),
            "custom" | "ollama" | "local" => Some(Provider::Custom),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Grok => "Grok (xAI)",
            Provider::Gemini => "Gemini (Google)",
            Provider::Claude => "Claude (Anthropic)",
            Provider::OpenAi => "OpenAI (ChatGPT)",
            Provider::Custom => "Custom (OpenAI API)",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Provider::Grok => "Grok",
            Provider::Gemini => "Gemini",
            Provider::Claude => "Claude",
            Provider::OpenAi => "OpenAI",
            Provider::Custom => "Custom",
        }
    }

    pub fn default_model(self) -> &'static str {
        match self {
            Provider::Grok => "grok-3",
            Provider::Gemini => "gemini-2.5-flash",
            Provider::Claude => "claude-sonnet-4-5",
            Provider::OpenAi => "gpt-4.1",
            Provider::Custom => "llama3.3",
        }
    }

    pub fn preset_models(self) -> &'static [&'static str] {
        match self {
            Provider::Grok => &[
                "grok-4",
                "grok-3",
                "grok-3-mini",
                "grok-2-latest",
            ],
            Provider::Gemini => &[
                "gemini-2.5-flash",
                "gemini-2.5-pro",
                "gemini-2.0-flash",
                "gemini-1.5-pro",
            ],
            Provider::Claude => &[
                "claude-sonnet-4-5",
                "claude-opus-4-5",
                "claude-haiku-4-5",
                "claude-3-7-sonnet-latest",
                "claude-3-5-sonnet-latest",
            ],
            Provider::OpenAi => &[
                "gpt-4.1",
                "gpt-4.1-mini",
                "gpt-4o",
                "gpt-4o-mini",
                "o3-mini",
            ],
            Provider::Custom => &[
                "llama3.3",
                "qwen2.5-coder:32b",
                "deepseek-r1",
            ],
        }
    }

    pub fn default_endpoint(self) -> &'static str {
        match self {
            Provider::Grok => "https://api.x.ai/v1/chat/completions",
            Provider::Gemini => "https://generativelanguage.googleapis.com/v1beta/models",
            Provider::Claude => "https://api.anthropic.com/v1/messages",
            Provider::OpenAi => "https://api.openai.com/v1/chat/completions",
            Provider::Custom => "http://127.0.0.1:11434/v1/chat/completions",
        }
    }

    pub fn env_vars(self) -> &'static [&'static str] {
        match self {
            Provider::Grok => &["XAI_API_KEY", "GROK_API_KEY"],
            Provider::Gemini => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
            Provider::Claude => &["ANTHROPIC_API_KEY"],
            Provider::OpenAi => &["OPENAI_API_KEY"],
            Provider::Custom => &["OPENAI_API_KEY", "OPENROUTER_API_KEY"],
        }
    }

    pub fn env_api_key(self) -> Option<(&'static str, String)> {
        for &var in self.env_vars() {
            if let Ok(val) = std::env::var(var) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return Some((var, trimmed.to_owned()));
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSettings {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
}

impl ProviderSettings {
    pub fn for_provider(provider: Provider) -> Self {
        Self {
            api_key: String::new(),
            model: provider.default_model().to_owned(),
            endpoint: provider.default_endpoint().to_owned(),
        }
    }

    /// The effective API key: user-configured key, or environment variable fallback.
    pub fn effective_api_key(&self, provider: Provider) -> String {
        let trimmed = self.api_key.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
        provider.env_api_key().map_or_else(String::new, |(_, k)| k)
    }

    pub fn has_api_key(&self, provider: Provider) -> bool {
        provider == Provider::Custom || !self.effective_api_key(provider).is_empty()
    }

    pub fn effective_model<'a>(&'a self, provider: Provider) -> &'a str {
        let trimmed = self.model.trim();
        if trimmed.is_empty() {
            provider.default_model()
        } else {
            trimmed
        }
    }

    pub fn effective_endpoint<'a>(&'a self, provider: Provider) -> &'a str {
        let trimmed = self.endpoint.trim();
        if trimmed.is_empty() {
            provider.default_endpoint()
        } else {
            trimmed
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub provider: Provider,
    pub providers: [ProviderSettings; 5],
    pub include_source: bool,
    pub include_resources: bool,
    pub include_network: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let providers = [
            ProviderSettings::for_provider(Provider::Grok),
            ProviderSettings::for_provider(Provider::Gemini),
            ProviderSettings::for_provider(Provider::Claude),
            ProviderSettings::for_provider(Provider::OpenAi),
            ProviderSettings::for_provider(Provider::Custom),
        ];
        // Pick the first provider that has an environment variable set, or Grok by default.
        let provider = Provider::ALL
            .into_iter()
            .find(|p| *p != Provider::Custom && p.env_api_key().is_some())
            .unwrap_or(Provider::Grok);
        Self {
            provider,
            providers,
            include_source: true,
            include_resources: true,
            include_network: true,
        }
    }
}

impl AgentConfig {
    pub fn active(&self) -> &ProviderSettings {
        &self.providers[self.provider.index()]
    }

    pub fn active_mut(&mut self) -> &mut ProviderSettings {
        &mut self.providers[self.provider.index()]
    }

    pub fn settings(&self, provider: Provider) -> &ProviderSettings {
        &self.providers[provider.index()]
    }

    pub fn settings_mut(&mut self, provider: Provider) -> &mut ProviderSettings {
        &mut self.providers[provider.index()]
    }

    pub fn to_json(&self) -> JsonValue {
        let mut prov_obj = Vec::new();
        for p in Provider::ALL {
            let s = self.settings(p);
            prov_obj.push((
                p.id().to_owned(),
                JsonValue::obj([
                    ("api_key", JsonValue::str(&s.api_key)),
                    ("model", JsonValue::str(&s.model)),
                    ("endpoint", JsonValue::str(&s.endpoint)),
                ]),
            ));
        }
        JsonValue::obj([
            ("provider", JsonValue::str(self.provider.id())),
            ("include_source", JsonValue::Bool(self.include_source)),
            ("include_resources", JsonValue::Bool(self.include_resources)),
            ("include_network", JsonValue::Bool(self.include_network)),
            ("providers", JsonValue::Object(prov_obj)),
        ])
    }

    pub fn from_json(val: &JsonValue) -> Self {
        let mut cfg = Self::default();
        if let Some(p) = val.get("provider").and_then(JsonValue::as_str).and_then(Provider::from_id) {
            cfg.provider = p;
        }
        if let Some(b) = val.get("include_source").and_then(JsonValue::as_bool) {
            cfg.include_source = b;
        }
        if let Some(b) = val.get("include_resources").and_then(JsonValue::as_bool) {
            cfg.include_resources = b;
        }
        if let Some(b) = val.get("include_network").and_then(JsonValue::as_bool) {
            cfg.include_network = b;
        }
        if let Some(providers) = val.get("providers") {
            for p in Provider::ALL {
                if let Some(entry) = providers.get(p.id()) {
                    let slot = cfg.settings_mut(p);
                    if let Some(k) = entry.get("api_key").and_then(JsonValue::as_str) {
                        slot.api_key = k.to_owned();
                    }
                    if let Some(m) = entry.get("model").and_then(JsonValue::as_str) {
                        if !m.trim().is_empty() {
                            slot.model = m.to_owned();
                        }
                    }
                    if let Some(e) = entry.get("endpoint").and_then(JsonValue::as_str) {
                        if !e.trim().is_empty() {
                            slot.endpoint = e.to_owned();
                        }
                    }
                }
            }
        }
        cfg
    }

    pub fn config_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(dir).join("bogusmips/agent.json");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config/bogusmips/agent.json");
        }
        std::env::temp_dir().join("bogusmips-agent.json")
    }

    pub fn load() -> Self {
        Self::load_from(&Self::config_path())
    }

    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| JsonValue::parse(&s).ok())
            .map(|v| Self::from_json(&v))
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Self::config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, self.to_json().to_json_string()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_config_json() {
        let mut cfg = AgentConfig::default();
        cfg.provider = Provider::Gemini;
        cfg.settings_mut(Provider::Grok).api_key = "xai-key".to_owned();
        cfg.settings_mut(Provider::Grok).model = "grok-4".to_owned();
        cfg.settings_mut(Provider::Gemini).api_key = "gem-key".to_owned();
        cfg.settings_mut(Provider::Claude).api_key = "ant-key".to_owned();
        cfg.include_network = false;

        let json = cfg.to_json().to_json_string();
        let parsed = AgentConfig::from_json(&JsonValue::parse(&json).unwrap());
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn provider_presets_and_defaults_are_valid() {
        for p in Provider::ALL {
            assert_eq!(Provider::from_id(p.id()), Some(p));
            assert!(!p.preset_models().is_empty());
            assert!(p.default_endpoint().starts_with("http"));
        }
    }
}

