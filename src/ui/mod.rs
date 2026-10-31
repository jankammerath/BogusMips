pub mod agent_panel;
pub mod content_view;
pub mod highlight;
pub mod icon;
pub mod icons;
pub mod info_panel;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod native_menu;
pub mod net_detail;
pub mod network_view;
pub mod search_view;
pub mod theme;
pub mod tree_view;

/// Commands of the application menu (native or in-app).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MenuAction {
    Open,
    Export,
    Close,
    Quit,
    ShowExplorer,
    ShowSearch,
    ShowNetwork,
    ShowAgent,
    ToggleInfo,
}
