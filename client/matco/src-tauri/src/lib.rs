// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();

    // ÖNEMLİ: single-instance eklentisi ilk kaydedilen eklenti olmalı
    // (resmi dokümandaki kural). İkinci kez açılmaya çalışıldığında yeni
    // process hiçbir pencere açmadan hemen kapanır, bunun yerine burada
    // mevcut (ilk) pencere öne getirilip odaklanır.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        use tauri::Manager;
        if let Some(win) = app.webview_windows().values().next() {
            let _ = win.show();
            let _ = win.unminimize();
            let _ = win.set_focus();
        }
    }));

    let builder = builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet]);

    // Sistem tepsisi (tray) sadece masaüstünde (Windows/Linux/macOS) var;
    // mobilde (Android/iOS) bu kavram yok, o yüzden #[cfg(desktop)] ile
    // sarmalıyoruz ki mobil derlemeyi bozmasın.
    #[cfg(desktop)]
    let builder = builder.setup(|app| {
        use tauri::{
            menu::{Menu, MenuItem},
            tray::TrayIconBuilder,
            Manager,
        };

        let show_item = MenuItem::with_id(app, "show", "Magma'yı Aç", true, None::<&str>)?;
        let quit_item = MenuItem::with_id(app, "quit", "Çıkış", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

        TrayIconBuilder::new()
            .icon(app.default_window_icon().unwrap().clone())
            .menu(&menu)
            .tooltip("Magma")
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => {
                    // "main" etiketine güvenmek yerine, hangi etiketle
                    // oluşturulmuş olursa olsun ilk pencereyi buluyoruz -
                    // tauri.conf.json'da label ayarlanmamış olsa bile çalışsın.
                    if let Some(win) = app.webview_windows().values().next() {
                        let _ = win.show();
                        let _ = win.unminimize();
                        let _ = win.set_focus();
                    }
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                // Sol tık: tepsi ikonuna tıklamak pencereyi geri getirir/odaklar.
                if let tauri::tray::TrayIconEvent::Click {
                    button: tauri::tray::MouseButton::Left,
                    button_state: tauri::tray::MouseButtonState::Up,
                    ..
                } = event
                {
                    let app = tray.app_handle();
                    if let Some(win) = app.webview_windows().values().next() {
                        let _ = win.show();
                        let _ = win.unminimize();
                        let _ = win.set_focus();
                    }
                }
            })
            .build(app)?;

        Ok(())
    });

    // ÖNEMLİ: pencere kapatma (X) isteğini burada, Builder üzerinde
    // yakalıyoruz. Tek pencere olduğu için label kontrolü yapmadan
    // hangi pencere kapatılırsa kapatılsın gizliyoruz.
    let builder = builder.on_window_event(|window, event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            // Label kontrolü kasıtlı olarak yok: tauri.conf.json'da "label"
            // alanı "main" olarak ayarlanmamışsa (ya da hiç yoksa) eşleşme
            // sessizce başarısız olup pencere normal şekilde kapanıyordu.
            // Tek pencaremiz olduğu için hangi pencere olursa olsun gizlemek
            // güvenli.
            window.hide().ok();
            api.prevent_close();
        }
    });

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}