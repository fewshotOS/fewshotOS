//! `fewshot-approve`: the approval window (ARCHITECTURE §6.1, ADR-0006).
//!
//! A separate process that alone holds the approval signing key. Runtimes
//! connect over a local socket and send requests; the user's decisions go
//! back signed. Text comes from fixed templates filled with gate data.

mod inbox;
mod server;

use eframe::egui;
use fewshot_approval::{Server, default_dir, load_or_create, socket_name};
use inbox::Inbox;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn main() -> eframe::Result {
    let dir = default_dir();
    let approver = match load_or_create(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fewshot-approve: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("fewshot-approve: approval key in {}", dir.display());
    let server = match Server::bind(&socket_name()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fewshot-approve: cannot listen on {} (already running?): {e}", socket_name());
            std::process::exit(1);
        }
    };
    let inbox = Arc::new(Mutex::new(Inbox::new(approver)));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Fewshot approvals")
            .with_inner_size([520.0, 380.0])
            .with_always_on_top(),
        ..Default::default()
    };
    eframe::run_native(
        "fewshot-approve",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let shared = inbox.clone();
            std::thread::spawn(move || server::serve(server, shared, move || ctx.request_repaint()));
            Ok(Box::new(App { inbox }))
        }),
    )
}

struct App {
    inbox: Arc<Mutex<Inbox>>,
}

/// What the user clicked this frame, applied after drawing.
enum Click {
    One(usize, usize, bool),
    All(usize, bool),
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let mut click = None;
        egui::CentralPanel::default().show(ui, |ui| {
            let inbox = self.inbox.lock().expect("inbox lock");
            if inbox.pending().is_empty() {
                ui.label("No requests waiting.");
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (r, p) in inbox.pending().iter().enumerate() {
                    ui.group(|ui| {
                        ui.heading(format!("{} asks:", p.request.client));
                        for (i, (item, choice)) in p.request.items.iter().zip(&p.choices).enumerate() {
                            ui.separator();
                            ui.label(&item.text);
                            for a in &item.args {
                                let mark = if a.below_floor { " (untrusted)" } else { "" };
                                ui.small(format!("{}: from {}, {}{mark}", a.param, a.origin, a.integrity));
                            }
                            if item.context_below_floor {
                                ui.small(format!("agent context: {}", item.context_integrity));
                            }
                            match choice {
                                Some(true) => drop(ui.label("Approved")),
                                Some(false) => drop(ui.label("Denied")),
                                None => {
                                    ui.horizontal(|ui| {
                                        if ui.button("Approve").clicked() {
                                            click = Some(Click::One(r, i, true));
                                        }
                                        if ui.button("Deny").clicked() {
                                            click = Some(Click::One(r, i, false));
                                        }
                                    });
                                }
                            }
                        }
                        if p.choices.iter().filter(|c| c.is_none()).count() > 1 {
                            ui.separator();
                            ui.horizontal(|ui| {
                                if ui.button("Approve all").clicked() {
                                    click = Some(Click::All(r, true));
                                }
                                if ui.button("Deny all").clicked() {
                                    click = Some(Click::All(r, false));
                                }
                            });
                        }
                    });
                }
            });
        });
        let Some(click) = click else { return };
        let mut inbox = self.inbox.lock().expect("inbox lock");
        let result = match click {
            Click::One(r, i, approve) => inbox.decide(r, i, approve, now_ms()),
            Click::All(r, approve) => inbox.decide_all(r, approve, now_ms()),
        };
        if let Err(e) = result {
            eprintln!("fewshot-approve: could not sign: {e}");
        }
    }
}
