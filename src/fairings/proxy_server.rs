//! Reverse Proxy im Hintergrund (Liftoff): Ports aus `proxy_listen` öffnen. Ist ein Port
//! belegt, steht das im Protokoll und unter `GET /proxy` – der Rest läuft weiter.

use crate::config::Config;
use crate::proxy::ProxyState;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Orbit, Rocket};

pub struct ProxyServer;

#[rocket::async_trait]
impl Fairing for ProxyServer {
    fn info(&self) -> Info {
        Info {
            name: "Reverse Proxy",
            kind: Kind::Liftoff,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let (Some(config), Some(state)) = (rocket.state::<Config>(), rocket.state::<ProxyState>())
        else {
            return;
        };
        if !config.background {
            return;
        }
        if config.proxy_listen.is_empty() {
            tracing::info!("Kein Reverse Proxy (proxy_listen ist leer)");
            return;
        }
        state.serve(&config.proxy_listen, rocket.shutdown()).await;
    }
}
