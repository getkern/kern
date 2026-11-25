//! `GET /events`: Docker's event stream, for the containers this server creates and starts.
//!
//! kern has no daemon and so no event bus, and `kern events` watches the registry every 500 ms.
//! This server does not need to watch: it is the one creating and starting these containers, so it
//! publishes each event at the moment it happens, and a client waiting for one (Dev Containers
//! waits for `start` before it goes on) is not made to wait a poll interval for it. A box started
//! with kern directly makes no event here.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;

use kern_common::json::{self, Value};
use kern_common::json_str;

use crate::api::{error, filter_values, id_of};
use crate::{Request, Response};

/// One container event, as Docker's stream spells it.
#[derive(Clone)]
pub(crate) struct Event {
    pub(crate) action: &'static str,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) labels: Vec<(String, String)>,
    /// `exitCode` of a `die`.
    pub(crate) exit: Option<i32>,
}

/// The streams open now. A sender whose stream has gone is dropped at the next publish.
static SUBSCRIBERS: Mutex<Vec<Sender<String>>> = Mutex::new(Vec::new());

/// Send `e` to every open stream whose filters take it.
pub(crate) fn publish(e: &Event) {
    let line = to_json(e);
    let Ok(mut subs) = SUBSCRIBERS.lock() else {
        return;
    };
    if subs.is_empty() {
        return;
    }
    // Each stream applies its own filters to the line, so one encoding serves them all.
    subs.retain(|s| s.send(line.clone()).is_ok());
}

fn to_json(e: &Event) -> String {
    let id = id_of(&e.name);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut attrs = vec![
        format!("\"image\":{}", json_str(&e.image)),
        format!("\"name\":{}", json_str(&e.name)),
    ];
    if let Some(code) = e.exit {
        attrs.push(format!("\"exitCode\":{}", json_str(&code.to_string())));
    }
    for (k, v) in &e.labels {
        if k != "image" && k != "name" && k != "exitCode" {
            attrs.push(format!("{}:{}", json_str(k), json_str(v)));
        }
    }
    format!(
        "{{\"status\":{a},\"id\":{id},\"from\":{img},\"Type\":\"container\",\"Action\":{a},\"Actor\":{{\"ID\":{id},\"Attributes\":{{{}}}}},\"scope\":\"local\",\"time\":{},\"timeNano\":{}}}",
        attrs.join(","),
        since.as_secs(),
        since.as_nanos(),
        a = json_str(e.action),
        id = json_str(&id),
        img = json_str(&e.image),
    )
}

/// The filters of an event stream: `type` (only `container` has events here), `event`,
/// `container` (a name, or an id or its prefix), `label` (`k` or `k=v`) and `image`. Another one,
/// and `since`/`until` (there is no history to replay and no end to stop at), are refused by name.
struct Filters {
    types: Vec<String>,
    events: Vec<String>,
    containers: Vec<String>,
    labels: Vec<String>,
    images: Vec<String>,
}

impl Filters {
    fn parse(req: &Request) -> Result<Self, String> {
        for p in ["since", "until"] {
            if req.param(p).is_some_and(|v| !v.is_empty()) {
                return Err(format!(
                    "events {p}=: not translated by kern-serve (it streams what happens from now on)"
                ));
            }
        }
        let f = match req.param("filters").filter(|f| !f.is_empty()) {
            Some(f) => json::parse(f).map_err(|e| format!("invalid filters: {e}"))?,
            None => Value::Null,
        };
        if let Some((k, _)) = f.as_object().unwrap_or_default().iter().find(|(k, _)| {
            !matches!(
                k.as_str(),
                "type" | "event" | "container" | "label" | "image"
            )
        }) {
            return Err(format!("events filter {k:?}: not translated by kern-serve"));
        }
        Ok(Self {
            types: filter_values(&f, "type"),
            events: filter_values(&f, "event"),
            containers: filter_values(&f, "container"),
            labels: filter_values(&f, "label"),
            images: filter_values(&f, "image"),
        })
    }

    fn keeps(&self, e: &Value) -> bool {
        let field = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or_default();
        let attr = |k: &str| {
            e.get("Actor")
                .and_then(|a| a.get("Attributes"))
                .and_then(|a| a.get(k))
                .and_then(Value::as_str)
        };
        let (id, name) = (field("id"), attr("name").unwrap_or_default());
        (self.types.is_empty() || self.types.iter().any(|t| t == field("Type")))
            && (self.events.is_empty() || self.events.iter().any(|a| a == field("Action")))
            && (self.containers.is_empty()
                || self
                    .containers
                    .iter()
                    .any(|c| c == name || (!c.is_empty() && id.starts_with(c.as_str()))))
            && (self.images.is_empty() || self.images.iter().any(|i| i == field("from")))
            && self.labels.iter().all(|l| match l.split_once('=') {
                Some((k, v)) => attr(k) == Some(v),
                None => attr(l).is_some(),
            })
    }
}

/// `GET /events`. The stream is subscribed before this returns, so an event published while the
/// answer's head is on its way is not lost: Dev Containers opens it and starts its container in
/// the same moment.
pub(crate) fn events(req: &Request) -> Response {
    let filters = match Filters::parse(req) {
        Ok(f) => f,
        Err(e) => return error(400, &e),
    };
    let (tx, rx) = mpsc::channel();
    match SUBSCRIBERS.lock() {
        Ok(mut subs) => subs.push(tx),
        Err(_) => return error(500, "the event stream's subscriber list is poisoned"),
    }
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        writer: Box::new(move |w: &mut crate::Out| stream(&rx, &filters, w)),
    }
}

/// How often a stream with nothing to send checks that its client is still there.
const IDLE_CHECK: Duration = Duration::from_millis(500);

fn stream(rx: &Receiver<String>, filters: &Filters, w: &mut crate::Out) {
    use std::io::Write;
    loop {
        match rx.recv_timeout(IDLE_CHECK) {
            Ok(line) => {
                let keep = json::parse(&line).is_ok_and(|e| filters.keeps(&e));
                if keep && (writeln!(w, "{line}").is_err() || w.flush().is_err()) {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if client_gone(w) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The client hung up: a stream that only ever writes would otherwise learn it at the next event,
/// which may never come, and hold a thread and a subscriber until then.
fn client_gone(w: &crate::Out) -> bool {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: w.socket().as_raw_fd(),
        events: libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: one pollfd owned here, count 1, zero timeout: it returns at once.
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n > 0 && pfd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(query: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            path: "/events".into(),
            query: query
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        }
    }

    fn start_of(name: &str, labels: &[(&str, &str)]) -> Value {
        let e = Event {
            action: "start",
            name: name.into(),
            image: "alpine:3.19".into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            exit: None,
        };
        json::parse(&to_json(&e)).unwrap()
    }

    /// The event is Docker's shape: what Dev Containers reads (`Action`, the labels in
    /// `Actor.Attributes`) and what `docker events` prints (`status`, `id`, `from`, `time`).
    #[test]
    fn an_event_carries_docker_fields_and_the_labels_as_attributes() {
        let e = start_of("kd-1", &[("devcontainer.local_folder", "/w")]);
        assert_eq!(e.get("Action").and_then(Value::as_str), Some("start"));
        assert_eq!(e.get("status").and_then(Value::as_str), Some("start"));
        assert_eq!(e.get("Type").and_then(Value::as_str), Some("container"));
        assert_eq!(e.get("from").and_then(Value::as_str), Some("alpine:3.19"));
        assert_eq!(
            e.get("id").and_then(Value::as_str),
            Some(id_of("kd-1").as_str())
        );
        let attrs = e.get("Actor").and_then(|a| a.get("Attributes")).unwrap();
        assert_eq!(
            attrs
                .get("devcontainer.local_folder")
                .and_then(Value::as_str),
            Some("/w")
        );
        assert_eq!(attrs.get("name").and_then(Value::as_str), Some("kd-1"));
        assert!(e
            .get("timeNano")
            .and_then(Value::as_i64)
            .is_some_and(|n| n > 0));
    }

    /// The filters a client sends, in both spellings of the map, and the refusals.
    #[test]
    fn filters_select_by_event_label_container_and_refuse_the_rest() {
        let ev = start_of("kd-1", &[("a", "1")]);
        let f = |q: &str| Filters::parse(&req(&[("filters", q)])).unwrap();
        assert!(f(r#"{"event":{"start":true}}"#).keeps(&ev));
        assert!(!f(r#"{"event":["die"]}"#).keeps(&ev));
        assert!(f(r#"{"label":["a=1"]}"#).keeps(&ev));
        assert!(!f(r#"{"label":["a=2"]}"#).keeps(&ev));
        assert!(f(r#"{"container":["kd-1"]}"#).keeps(&ev));
        assert!(f(&format!(r#"{{"container":["{}"]}}"#, &id_of("kd-1")[..12])).keeps(&ev));
        assert!(!f(r#"{"container":["kd-2"]}"#).keeps(&ev));
        assert!(f(r#"{"type":["container"]}"#).keeps(&ev));
        assert!(!f(r#"{"type":["image"]}"#).keeps(&ev));
        assert!(Filters::parse(&req(&[("filters", r#"{"network":["n"]}"#)])).is_err());
        assert!(Filters::parse(&req(&[("since", "1700000000")])).is_err());
        assert!(Filters::parse(&req(&[("filters", "{bad")])).is_err());
    }

    /// A published event reaches an open stream, and a stream that went away is dropped.
    #[test]
    fn publish_reaches_subscribers_and_drops_the_closed() {
        let (tx, rx) = mpsc::channel();
        let (gone_tx, gone_rx) = mpsc::channel::<String>();
        drop(gone_rx);
        {
            let mut subs = SUBSCRIBERS.lock().unwrap();
            subs.push(tx);
            subs.push(gone_tx);
        }
        let before = SUBSCRIBERS.lock().unwrap().len();
        publish(&Event {
            action: "create",
            name: "kd-pub".into(),
            image: "alpine:3.19".into(),
            labels: Vec::new(),
            exit: None,
        });
        let line = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(line.contains("\"Action\":\"create\"") && line.contains("kd-pub"));
        assert!(SUBSCRIBERS.lock().unwrap().len() < before);
    }
}
