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
    /// Docker's action: `start`, or `exec_start: <cmd>` (the filter matches the part before `:`).
    pub(crate) action: String,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) labels: Vec<(String, String)>,
    /// `exitCode` of a `die`.
    pub(crate) exit: Option<i32>,
}

/// The image and labels each container's last event carried, so an exec event (which only knows
/// the container's name) is described as Docker describes it.
type Meta = std::collections::HashMap<String, (String, Vec<(String, String)>)>;
static META: Mutex<Option<Meta>> = Mutex::new(None);

/// `exec_create: <cmd>`, `exec_start: <cmd>`, `exec_die`: an exec's events, with its id
/// (`execID`) and its container's image and labels, as Docker sends them.
pub(crate) fn exec_event(kind: &str, name: &str, cmd: &[String], exec_id: &str, exit: Option<i32>) {
    let (image, mut labels) = META
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).cloned()))
        .unwrap_or_default();
    labels.push(("execID".to_string(), exec_id.to_string()));
    let action = if kind == "exec_die" {
        kind.to_string()
    } else {
        format!("{kind}: {}", cmd.join(" "))
    };
    publish(&Event {
        action,
        name: name.to_string(),
        image,
        labels,
        exit,
    });
}

/// Docker's `action` for `name` (`die` with its `exit`, `kill`, `stop`, `restart`), described by
/// the image and labels its last event carried. A container this server made no event for makes
/// none here either.
pub(crate) fn publish_named(action: &str, name: &str, exit: Option<i32>) {
    let meta = META
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).cloned()));
    if let Some((image, labels)) = meta {
        publish(&Event {
            action: action.to_string(),
            name: name.to_string(),
            image,
            labels,
            exit,
        });
    }
}

/// The container is removed: Docker's `destroy`, with the image and labels its events carried,
/// which go with it. A container this server made no event for makes none here either.
pub(crate) fn destroyed(name: &str) {
    let meta = META
        .lock()
        .ok()
        .and_then(|mut g| g.as_mut().and_then(|m| m.remove(name)));
    if let Some((image, labels)) = meta {
        publish(&Event {
            action: "destroy".into(),
            name: name.to_string(),
            image,
            labels,
            exit: None,
        });
    }
}

/// The streams open now. A sender whose stream has gone is dropped at the next publish.
static SUBSCRIBERS: Mutex<Vec<Sender<String>>> = Mutex::new(Vec::new());

/// Send `e` to every open stream whose filters take it.
pub(crate) fn publish(e: &Event) {
    if !e.action.starts_with("exec_") && e.action != "destroy" {
        if let Ok(mut g) = META.lock() {
            let m = g.get_or_insert_with(Default::default);
            m.insert(e.name.clone(), (e.image.clone(), e.labels.clone()));
        }
    }
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
        a = json_str(&e.action),
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
            // Docker matches an event by its TYPE, the action before any `:` (`exec_start: sh`).
            && (self.events.is_empty() || {
                let action = field("Action");
                let kind = action.split_once(':').map_or(action, |(k, _)| k);
                self.events.iter().any(|a| a == kind || a == action)
            })
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
        extra: Vec::new(),
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

    /// The tests that subscribe share `SUBSCRIBERS`, and count it: one at a time.
    static SUBSCRIBING: Mutex<()> = Mutex::new(());

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
            action: "start".into(),
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

    /// `docker events --filter event=exec_start` matches `exec_start: true`: Docker matches an
    /// event by its type, the action before the `:`. MEASURED before: kern sent no exec event at
    /// all, so the filtered stream printed nothing where Docker printed `exec_start: true`.
    #[test]
    fn an_exec_event_names_its_command_and_matches_by_type() {
        let e = Event {
            action: "exec_start: true".into(),
            name: "kd-x".into(),
            image: "alpine:3.21".into(),
            labels: vec![("execID".into(), "ab12".into())],
            exit: None,
        };
        let ev = json::parse(&to_json(&e)).unwrap();
        let f = |q: &str| Filters::parse(&req(&[("filters", q)])).unwrap();
        assert!(f(r#"{"event":["exec_start"]}"#).keeps(&ev));
        assert!(f(r#"{"event":["exec_start: true"]}"#).keeps(&ev));
        assert!(!f(r#"{"event":["exec_die"]}"#).keeps(&ev));
        let attrs = ev.get("Actor").and_then(|a| a.get("Attributes")).unwrap();
        assert_eq!(attrs.get("execID").and_then(Value::as_str), Some("ab12"));
    }

    /// `rm` publishes `destroy` with what the container's events carried, once; a container this
    /// server made no event for makes none. MEASURED before: `docker events` on kern's socket
    /// printed `create start die` for a `run` then `rm`, where Docker's printed `destroy` too.
    #[test]
    fn removal_publishes_destroy_with_the_containers_labels_once() {
        let _one = SUBSCRIBING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tx, rx) = mpsc::channel();
        SUBSCRIBERS.lock().unwrap().push(tx);
        publish(&Event {
            action: "create".into(),
            name: "kd-destroy".into(),
            image: "alpine:3.20".into(),
            labels: vec![("com.example".into(), "1".into())],
            exit: None,
        });
        destroyed("kd-destroy");
        destroyed("kd-destroy");
        destroyed("kd-never-seen");
        let mine: Vec<Value> =
            std::iter::from_fn(|| rx.recv_timeout(Duration::from_millis(200)).ok())
                .filter_map(|l| json::parse(&l).ok())
                .filter(|v| {
                    v.get("Actor")
                        .and_then(|a| a.get("Attributes"))
                        .and_then(|a| a.get("name"))
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.starts_with("kd-destroy") || n == "kd-never-seen")
                })
                .collect();
        let actions: Vec<&str> = mine
            .iter()
            .filter_map(|v| v.get("Action").and_then(Value::as_str))
            .collect();
        assert_eq!(actions, ["create", "destroy"]);
        let attrs = mine[1]
            .get("Actor")
            .and_then(|a| a.get("Attributes"))
            .unwrap();
        assert_eq!(attrs.get("com.example").and_then(Value::as_str), Some("1"));
        assert_eq!(
            mine[1].get("from").and_then(Value::as_str),
            Some("alpine:3.20")
        );
        assert!(META
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|m| !m.contains_key("kd-destroy")));
    }

    /// A published event reaches an open stream, and a stream that went away is dropped.
    #[test]
    fn publish_reaches_subscribers_and_drops_the_closed() {
        let _one = SUBSCRIBING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            action: "create".into(),
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
