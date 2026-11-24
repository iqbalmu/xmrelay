use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use xmrelay_core::session::{EventSourceRef, ProjectRef, SessionSource};
use xmrelay_core::{
    Actor, AgentId, AgentInfo, Classification, Confidence, Event, EventContent, EventKind,
    ParseReport, ParseStatus, Session, ToolInfo, ToolStatus,
};
use xmrelay_handoff::{
    create_handoff, export_handoff, generate_continuation_prompt, list_handoffs, validate_handoff,
    PreflightStatus,
};

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("xmr-ho-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) {
    let s = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .unwrap();
    assert!(s.success());
}

fn sample_session(root: &Path, written_file: &str, secret: &str) -> Session {
    Session {
        id: "ses_demo".into(),
        agent: AgentInfo {
            id: AgentId::OpenCode,
            version: Some("2.2.6".into()),
            adapter_version: "0.1.0".into(),
        },
        source: SessionSource {
            path: "/tmp/opencode.db".into(),
            format: "opencode-sqlite".into(),
            format_version: Some("session_v2".into()),
        },
        project: Some(ProjectRef {
            root: root.display().to_string(),
            repository: true,
        }),
        started_at: Some("2026-11-13T00:00:00Z".into()),
        updated_at: Some("2026-11-13T00:05:00Z".into()),
        events: vec![
            Event {
                id: "e1".into(),
                sequence: 1,
                timestamp: None,
                kind: EventKind::UserMessage,
                actor: Actor::User,
                content: EventContent {
                    text: Some(format!("Implement auth endpoint using token {secret}")),
                    structured: None,
                },
                tool: None,
                status: ToolStatus::Unknown,
                source_ref: EventSourceRef {
                    session_id: "ses_demo".into(),
                    native_event_id: Some("m1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            Event {
                id: "e2".into(),
                sequence: 2,
                timestamp: None,
                kind: EventKind::FileChange,
                actor: Actor::Tool,
                content: EventContent {
                    text: None,
                    structured: Some(json!({ "path": written_file, "tool": "write" })),
                },
                tool: None,
                status: ToolStatus::Succeeded,
                source_ref: EventSourceRef {
                    session_id: "ses_demo".into(),
                    native_event_id: Some("t1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            Event {
                id: "e3".into(),
                sequence: 3,
                timestamp: None,
                kind: EventKind::ToolResult,
                actor: Actor::Tool,
                content: EventContent::default(),
                tool: Some(ToolInfo {
                    name: "shell".into(),
                    input: Some(json!({ "command": "cargo test" })),
                    output: Some("1 test failed".into()),
                }),
                status: ToolStatus::Failed,
                source_ref: EventSourceRef {
                    session_id: "ses_demo".into(),
                    native_event_id: Some("t2".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
        ],
        parse_report: ParseReport {
            total_events: 3,
            parsed_events: 3,
            partial_events: 0,
            unsupported: Vec::new(),
            errors: Vec::new(),
        },
    }
}

#[test]
fn builds_verifies_redacts_and_detects_missing_file_conflict() {
    let t = Tmp::new("flow");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("AGENTS.md"), "always run tests\n").unwrap();
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let secret = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
    let sess = sample_session(&repo, "src/auth.rs", &secret);

    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();
    assert_eq!(
        detail.validation.status,
        PreflightStatus::PassedWithWarnings
    );
    assert!(detail.validation.checksums_valid);
    assert_eq!(detail.manifest.confidence.overall, Confidence::Medium);
    assert_eq!(
        detail.evidence.items[0].classification,
        Classification::Verified
    );
    assert!(!detail.context_md.contains(&secret));
    assert!(detail.context_md.contains("[REDACTED:aws_access_key]"));

    let exp_root = t.0.join("exported");
    let exp_path = export_handoff(&store, &detail.manifest.handoff_id, &exp_root, false).unwrap();
    assert!(exp_path.join("manifest.json").is_file());
    assert!(export_handoff(&store, &detail.manifest.handoff_id, &exp_root, false).is_err());
    assert!(export_handoff(&store, &detail.manifest.handoff_id, &exp_root, true).is_ok());

    let list = list_handoffs(&store).unwrap();
    assert_eq!(list.len(), 1);

    let pkg_dir = store.join(&detail.manifest.handoff_id);
    let prompt = generate_continuation_prompt(&detail, &pkg_dir);
    assert!(prompt.contains("Do not assume the handoff summary is fully correct"));
    assert!(prompt.contains("Match the user's language, tone, and communication style"));

    // Delete the verified file on disk -> live validation blocks continuation!
    fs::remove_file(repo.join("src/auth.rs")).unwrap();
    let reval = validate_handoff(&store, &detail.manifest.handoff_id, Some(&repo)).unwrap();
    assert_eq!(reval.validation.status, PreflightStatus::Blocked);
    assert!(reval.validation.conflicts.iter().any(|c| c.critical));

    // Also test creating a handoff when a claimed file is already missing
    let bad_sess = sample_session(&repo, "src/ghost.rs", &secret);
    let blocked = create_handoff(&bad_sess, AgentId::AntigravityCli, Some(&repo), &store).unwrap();
    assert_eq!(blocked.validation.status, PreflightStatus::Blocked);
    assert_eq!(blocked.manifest.confidence.overall, Confidence::Low);

    let blocked_pkg = store.join(&blocked.manifest.handoff_id);
    let unack_prompt = generate_continuation_prompt(&blocked, &blocked_pkg);
    assert!(unack_prompt.contains("Preflight status: Blocked\n"));
    assert!(!unack_prompt.contains("already acknowledged"));

    let ack_prompt =
        xmrelay_handoff::generate_continuation_prompt_with_options(&blocked, &blocked_pkg, true);
    assert!(ack_prompt.contains("Preflight status: Blocked (conflicts acknowledged by user)"));
    assert!(ack_prompt.contains("already acknowledged the preflight conflicts"));
    assert!(ack_prompt.contains("ask for user approval before editing any code"));
}

#[test]
fn missing_file_outside_workspace_warns_instead_of_blocking() {
    let t = Tmp::new("outside-ws");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("README.md"), "hello\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let outside_missing = t.0.join("scratch/main.go");
    let sess = sample_session(&repo, &outside_missing.display().to_string(), "no-secret");

    let detail = create_handoff(&sess, AgentId::AntigravityCli, Some(&repo), &store).unwrap();
    assert_eq!(
        detail.validation.status,
        PreflightStatus::PassedWithWarnings
    );
    assert!(detail.validation.conflicts.is_empty());
    assert!(detail
        .validation
        .warnings
        .iter()
        .any(|w| w.contains("outside workspace") && w.contains("no longer on disk")));
}

#[test]
fn trimmed_checksums_file_does_not_hide_tampering() {
    let t = Tmp::new("trimmed");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/a.rs"), "fn a() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let secret = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
    let sess = sample_session(&repo, "src/a.rs", &secret);
    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();
    assert!(detail.validation.checksums_valid);

    // Drop the context.md line from checksums.txt, then tamper with the file
    // it used to describe. The reverse check must still catch it.
    let pkg = store.join(&detail.manifest.handoff_id);
    let sums = fs::read_to_string(pkg.join("checksums.txt")).unwrap();
    let trimmed: String = sums
        .lines()
        .filter(|l| !l.contains("  context.md"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(pkg.join("checksums.txt"), trimmed).unwrap();
    fs::write(pkg.join("context.md"), "tampered context").unwrap();

    let re = validate_handoff(&store, &detail.manifest.handoff_id, Some(&repo)).unwrap();
    assert!(!re.validation.checksums_valid);
    assert!(re
        .validation
        .checksum_errors
        .iter()
        .any(|e| e.contains("not covered by checksums.txt") && e.contains("context.md")));
}

#[test]
fn context_accuracy_handles_in_session_rm_multiline_and_affirmative_reply() {
    let t = Tmp::new("ctx-acc");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("lib/ui")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("lib/main.dart"), "void main() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let sess = Session {
        id: "ses_acc".into(),
        agent: AgentInfo {
            id: AgentId::Omp,
            version: Some("1.0".into()),
            adapter_version: "0.1.0".into(),
        },
        source: SessionSource {
            path: "/tmp/omp.jsonl".into(),
            format: "omp-jsonl".into(),
            format_version: Some("3".into()),
        },
        project: Some(ProjectRef {
            root: repo.display().to_string(),
            repository: true,
        }),
        started_at: None,
        updated_at: None,
        events: vec![
            // 1. Multi-line user message starting with [Image ...]
            Event {
                id: "e1".into(),
                sequence: 1,
                timestamp: None,
                kind: EventKind::UserMessage,
                actor: Actor::User,
                content: EventContent {
                    text: Some(
                        "[Image #1, 480x360]\n\nhapus aja fitur kunci app ini untuk sekarang"
                            .into(),
                    ),
                    structured: None,
                },
                tool: None,
                status: ToolStatus::Unknown,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("u1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 2. File createdearlier in session (`lib/ui/app_lock_gate.dart`)
            Event {
                id: "e2".into(),
                sequence: 2,
                timestamp: None,
                kind: EventKind::FileChange,
                actor: Actor::Tool,
                content: EventContent {
                    text: None,
                    structured: Some(
                        json!({ "path": "lib/ui/app_lock_gate.dart", "tool": "write" }),
                    ),
                },
                tool: None,
                status: ToolStatus::Succeeded,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("fc1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 3. Transient edit failure on `lib/main.dart`, resolved by a later FileChange
            Event {
                id: "e3".into(),
                sequence: 3,
                timestamp: None,
                kind: EventKind::ToolResult,
                actor: Actor::Tool,
                content: EventContent::default(),
                tool: Some(ToolInfo {
                    name: "edit".into(),
                    input: Some(json!({ "path": "lib/main.dart" })),
                    output: Some("Could not find a close enough match".into()),
                }),
                status: ToolStatus::Failed,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("tr1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 4. Subsequent successful edit on `lib/main.dart`
            Event {
                id: "e4".into(),
                sequence: 4,
                timestamp: None,
                kind: EventKind::FileChange,
                actor: Actor::Tool,
                content: EventContent {
                    text: None,
                    structured: Some(json!({ "path": "lib/main.dart", "tool": "edit" })),
                },
                tool: None,
                status: ToolStatus::Succeeded,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("fc2".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 5. Agent deletes `lib/ui/app_lock_gate.dart` via bash `rm`
            Event {
                id: "e5".into(),
                sequence: 5,
                timestamp: None,
                kind: EventKind::ToolResult,
                actor: Actor::Tool,
                content: EventContent::default(),
                tool: Some(ToolInfo {
                    name: "bash".into(),
                    input: Some(json!({ "command": "rm lib/ui/app_lock_gate.dart" })),
                    output: Some("deleted".into()),
                }),
                status: ToolStatus::Succeeded,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("tr2".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 6. Benign `rg` exit-1 check
            Event {
                id: "e6".into(),
                sequence: 6,
                timestamp: None,
                kind: EventKind::ToolResult,
                actor: Actor::Tool,
                content: EventContent::default(),
                tool: Some(ToolInfo {
                    name: "bash".into(),
                    input: Some(json!({ "command": "rg -n app_lock lib/" })),
                    output: Some("stragglers-exit=1".into()),
                }),
                status: ToolStatus::Failed,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("tr3".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            // 7. User asks for plan -> Assistant proposes plan -> User says "ya"
            Event {
                id: "e7".into(),
                sequence: 7,
                timestamp: None,
                kind: EventKind::UserMessage,
                actor: Actor::User,
                content: EventContent {
                    text: Some("commit dan berikan rencana selanjutnya".into()),
                    structured: None,
                },
                tool: None,
                status: ToolStatus::Unknown,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("u2".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            Event {
                id: "e8".into(),
                sequence: 8,
                timestamp: None,
                kind: EventKind::AssistantMessage,
                actor: Actor::Assistant,
                content: EventContent {
                    text: Some(
                        "Rencana berikutnya: implement bulk draft inbox action dan unit test."
                            .into(),
                    ),
                    structured: None,
                },
                tool: None,
                status: ToolStatus::Unknown,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("a1".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
            Event {
                id: "e9".into(),
                sequence: 9,
                timestamp: None,
                kind: EventKind::UserMessage,
                actor: Actor::User,
                content: EventContent {
                    text: Some("ya".into()),
                    structured: None,
                },
                tool: None,
                status: ToolStatus::Unknown,
                source_ref: EventSourceRef {
                    session_id: "ses_acc".into(),
                    native_event_id: Some("u3".into()),
                },
                parse_status: ParseStatus::Parsed,
            },
        ],
        parse_report: ParseReport {
            total_events: 9,
            parsed_events: 9,
            partial_events: 0,
            unsupported: Vec::new(),
            errors: Vec::new(),
        },
    };

    let detail = create_handoff(&sess, AgentId::AntigravityCli, Some(&repo), &store).unwrap();
    // No conflicts! `lib/ui/app_lock_gate.dart` was deleted in session.
    assert!(detail.validation.conflicts.is_empty());
    assert_eq!(detail.validation.status, PreflightStatus::Passed);
    assert_eq!(detail.manifest.confidence.overall, Confidence::High);

    // Multi-line user message preserved beyond `[Image #1, ...]`
    assert!(detail
        .context_md
        .contains("hapus aja fitur kunci app ini untuk sekarang"));
    // Removed file is recorded as completed `Remove lib/ui/app_lock_gate.dart`
    assert!(detail
        .context_md
        .contains("Remove lib/ui/app_lock_gate.dart"));
    // Short affirmative "ya" resolved with previous user request + assistant plan
    assert!(detail
        .context_md
        .contains("commit dan berikan rencana selanjutnya → user confirmed 'ya'"));
    assert!(detail.context_md.contains("## Recent Assistant Context"));
    // Transient edit mismatch and benign rg exit-1 are not in Failed Attempts
    assert!(detail
        .context_md
        .contains("## Failed Attempts\n- None recorded."));

    // Re-validating the stored handoff also passes cleanly
    let reval = validate_handoff(&store, &detail.manifest.handoff_id, Some(&repo)).unwrap();
    assert_eq!(reval.validation.status, PreflightStatus::Passed);
}

/// Recursively assert that no file under `dir` contains `needle`.
fn assert_dir_lacks(dir: &Path, needle: &str) {
    fn walk(p: &Path, needle: &str) {
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap().flatten() {
                walk(&e.path(), needle);
            }
        } else if let Ok(b) = fs::read(p) {
            assert!(
                !String::from_utf8_lossy(&b).contains(needle),
                "unexpected secret in {}",
                p.display()
            );
        }
    }
    walk(dir, needle);
}

#[test]
fn untracked_secret_warns_without_exporting() {
    let t = Tmp::new("untracked-secret");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);
    let token = format!("ghp_{}", "A".repeat(36));
    fs::write(repo.join("config.env"), format!("GITHUB_TOKEN={token}\n")).unwrap();

    let sess = sample_session(&repo, "src/auth.rs", "no-secret");
    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();

    assert!(detail
        .validation
        .warnings
        .iter()
        .any(|w| w.contains("potential secret in untracked file config.env:1")));
    assert!(detail
        .manifest
        .sensitive_files
        .iter()
        .any(|s| s.path == "config.env"));
    assert_eq!(
        detail.validation.status,
        PreflightStatus::PassedWithWarnings
    );
    let pkg = store.join(&detail.manifest.handoff_id);
    assert_dir_lacks(&pkg, &token);
}

#[test]
fn successful_check_runs_reach_context_and_evidence() {
    let t = Tmp::new("check-runs");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let mut sess = sample_session(&repo, "src/auth.rs", "no-secret");
    sess.events.push(Event {
        id: "e4".into(),
        sequence: 4,
        timestamp: None,
        kind: EventKind::ToolResult,
        actor: Actor::Tool,
        content: EventContent::default(),
        tool: Some(ToolInfo {
            name: "bash".into(),
            input: Some(json!({ "command": "cargo test" })),
            output: Some("ok. 3 passed".into()),
        }),
        status: ToolStatus::Succeeded,
        source_ref: EventSourceRef {
            session_id: "ses_demo".into(),
            native_event_id: Some("t3".into()),
        },
        parse_status: ParseStatus::Parsed,
    });
    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();

    assert!(detail.context_md.contains("## Verification Runs"));
    assert!(detail.context_md.contains("cargo test (passed"));
    assert!(detail.evidence.items.iter().any(|i| i
        .claim
        .contains("Verification run passed in session: cargo test")
        && i.classification == Classification::Verified));
}

#[test]
fn validate_warns_when_tracked_tree_drifts_after_creation() {
    let t = Tmp::new("drift");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let sess = sample_session(&repo, "src/auth.rs", "no-secret");
    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();

    // Edit a tracked file after the handoff snapshot: branch/HEAD unchanged,
    // file still exists; only the patch digest can reveal the drift.
    fs::write(repo.join("src/auth.rs"), "pub fn auth() { changed }\n").unwrap();
    let reval = validate_handoff(&store, &detail.manifest.handoff_id, Some(&repo)).unwrap();
    assert!(reval.validation.conflicts.iter().all(|c| !c.critical));
    assert!(reval
        .validation
        .warnings
        .iter()
        .any(|w| w.contains("differ from the handoff snapshot")));
}

#[test]
fn missing_project_root_blocks_create() {
    let t = Tmp::new("missing-root");
    let ghost = t.0.join("ghost");
    let store = t.0.join("store");

    let mut sess = sample_session(&ghost, "src/none.rs", "no-secret");
    sess.events.retain(|e| e.kind == EventKind::UserMessage);
    let detail = create_handoff(&sess, AgentId::Omp, Some(&ghost), &store).unwrap();

    assert_eq!(detail.validation.status, PreflightStatus::Blocked);
    assert!(detail
        .validation
        .checklist
        .iter()
        .any(|c| c.id == "CHK-01" && !c.checked));
}

#[test]
fn user_message_noise_filtered_and_deduped() {
    let t = Tmp::new("user-noise");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let mut sess = sample_session(&repo, "src/auth.rs", "no-secret");
    let user_events: Vec<Event> = ["e1", "e2", "e3"]
        .iter()
        .enumerate()
        .map(|(i, id)| Event {
            id: (*id).into(),
            sequence: i as u64 + 1,
            timestamp: None,
            kind: EventKind::UserMessage,
            actor: Actor::User,
            content: EventContent {
                text: Some(match *id {
                    "e1" => {
                        "<system-reminder>session context refreshed</system-reminder>\nperbaiki bug login di halaman auth"
                    }
                    "e2" => "perbaiki bug login di halaman auth",
                    _ => "[Request interrupted by user]",
                }
                .into()),
                structured: None,
            },
            tool: None,
            status: ToolStatus::Unknown,
            source_ref: EventSourceRef {
                session_id: "ses_demo".into(),
                native_event_id: Some((*id).into()),
            },
            parse_status: ParseStatus::Parsed,
        })
        .collect();
    sess.events = user_events;
    sess.parse_report.total_events = 3;
    sess.parse_report.parsed_events = 3;

    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();

    assert_eq!(
        detail.task_state.objective,
        "perbaiki bug login di halaman auth"
    );
    assert!(!detail.context_md.to_lowercase().contains("system-reminder"));
    assert!(!detail.context_md.contains("[Request interrupted"));
    let section = detail
        .context_md
        .split("## User Requirements\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let bullets = section.lines().filter(|l| l.starts_with("- ")).count();
    assert_eq!(bullets, 1);
}

#[test]
fn validate_blocks_when_git_repository_disappears() {
    let t = Tmp::new("git-gone");
    let repo = t.0.join("repo");
    let store = t.0.join("store");
    fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("src/auth.rs"), "pub fn auth() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "init"]);

    let sess = sample_session(&repo, "src/auth.rs", "no-secret");
    let detail = create_handoff(&sess, AgentId::Omp, Some(&repo), &store).unwrap();
    assert!(detail.manifest.git.is_repository);

    // The whole repository vanishes (`rm -rf .git` or a move): the manifest
    // still records branch + HEAD, so continuation must block instead of
    // silently skipping every git comparison.
    fs::remove_dir_all(repo.join(".git")).unwrap();
    let reval = validate_handoff(&store, &detail.manifest.handoff_id, Some(&repo)).unwrap();
    assert_eq!(reval.validation.status, PreflightStatus::Blocked);
    assert!(reval
        .validation
        .conflicts
        .iter()
        .any(|c| { c.critical && c.description.contains("live workspace no longer has one") }));
    assert!(reval
        .validation
        .checklist
        .iter()
        .any(|c| c.id == "CHK-03" && !c.checked));
}
