//! 黄金 fixture 门禁：防 Go / Rust 协议双写漂移。
//!
//! `fixtures/*.json` **全部由 Go 侧真实序列化产出**（`harness_go/scripts/gen-fixtures.go`
//! 调用 `device.MustEnvelope`），不是手写的。这保证 fixture 永远反映服务端实现，
//! 而不是「我以为的协议」。
//!
//! ## 回归方式（CI 门禁）
//!
//! ```text
//! # 1. 在 harness_go 侧重新生成（服务端改了协议就必须重跑）
//! cd ../harness_go && go run scripts/gen-fixtures.go -out ../harness_desktop/crates/hd-protocol/fixtures
//! # 2. 在 harness_desktop 侧验证
//! cargo test -p hd-protocol
//! ```
//!
//! 若服务端改了结构体却没同步重生成 fixture，本测试仍会通过（fixture 是旧的）；
//! 故 CI 必须先执行生成再 `git diff --exit-code fixtures/` —— 有 diff 说明漏了提交，
//! 直接失败。这一点在 `.github/workflows/ci.yml` 的 `protocol-gate` 中体现。

use hd_protocol::{
    envelope::{Envelope, MessageType},
    error_code,
    payload::{
        ErrorPayload, HelloPayload, LeaseRevokedPayload, PingPayload, PongPayload, SourceTrust,
        TaskDispatchPayload, TaskProgressPayload, TaskResultPayload, WelcomePayload,
    },
};

/// 解析 fixture 并按类型解码负载。
fn load<T: serde::de::DeserializeOwned>(raw: &str, want: MessageType) -> T {
    let env: Envelope = serde_json::from_str(raw).expect("Go 产出的帧必须可解析");
    assert_eq!(env.msg_type, want, "帧类型不符");
    env.validate().expect("已知帧类型应通过校验");
    env.decode::<T>()
        .expect("负载解码不应失败")
        .expect("fixture 不应是空负载")
}

#[test]
fn hello_decodes_from_go_fixture() {
    let p: HelloPayload = load(include_str!("../fixtures/hello.json"), MessageType::Hello);
    assert_eq!(p.name, "我的工作站");
    assert_eq!(p.platform, "windows-amd64");
    assert_eq!(p.app_version, "1.0.0");
    assert_eq!(p.protocol_version, hd_protocol::CURRENT_PROTOCOL_VERSION);
    assert_eq!(p.capabilities.len(), 3);
    // 🔴 能力名必须是 pkg/toolapi 的合法常量词汇，不得自造
    assert_eq!(p.capabilities[0].name, "workspace.read");
    assert_eq!(p.capabilities[1].name, "workspace.list");
    // updated_at 无 omitempty，Go 固定输出 0
    assert_eq!(p.capabilities[0].updated_at, 0);
}

#[test]
fn welcome_decodes_and_carries_heartbeat() {
    let p: WelcomePayload = load(
        include_str!("../fixtures/welcome.json"),
        MessageType::Welcome,
    );
    assert_eq!(p.device_id, "dev_0123456789abcdef");
    assert_eq!(p.heartbeat_s, 15);
    assert_eq!(p.offline_after_s, 45);
    assert_eq!(p.pending, 2);
    assert_eq!(p.lease_epoch, 7);
    // 协议版本必须落在服务端接受集合内
    assert!(hd_protocol::supported_versions().contains(&p.protocol_version));
}

#[test]
fn ping_preserves_opaque_load() {
    let p: PingPayload = load(include_str!("../fixtures/ping.json"), MessageType::Ping);
    let load = p.load.expect("load 应存在");
    assert_eq!(load["cpu"], serde_json::json!(0.42));
    assert_eq!(load["running"], serde_json::json!(1));
    assert_eq!(p.capabilities_hash, "sha256:abc123");
}

#[test]
fn pong_decodes() {
    let p: PongPayload = load(include_str!("../fixtures/pong.json"), MessageType::Pong);
    assert_eq!(p.pending, 0);
    assert_eq!(p.protocol_version, hd_protocol::CURRENT_PROTOCOL_VERSION);
}

#[test]
fn error_frame_code_matches_go_constant() {
    let p: ErrorPayload = load(include_str!("../fixtures/error.json"), MessageType::Error);
    assert_eq!(p.code, error_code::FRAME_PROTOCOL_MISMATCH);
    assert!(p.fatal, "协议不兼容应为 Fatal");
    // 帧级码：重连也无用，必须停止
    assert!(
        error_code::is_terminal(&p.code),
        "device.protocol_mismatch 必须被判为终态（停止重连）"
    );
}

#[test]
fn task_dispatch_uses_tool_event_id_as_idempotency_key() {
    let p: TaskDispatchPayload = load(
        include_str!("../fixtures/task_dispatch.json"),
        MessageType::TaskDispatch,
    );
    assert_eq!(p.tool_event_id, "te_abc123");
    assert_eq!(p.tool_name, "fs.list");
    assert_eq!(p.attempt, 1);
    // args 是各工具自定义形状，端侧原样透传给 executor
    let args = p.args.as_ref().expect("args 应存在");
    assert_eq!(args["max"], serde_json::json!(500));
    assert_eq!(args["path"], serde_json::json!("C:\\Users\\me\\work"));
    // deadline 是毫秒时间戳，必须晚于信封 ts
    assert!(p.deadline > 0);
}

#[test]
fn task_progress_decodes() {
    let p: TaskProgressPayload = load(
        include_str!("../fixtures/task_progress.json"),
        MessageType::TaskProgress,
    );
    assert_eq!(p.tool_event_id, "te_abc123");
    assert!(!p.chunk.is_empty());
}

#[test]
fn task_result_is_always_untrusted() {
    let p: TaskResultPayload = load(
        include_str!("../fixtures/task_result.json"),
        MessageType::TaskResult,
    );
    assert_eq!(p.status, "success");
    // 🔴 不变量 4：端侧结果恒 untrusted。枚举只有这一个变体，
    // 故此处断言的是「JSON 里的字面量必须是 untrusted」。
    assert_eq!(p.source_trust, SourceTrust::Untrusted);
    assert!(p.result.is_some());
}

#[test]
fn lease_revoked_decodes() {
    let p: LeaseRevokedPayload = load(
        include_str!("../fixtures/lease_revoked.json"),
        MessageType::LeaseRevoked,
    );
    assert_eq!(p.session_id, "sess_001");
    assert_eq!(p.epoch, 8);
}

// ============ 反向门禁：Rust 构造的帧必须能被 Go 侧解码 ============

/// Rust 侧序列化任务结果，断言字段名/字面量与 Go 期望完全一致。
///
/// 这条测试防的是「Rust 写错了 json key 名」——正向 fixture 测试只能证明
/// 「Go 的能读进来」，不能证明「Rust 发出去的 Go 能读」。
#[test]
fn task_result_serializes_with_go_field_names() {
    let payload = TaskResultPayload {
        task_id: "te_x".into(),
        run_id: "run_x".into(),
        tool_event_id: "te_x".into(),
        status: "success".into(),
        result: Some(serde_json::json!({"ok": true})),
        error: String::new(),
        source_trust: SourceTrust::Untrusted,
    };
    let v = serde_json::to_value(&payload).expect("序列化不应失败");
    let obj = v.as_object().expect("应为对象");

    // Go 侧读取的 key 名必须全部存在
    for key in [
        "task_id",
        "run_id",
        "tool_event_id",
        "status",
        "result",
        "source_trust",
    ] {
        assert!(obj.contains_key(key), "缺少 Go 侧期望的 key: {key}");
    }
    // error 为空时省略（对齐 Go 的 omitempty）
    assert!(!obj.contains_key("error"), "空 error 应省略");
    // source_trust 字面量必须是 untrusted
    assert_eq!(obj["source_trust"], serde_json::json!("untrusted"));
}

#[test]
fn envelope_roundtrip_preserves_shape() {
    let env = Envelope::new(
        MessageType::Hello,
        "f-1",
        Some(serde_json::json!({"name": "x"})),
    );
    let raw = serde_json::to_string(&env).expect("序列化不应失败");
    let back: Envelope = serde_json::from_str(&raw).expect("反序列化不应失败");
    assert_eq!(back.v, hd_protocol::CURRENT_PROTOCOL_VERSION);
    assert_eq!(back.msg_type, MessageType::Hello);
    assert_eq!(back.id, "f-1");
}

// ============ 向后兼容：未知帧不得导致断连 ============

#[test]
fn unknown_frame_type_is_dropped_not_fatal() {
    // 模拟「服务端新增了 fs.* 帧，而本端壳较旧」的场景
    let raw = r#"{"v":1,"type":"fs.list","id":"x","ts":1,"payload":{"path":"/"}}"#;
    let env: Envelope = serde_json::from_str(raw).expect("未知类型也必须可解析，否则会断连");
    assert_eq!(env.msg_type, MessageType::Unknown);
    assert!(!env.msg_type.is_valid());
    assert!(
        env.validate().is_err(),
        "未知类型应校验失败（供调用方丢弃）"
    );
    // 关键：解析成功而非 panic —— 这是不断连的前提
}

#[test]
fn missing_optional_fields_do_not_break_decoding() {
    // 模拟「旧服务端缺字段」：welcome 缺 pending / lease_epoch
    let raw = r#"{"v":1,"type":"welcome","payload":{"device_id":"d1","server_time":1,"protocol_version":1,"heartbeat_s":15,"offline_after_s":45}}"#;
    let env: Envelope = serde_json::from_str(raw).expect("应可解析");
    let p: WelcomePayload = env.decode().unwrap().unwrap();
    assert_eq!(p.pending, 0);
    assert_eq!(p.lease_epoch, 0);
    assert_eq!(p.heartbeat_s, 15);
}

// ============ 版本协商语义 ============

#[test]
fn version_negotiation_matches_go_semantics() {
    // v=0 = 端侧未声明 → 接受
    assert!(hd_protocol::compatible_version(0).is_ok());
    // 当前版本 → 接受
    assert!(hd_protocol::compatible_version(hd_protocol::CURRENT_PROTOCOL_VERSION).is_ok());
    // 过旧（负数）→ 拒绝
    assert!(hd_protocol::compatible_version(-1).is_err());
    // 超前 → 拒绝（端侧必须提示升级，不得静默降级）
    let too_new = hd_protocol::CURRENT_PROTOCOL_VERSION + 1;
    assert!(hd_protocol::compatible_version(too_new).is_err());
}
