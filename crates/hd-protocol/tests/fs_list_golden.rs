//! `fs.list` / `fs.list.result` 黄金 fixture 门禁（**本次事故的直接回归锁**）。
//!
//! ## 事故背景（真实发生，不是假想）
//!
//! 服务端 `harness_go` 早已实现 `fs.list` 派发（`internal/device/pathquery.go`），
//! 但桌面端协议层 `MessageType` 里没有这两个变体，`#[serde(other)] Unknown` 兜底后
//! 端侧把它当未知帧**静默丢弃**。后果：web 端每次打开「桌面端空间」目录选择器
//! 都空等服务端的 3 秒硬超时，用户看到的是永久转圈。
//!
//! 因此本文件的第一条断言就是「**解码结果不是 `Unknown`**」—— 它比任何字段断言
//! 都重要：字段断言只能发现「形状漂移」，类型断言才能发现「整条链路不存在」。
//!
//! ## fixture 来源
//!
//! `fixtures/fs_list.json` 与 `fixtures/fs_list_result.json` 是与
//! `harness_go/internal/device/testdata/` 逐字节相同的双仓契约样本
//! （见 `docs/工作区宿主与目录选择对接约定.md` §3.3）。**勿改**。

use hd_protocol::{
    envelope::{Envelope, MessageType},
    payload::{FsDirEntry, FsListPayload, FsListResultPayload},
};

fn parse(raw: &str) -> Envelope {
    serde_json::from_str(raw).expect("Go 产出的帧必须可解析")
}

#[test]
fn fs_list_request_is_not_unknown() {
    let env = parse(include_str!("../fixtures/fs_list.json"));

    // 🔴 本次事故的直接回归锁：绝不能落进 `#[serde(other)] Unknown`
    assert_ne!(
        env.msg_type,
        MessageType::Unknown,
        "fs.list 被解码成 Unknown —— 端侧会静默丢帧，服务端只能等 3 秒超时"
    );
    assert_eq!(env.msg_type, MessageType::FsList);
    assert_eq!(env.msg_type.as_str(), "fs.list");
    assert!(env.msg_type.is_valid());
    // 目录浏览是旁路查询，**不许**进任务链路（否则会凭空产生 tool_event）
    assert!(!env.msg_type.is_task_frame());
    env.validate().expect("已知帧类型应通过校验");

    // 信封 id 是配对的唯一依据（服务端按 env.ID 匹配应答，不读 payload）
    assert_eq!(env.id, "fsq-1704067200000000000-1");

    let p: FsListPayload = env
        .decode::<FsListPayload>()
        .expect("负载解码不应失败")
        .expect("fixture 不应是空负载");
    assert_eq!(p.path, "", "空串 = 未定位，只回 roots");
    assert!(p.with_roots);
}

#[test]
fn fs_list_result_is_not_unknown() {
    let env = parse(include_str!("../fixtures/fs_list_result.json"));

    assert_ne!(
        env.msg_type,
        MessageType::Unknown,
        "fs.list.result 被解码成 Unknown —— web 端永远收不到目录列表"
    );
    assert_eq!(env.msg_type, MessageType::FsListResult);
    assert_eq!(env.msg_type.as_str(), "fs.list.result");
    assert!(env.msg_type.is_valid());
    assert!(!env.msg_type.is_task_frame());

    // 🔴 应答必须逐字回显请求的 id（服务端 `Deliver(env.ID, ...)` 按此配对）
    assert_eq!(
        env.id, "fsq-1704067200000000000-1",
        "应答 id 必须等于请求 id"
    );

    let p: FsListResultPayload = env
        .decode::<FsListResultPayload>()
        .expect("负载解码不应失败")
        .expect("fixture 不应是空负载");
    assert_eq!(p.path, "C:\\Users\\me\\work");
    assert_eq!(p.parent.as_deref(), Some("C:\\Users\\me"));
    assert_eq!(p.separator, "\\", "Windows 分隔符必须逐字保真");
    assert_eq!(
        p.roots,
        vec![
            FsDirEntry {
                name: "work".to_string(),
                path: "C:\\Users\\me\\work".to_string(),
            },
            FsDirEntry {
                name: "tmp".to_string(),
                path: "C:\\Users\\me\\tmp".to_string(),
            },
        ]
    );
    assert_eq!(p.dirs.len(), 2);
    assert_eq!(p.dirs[0].name, "Proj");
    assert_eq!(p.dirs[0].path, "C:\\Users\\me\\work\\Proj");
    assert_eq!(p.dirs[1].name, "Docs");
    assert!(!p.truncated);
    // fixture 是成功应答：失败字段必须为空
    assert!(p.error.is_empty());
    assert!(p.code.is_empty());
}

/// 「编码 → 再解码」往返一致（锁死 `skip_serializing_if` 与 Go `omitempty` 的对齐）。
#[test]
fn fs_list_result_roundtrip_is_stable() {
    let env = parse(include_str!("../fixtures/fs_list_result.json"));
    let p: FsListResultPayload = env.decode().expect("解码").expect("非空负载");

    let re_encoded = serde_json::to_value(&p).expect("序列化");
    let decoded: FsListResultPayload = serde_json::from_value(re_encoded.clone()).expect("再解码");

    assert_eq!(decoded, p, "往返后负载必须逐字段相等");
    // 编码后仍必须是合法帧：类型与信封形状不变
    let rebuilt = Envelope::new(MessageType::FsListResult, env.id.clone(), Some(re_encoded));
    assert_eq!(rebuilt.msg_type, MessageType::FsListResult);
    assert_eq!(rebuilt.id, "fsq-1704067200000000000-1");
}

/// 空负载请求必须能序列化成「只有 path」的最小形状（Go 侧 omitempty 语义）。
#[test]
fn fs_list_request_omits_false_flags() {
    let p = FsListPayload::default();
    let json = serde_json::to_value(&p).expect("序列化");
    assert_eq!(json["path"], "");
    assert!(
        json.get("with_roots").is_none(),
        "false 必须被省略（对齐 Go omitempty），实际 {json}"
    );
}

/// `parent` 的 `null` 必须显式上行（Go 侧 `*string` 无 omitempty）。
#[test]
fn fs_list_result_keeps_null_parent_visible() {
    let p = FsListResultPayload {
        path: "C:\\".to_string(),
        parent: None,
        separator: "\\".to_string(),
        ..Default::default()
    };
    let json = serde_json::to_value(&p).expect("序列化");
    assert!(
        json.get("parent").is_some(),
        "根层级必须显式给 null，缺字段会让前端无法区分「根」与「旧服务端」"
    );
    assert!(json["parent"].is_null());
    // 空 roots / false truncated / 空 error+code 均省略
    assert!(json.get("roots").is_none());
    assert!(json.get("truncated").is_none());
    assert!(json.get("error").is_none());
    assert!(json.get("code").is_none());
}
