//! 结果脱敏。
//!
//! 端侧执行结果会原样上行到服务端、再进前端渲染与模型上下文，因此这里是**最后一道**
//! 拦住密钥的地方：`cat .env`、`git config --list`、`echo $TOKEN` 都可能把凭据带出来。
//! 策略是「宁可多打码」：误伤一段普通文本只会让用户困惑，漏掉一个 token 就是事故。

use serde_json::{Map, Value};

/// 打码后的占位符。固定成三颗星而不做「保留前几位」，
/// 因为部分打码（`sk-abc***`）仍会泄漏可用于爆破的有效前缀。
const MASK: &str = "***";

/// 字段名里出现这些词（大小写不敏感）就整段打码。
const SENSITIVE_KEY_HINTS: [&str; 4] = ["token", "secret", "password", "api_key"];

/// 这些前缀开头的字符串一律视为凭据，无论字段名叫什么。
/// 出处：`hgd_` = harness 设备令牌；其余是常见生态的密钥前缀。
const SENSITIVE_VALUE_PREFIXES: [&str; 3] = ["sk-", "hgd_", "ghp_"];

/// 递归脱敏入口。
pub fn scrub(v: Value) -> Value {
    scrub_value(v, false)
}

/// `force` 为真时，表示该子树处在敏感字段之下，所有字符串一律打码
/// （保留对象/数组结构，避免把 `{"token": {...}}` 直接变成一个字符串让下游解析失败）。
fn scrub_value(v: Value, force: bool) -> Value {
    match v {
        Value::String(s) => {
            if force || is_sensitive_value(&s) {
                Value::String(MASK.to_string())
            } else {
                Value::String(s)
            }
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|it| scrub_value(it, force))
                .collect::<Vec<_>>(),
        ),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, val) in map {
                let child_force = force || is_sensitive_key(&k);
                out.insert(k, scrub_value(val, child_force));
            }
            Value::Object(out)
        }
        // 数字/布尔/null 不可能是凭据本身，原样返回
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_HINTS.iter().any(|h| lower.contains(h))
}

fn is_sensitive_value(s: &str) -> bool {
    let trimmed = s.trim_start();
    if SENSITIVE_VALUE_PREFIXES
        .iter()
        .any(|p| trimmed.starts_with(p))
    {
        return true;
    }
    // "Bearer " 按大小写不敏感比较：HTTP 头里出现 `bearer xxx` 同样必须打码。
    // 用 `get(..7)` 而不是 `trimmed[..7]`：结果字符串可能含中文等多字节字符，
    // 按字节切片会切在字符中间直接 panic（脱敏函数自己崩掉比漏打码更糟）。
    trimmed
        .get(..7)
        .is_some_and(|head| head.eq_ignore_ascii_case("bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scrub_str(s: &str) -> String {
        match scrub(Value::String(s.to_string())) {
            Value::String(out) => out,
            other => panic!("期望字符串，实际 {other:?}"),
        }
    }

    #[test]
    fn masks_sensitive_value_prefixes() {
        assert_eq!(scrub_str("sk-abc123"), MASK);
        assert_eq!(scrub_str("hgd_0123456789"), MASK);
        assert_eq!(scrub_str("ghp_deadbeef"), MASK);
        assert_eq!(scrub_str("Bearer eyJhbGciOi"), MASK);
        // 大小写不敏感的 Bearer
        assert_eq!(scrub_str("bearer eyJhbGciOi"), MASK);
        // 带前导空白的也要抓（日志里常见缩进）
        assert_eq!(scrub_str("   sk-abc123"), MASK);
    }

    #[test]
    fn keeps_normal_text_intact() {
        assert_eq!(scrub_str("hello world"), "hello world");
        assert_eq!(scrub_str("/home/me/work"), "/home/me/work");
        // 只是提到单词，不带密钥前缀 → 不误伤
        assert_eq!(scrub_str("token 字段说明"), "token 字段说明");
        assert_eq!(
            scrub_str("BearerTokenWithoutSpace"),
            "BearerTokenWithoutSpace"
        );
        // 多字节字符不能把脱敏函数自己搞 panic（回归：按字节切 ..7 曾切在中文中间）
        assert_eq!(
            scrub_str("你好世界这是一个很长的中文串"),
            "你好世界这是一个很长的中文串"
        );
        assert_eq!(
            scrub_str("令牌bearer 前缀不在开头"),
            "令牌bearer 前缀不在开头"
        );
    }

    #[test]
    fn masks_by_key_name_case_insensitively() {
        let v = json!({
            "accessToken": "abc",
            "API_KEY": "abc",
            "user_secret": "abc",
            "DbPassword": "abc",
            "name": "harness",
        });
        let out = scrub(v);
        assert_eq!(out["accessToken"], MASK);
        assert_eq!(out["API_KEY"], MASK);
        assert_eq!(out["user_secret"], MASK);
        assert_eq!(out["DbPassword"], MASK);
        assert_eq!(out["name"], "harness");
    }

    #[test]
    fn scrubs_nested_objects_and_arrays() {
        let v = json!({
            "dirs": [
                { "name": "a", "path": "C:\\work\\a" },
                { "name": "sk-leaked", "path": "C:\\work\\b" }
            ],
            "meta": { "token": "whatever", "count": 3 },
        });
        let out = scrub(v);
        assert_eq!(out["dirs"][0]["name"], "a");
        assert_eq!(out["dirs"][1]["name"], MASK);
        assert_eq!(out["dirs"][1]["path"], "C:\\work\\b");
        assert_eq!(out["meta"]["token"], MASK);
        assert_eq!(out["meta"]["count"], 3);
    }

    #[test]
    fn sensitive_key_with_container_preserves_shape() {
        let v = json!({ "api_key": { "value": "abc", "len": 3 } });
        let out = scrub(v);
        // 结构保留，内部字符串打码，数字不动
        assert_eq!(out["api_key"]["value"], MASK);
        assert_eq!(out["api_key"]["len"], 3);
    }

    #[test]
    fn non_string_primitives_pass_through() {
        assert_eq!(scrub(json!(42)), json!(42));
        assert_eq!(scrub(json!(true)), json!(true));
        assert_eq!(scrub(Value::Null), Value::Null);
    }
}
