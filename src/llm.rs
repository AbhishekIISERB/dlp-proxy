use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: String,
    pub text: String,
    pub is_tool_result: bool,
}

// ponytail: basic OpenAI/Anthropic JSON extraction; upgrade: full streaming AST visitor
pub fn parse_chat_messages(json_str: &str) -> Option<Vec<ChatMessage>> {
    let val: Value = serde_json::from_str(json_str).ok()?;
    let mut messages = Vec::new();

    // Anthropic top-level system prompt
    if let Some(sys) = val.get("system").and_then(|s| s.as_str()) {
        messages.push(ChatMessage {
            role: "system".into(),
            text: sys.to_string(),
            is_tool_result: false,
        });
    }

    let msgs = val.get("messages")?.as_array()?;
    for m in msgs {
        let role = m
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("user")
            .to_string();
        let is_tool_role = role == "tool" || role == "tool_result";

        match m.get("content") {
            Some(Value::String(s)) => {
                messages.push(ChatMessage {
                    role: role.clone(),
                    text: s.clone(),
                    is_tool_result: is_tool_role,
                });
            }
            Some(Value::Array(blocks)) => {
                for b in blocks {
                    let b_type = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    let is_tool_block = is_tool_role || b_type == "tool_result";
                    let text = if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                        t
                    } else if let Some(c) = b.get("content").and_then(|c| c.as_str()) {
                        c
                    } else {
                        continue;
                    };
                    let effective_role = if is_tool_block {
                        "tool".to_string()
                    } else {
                        role.clone()
                    };
                    messages.push(ChatMessage {
                        role: effective_role,
                        text: text.to_string(),
                        is_tool_result: is_tool_block,
                    });
                }
            }
            _ => {}
        }
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages)
    }
}
