// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::protocol::*;
use super::resources::McpResources;
use super::tools::McpTools;
use anyhow::Result;
use log::{debug, error, info};
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Clone, Default)]
pub struct McpServerConfig {
    pub enable_logging: bool,
}

pub struct McpServer {
    config: McpServerConfig,
    initialized: bool,
    resources: McpResources,
    tools: McpTools,
}

impl McpServer {
    pub fn new(config: McpServerConfig) -> Self {
        Self {
            config,
            initialized: false,
            resources: McpResources::new(),
            tools: McpTools::new(),
        }
    }

    pub fn setup_chaos_resources(self) -> Self {
        self.resources.setup_chaos_resources();
        self
    }

    pub fn run_blocking(&mut self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let reader = BufReader::new(stdin.lock());

        info!("MCP server started, waiting for requests...");

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", line);
            let response = self.handle_request(&line);
            let response_json = serde_json::to_string(&response)? + "\n";
            debug!("Sending: {}", response_json.trim());
            stdout.write_all(response_json.as_bytes())?;
            stdout.flush()?;
        }

        Ok(())
    }

    fn handle_request(&mut self, line: &str) -> JsonRpcResponse {
        // Parse request
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse request: {}", e);
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError::parse_error()),
                    id: None,
                };
            }
        };

        // Dispatch to method handler
        let result = self.dispatch_method(&request);

        match result {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(result),
                error: None,
                id: request.id.clone(),
            },
            Err(e) => {
                error!("Error handling request: {}", e);
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError::internal_error(&e.to_string())),
                    id: request.id.clone(),
                }
            }
        }
    }

    fn dispatch_method(&mut self, request: &JsonRpcRequest) -> Result<serde_json::Value> {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "initialized" => self.handle_initialized(),
            "resources/list" => self.handle_resources_list(),
            "resources/read" => self.handle_resources_read(request),
            "tools/list" => self.handle_tools_list(),
            "tools/call" => self.handle_tools_call(request),
            "ping" => Ok(serde_json::json!({})),
            method => {
                error!("Unknown method: {}", method);
                Err(anyhow::anyhow!("Method not found: {}", method))
            }
        }
    }

    fn handle_initialize(&mut self, request: &JsonRpcRequest) -> Result<serde_json::Value> {
        let _params: McpInitializeParams = if let Some(ref params) = request.params {
            serde_json::from_value(params.clone())?
        } else {
            return Err(anyhow::anyhow!("Missing initialize params"));
        };

        self.initialized = true;

        let result = McpInitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: McpServerCapabilities {
                experimental: None,
                logging: if self.config.enable_logging {
                    Some(serde_json::json!({}))
                } else {
                    None
                },
                prompts: None,
                resources: Some(McpResourcesCapability {
                    subscribe: Some(false),
                    list_changed: Some(false),
                }),
                tools: Some(McpToolsCapability {
                    list_changed: Some(false),
                }),
            },
            server_info: McpImplementationInfo {
                name: "scx_chaos".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        Ok(serde_json::to_value(result)?)
    }

    fn handle_initialized(&mut self) -> Result<serde_json::Value> {
        info!("Client acknowledged initialization");
        Ok(serde_json::json!({}))
    }

    fn handle_resources_list(&self) -> Result<serde_json::Value> {
        let resources = self.resources.list();
        Ok(serde_json::json!({
            "resources": resources
        }))
    }

    fn handle_resources_read(&self, request: &JsonRpcRequest) -> Result<serde_json::Value> {
        let params = request
            .params
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing params"))?;

        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing uri parameter"))?;

        let result = self.resources.read(uri)?;
        Ok(serde_json::to_value(result)?)
    }

    fn handle_tools_list(&self) -> Result<serde_json::Value> {
        let tools = self.tools.list();
        Ok(serde_json::json!({
            "tools": tools
        }))
    }

    fn handle_tools_call(&mut self, request: &JsonRpcRequest) -> Result<serde_json::Value> {
        let params = request
            .params
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing params"))?;

        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing name parameter"))?;

        let arguments = params
            .get("arguments")
            .ok_or_else(|| anyhow::anyhow!("Missing arguments parameter"))?;

        let result = self.tools.call(name, arguments)?;

        Ok(serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string_pretty(&result)?
                }
            ]
        }))
    }
}
