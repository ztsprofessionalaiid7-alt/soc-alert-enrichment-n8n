# SOC Alert Enrichment & Triage: n8n Workflow Code

Importable n8n workflow (n8n Cloud). Copy the JSON below into a file named `soc-alert-enrichment-cloud.json`, then in n8n use **Workflows → Import from File** (or paste it directly onto the canvas with Ctrl+V).

After import, connect your own credentials (nothing secret is stored in this file) and follow the setup steps in the README.

````json
{
  "name": "SOC Alert Enrichment (n8n Cloud)",
  "nodes": [
    {
      "parameters": {
        "content": "## Setup (n8n Cloud)\n1. Credentials (free tiers): VirusTotal and AbuseIPDB (Header Auth), Gemini, Slack, GitHub, Postgres (Supabase)\n2. Create table soc_alerts in Supabase SQL Editor (alert_id is the key)\n3. Slack channel and GitHub repo names: change in nodes\n4. Click Execute workflow: 3 mock alerts (bad IP, safe IP, EICAR test hash) run through the branches",
        "height": 200,
        "width": 440
      },
      "id": "2a0cbc12-aa8b-45a8-a932-b43a9cd94b17",
      "name": "Setup notes",
      "type": "n8n-nodes-base.stickyNote",
      "typeVersion": 1,
      "position": [
        -60,
        -160
      ]
    },
    {
      "parameters": {},
      "id": "66dfbc02-e2aa-4981-9264-54612e169500",
      "name": "When clicking Execute workflow",
      "type": "n8n-nodes-base.manualTrigger",
      "typeVersion": 1,
      "position": [
        0,
        160
      ]
    },
    {
      "parameters": {
        "jsCode": "return [\n  { json: { ioc: '185.220.101.1', source: 'firewall', description: 'Multiple failed SSH logins from external IP' } },\n  { json: { ioc: '8.8.8.8', source: 'dns-logs', description: 'Routine DNS query from internal host' } },\n  { json: { ioc: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', source: 'endpoint', description: 'Unknown file hash found in Downloads folder' } }\n];"
      },
      "id": "d5d44a04-8606-4b91-b84f-4783325ae6f1",
      "name": "Mock Alerts",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        220,
        160
      ]
    },
    {
      "parameters": {
        "jsCode": "const out = [];\nfor (const item of $input.all()) {\n  const d = item.json.body || item.json;\n  const ioc = String(d.ioc || d.indicator || d.ip || d.url || d.domain || d.hash || '').trim();\n  let type = 'domain';\n  if (/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(ioc)) type = 'ip';\n  else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) type = 'hash';\n  else if (/^https?:\\/\\//i.test(ioc)) type = 'url';\n  const base = 'https://www.virustotal.com/api/v3/';\n  let vt_url = base + 'domains/' + ioc;\n  if (type === 'ip') vt_url = base + 'ip_addresses/' + ioc;\n  else if (type === 'hash') vt_url = base + 'files/' + ioc;\n  else if (type === 'url') vt_url = base + 'urls/' + Buffer.from(ioc).toString('base64').replace(/=+$/, '').replace(/\\+/g, '-').replace(/\\//g, '_');\n  out.push({ json: {\n    alert_id: String(d.alert_id || ioc),\n    ioc,\n    ioc_type: type,\n    source: d.source || 'unknown',\n    description: String(d.description || '').slice(0, 1000),\n    vt_url\n  }});\n}\nreturn out;"
      },
      "id": "4879ae14-0a6e-4634-b235-f95d3d315d4b",
      "name": "Extract IOC",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        440,
        160
      ]
    },
    {
      "parameters": {
        "url": "={{ $json.vt_url }}",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "options": {}
      },
      "id": "49472193-17ae-4c4c-8103-395fc3515011",
      "name": "VT Lookup",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [
        660,
        160
      ],
      "credentials": {
        "httpHeaderAuth": {
          "id": "REPLACE_VT",
          "name": "VirusTotal Header Auth"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "url": "https://api.abuseipdb.com/api/v2/check",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "sendQuery": true,
        "queryParameters": {
          "parameters": [
            {
              "name": "ipAddress",
              "value": "={{ $('Extract IOC').item.json.ioc }}"
            },
            {
              "name": "maxAgeInDays",
              "value": "90"
            }
          ]
        },
        "sendHeaders": true,
        "headerParameters": {
          "parameters": [
            {
              "name": "Accept",
              "value": "application/json"
            }
          ]
        },
        "options": {}
      },
      "id": "aa42fa65-c8ee-4792-89dc-4f7af8efa301",
      "name": "AbuseIPDB Lookup",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [
        880,
        160
      ],
      "credentials": {
        "httpHeaderAuth": {
          "id": "REPLACE_ABUSE",
          "name": "AbuseIPDB Header Auth"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "mode": "runOnceForEachItem",
        "jsCode": "const a = $('Extract IOC').item.json;\nlet vt = 'no data';\ntry { vt = JSON.stringify($('VT Lookup').item.json.data.attributes.last_analysis_stats); } catch (e) {}\nlet abuse = 'no data';\ntry {\n  const x = $json.data;\n  abuse = JSON.stringify({ score: x.abuseConfidenceScore, reports: x.totalReports, country: x.countryCode, isp: x.isp });\n} catch (e) {}\nreturn { json: Object.assign({}, a, { vt, abuse }) };"
      },
      "id": "9c181a2d-8dfe-44bf-a1ef-703ccc80156a",
      "name": "Build Context",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        1100,
        160
      ]
    },
    {
      "parameters": {
        "promptType": "define",
        "text": "=You are a SOC analyst. Assess this security alert.\nIOC: {{ $json.ioc }} ({{ $json.ioc_type }})\nSource: {{ $json.source }}\nDescription: {{ $json.description }}\nVirusTotal stats: {{ $json.vt }}\nAbuseIPDB: {{ $json.abuse }}\n\nGive severity (low, medium or high), a score 0-100, a one-sentence summary and one recommended action. high = confirmed malicious or strong reputation hits. medium = suspicious. low = benign or no evidence.",
        "hasOutputParser": true
      },
      "id": "b3e83728-6388-4e9d-a51f-a6b4151510a1",
      "name": "Analyze Alert",
      "type": "@n8n/n8n-nodes-langchain.chainLlm",
      "typeVersion": 1.5,
      "position": [
        1320,
        160
      ],
      "retryOnFail": true,
      "maxTries": 3,
      "waitBetweenTries": 5000
    },
    {
      "parameters": {
        "modelName": "models/gemini-2.5-flash",
        "options": {}
      },
      "id": "85804b39-27fc-40a7-9103-5f1ba3ed85e7",
      "name": "Google Gemini Chat Model",
      "type": "@n8n/n8n-nodes-langchain.lmChatGoogleGemini",
      "typeVersion": 1,
      "position": [
        1300,
        400
      ],
      "credentials": {
        "googlePalmApi": {
          "id": "REPLACE_GEMINI",
          "name": "Google Gemini(PaLM) Api account"
        }
      }
    },
    {
      "parameters": {
        "schemaType": "manual",
        "inputSchema": "{\"type\": \"object\", \"properties\": {\"severity\": {\"type\": \"string\", \"enum\": [\"low\", \"medium\", \"high\"]}, \"score\": {\"type\": \"number\"}, \"summary\": {\"type\": \"string\"}, \"action\": {\"type\": \"string\"}}, \"required\": [\"severity\", \"summary\"]}"
      },
      "id": "490b6fae-9afc-46fd-ba80-75ea60fe23c2",
      "name": "Structured Output Parser",
      "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
      "typeVersion": 1.2,
      "position": [
        1500,
        400
      ]
    },
    {
      "parameters": {
        "mode": "runOnceForEachItem",
        "jsCode": "const ctx = $('Build Context').item.json;\nlet r = $json.output;\nif (typeof r === 'string') {\n  try { const m = r.match(/\\{[\\s\\S]*\\}/); r = m ? JSON.parse(m[0]) : {}; } catch (e) { r = {}; }\n}\nr = r || {};\nconst sev = String(r.severity || 'medium').toLowerCase();\nreturn { json: {\n  alert_id: ctx.alert_id,\n  ioc: ctx.ioc,\n  ioc_type: ctx.ioc_type,\n  source: ctx.source,\n  vt: ctx.vt,\n  abuse: ctx.abuse,\n  severity: ['low', 'medium', 'high'].includes(sev) ? sev : 'medium',\n  score: Number(r.score) || 50,\n  summary: String(r.summary || 'AI output could not be parsed').slice(0, 500),\n  action: String(r.action || 'Review manually').slice(0, 300)\n}};"
      },
      "id": "cf2afb6a-c5a8-4889-bceb-117f0ffed0ca",
      "name": "Parse Result",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        1700,
        160
      ]
    },
    {
      "parameters": {
        "rules": {
          "values": [
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "b656a849-4d49-48d3-8e22-3888af26e73f",
                    "leftValue": "={{ $json.severity }}",
                    "rightValue": "low",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "low"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "4c212a90-26d3-4af2-a82c-0aadf06900e6",
                    "leftValue": "={{ $json.severity }}",
                    "rightValue": "medium",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "medium"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "942982b0-2627-42d2-8191-59930d5b65ff",
                    "leftValue": "={{ $json.severity }}",
                    "rightValue": "high",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "high"
            }
          ]
        },
        "options": {}
      },
      "id": "637c8e91-6120-42c0-9043-1bd3f9ebe00a",
      "name": "Switch",
      "type": "n8n-nodes-base.switch",
      "typeVersion": 3,
      "position": [
        1920,
        160
      ]
    },
    {
      "parameters": {
        "select": "channel",
        "channelId": {
          "__rl": true,
          "value": "soc-alerts",
          "mode": "name"
        },
        "text": ":rotating_light: *{{ $json.severity.toUpperCase() }} alert* ({{ $json.score }}/100)\nIOC: `{{ $json.ioc }}` ({{ $json.ioc_type }})\nSource: {{ $json.source }}\nSummary: {{ $json.summary }}\nAction: {{ $json.action }}",
        "otherOptions": {}
      },
      "id": "6c7b2c44-a497-4c23-a52b-19aff4b80763",
      "name": "Slack Alert",
      "type": "n8n-nodes-base.slack",
      "typeVersion": 2.3,
      "position": [
        2200,
        240
      ],
      "credentials": {
        "slackApi": {
          "id": "REPLACE_SLACK",
          "name": "Slack account"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "authentication": "accessToken",
        "resource": "issue",
        "operation": "create",
        "owner": {
          "__rl": true,
          "value": "ztsprofessionalaiid7-alt",
          "mode": "name"
        },
        "repository": {
          "__rl": true,
          "value": "soc-alerts",
          "mode": "name"
        },
        "title": "=[{{ $json.severity.toUpperCase() }}] {{ $json.ioc }} ({{ $json.ioc_type }})",
        "body": "=**Summary:** {{ $json.summary }}\n\n**Action:** {{ $json.action }}\n\n**Source:** {{ $json.source }}\n\n**VirusTotal:** {{ $json.vt }}\n\n**AbuseIPDB:** {{ $json.abuse }}",
        "labels": [
          {
            "label": "high-severity"
          }
        ],
        "assignees": []
      },
      "id": "3fdf7603-1756-4b7c-9c7f-9bffc51b8d1a",
      "name": "Create GitHub Issue",
      "type": "n8n-nodes-base.github",
      "typeVersion": 1,
      "position": [
        2440,
        340
      ],
      "credentials": {
        "githubApi": {
          "id": "REPLACE_GITHUB",
          "name": "GitHub account"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "operation": "upsert",
        "schema": {
          "__rl": true,
          "value": "public",
          "mode": "list",
          "cachedResultName": "public"
        },
        "table": {
          "__rl": true,
          "value": "soc_alerts",
          "mode": "name"
        },
        "columns": {
          "mappingMode": "defineBelow",
          "value": {
            "alert_id": "={{ $json.alert_id }}",
            "ioc": "={{ $json.ioc }}",
            "ioc_type": "={{ $json.ioc_type }}",
            "source": "={{ $json.source }}",
            "severity": "={{ $json.severity }}",
            "score": "={{ $json.score }}",
            "summary": "={{ $json.summary }}",
            "action": "={{ $json.action }}"
          },
          "matchingColumns": [
            "alert_id"
          ],
          "schema": [
            {
              "id": "alert_id",
              "displayName": "alert_id",
              "required": false,
              "defaultMatch": true,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "ioc",
              "displayName": "ioc",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "ioc_type",
              "displayName": "ioc_type",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "source",
              "displayName": "source",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "severity",
              "displayName": "severity",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "score",
              "displayName": "score",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "number",
              "canBeUsedToMatch": true
            },
            {
              "id": "summary",
              "displayName": "summary",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "action",
              "displayName": "action",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            }
          ]
        },
        "options": {}
      },
      "id": "432796e6-ce3e-47b7-aef9-5e4b1cbf9133",
      "name": "Upsert Alert",
      "type": "n8n-nodes-base.postgres",
      "typeVersion": 2.5,
      "position": [
        2200,
        40
      ],
      "credentials": {
        "postgres": {
          "id": "REPLACE_PG",
          "name": "Postgres account"
        }
      }
    }
  ],
  "connections": {
    "When clicking Execute workflow": {
      "main": [
        [
          {
            "node": "Mock Alerts",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Mock Alerts": {
      "main": [
        [
          {
            "node": "Extract IOC",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Extract IOC": {
      "main": [
        [
          {
            "node": "VT Lookup",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "VT Lookup": {
      "main": [
        [
          {
            "node": "AbuseIPDB Lookup",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "AbuseIPDB Lookup": {
      "main": [
        [
          {
            "node": "Build Context",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Build Context": {
      "main": [
        [
          {
            "node": "Analyze Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Google Gemini Chat Model": {
      "ai_languageModel": [
        [
          {
            "node": "Analyze Alert",
            "type": "ai_languageModel",
            "index": 0
          }
        ]
      ]
    },
    "Structured Output Parser": {
      "ai_outputParser": [
        [
          {
            "node": "Analyze Alert",
            "type": "ai_outputParser",
            "index": 0
          }
        ]
      ]
    },
    "Analyze Alert": {
      "main": [
        [
          {
            "node": "Parse Result",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Parse Result": {
      "main": [
        [
          {
            "node": "Switch",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Switch": {
      "main": [
        [
          {
            "node": "Upsert Alert",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Upsert Alert",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Create GitHub Issue",
            "type": "main",
            "index": 0
          },
          {
            "node": "Upsert Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "pinData": {},
  "active": false,
  "settings": {
    "executionOrder": "v1"
  },
  "tags": []
}
````
