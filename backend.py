"""
MCP Attack/Defend Lab - Complete Backend
Integrated with all vulnerability servers and challenge system
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import subprocess
import os
import json
import sqlite3
import time
from datetime import datetime
import requests
from fastmcp import FastMCP
import asyncio
import traceback
import pickle
import yaml
import base64
import xml.etree.ElementTree as ET
import jwt
import hashlib
from jinja2 import Template
import threading

# ============================================================================
# VULNERABILITY FUNCTION IMPLEMENTATIONS
# ============================================================================

# 1. GIT OPERATIONS
def git_clone_func(repo_url: str) -> dict:
    try:
        cmd = f"git clone {repo_url} /tmp/repo_{int(time.time())} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {"success": result.returncode == 0, "output": result.stdout, "error": result.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def git_diff_func(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    try:
        cmd = f"cd {repo_path} && git diff {commit_range} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def git_log_func(repo_path: str, options: str = "--oneline") -> dict:
    try:
        cmd = f"cd {repo_path} && git log {options} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 2. FILE OPERATIONS
def read_file_func(filepath: str) -> dict:
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(50000)
            return {"success": True, "content": content, "path": os.path.abspath(filepath), "size": len(content)}
        return {"success": False, "error": "File not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def write_file_func(filepath: str, content: str) -> dict:
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        return {"success": True, "path": os.path.abspath(filepath), "bytes_written": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def list_directory_func(directory: str) -> dict:
    try:
        if os.path.exists(directory) and os.path.isdir(directory):
            files = os.listdir(directory)
            return {"success": True, "files": files, "count": len(files), "path": os.path.abspath(directory)}
        return {"success": False, "error": "Directory not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fetch_url_func(url: str) -> dict:
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return {"success": True, "status_code": response.status_code, "content": response.text[:10000], "headers": dict(response.headers)}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 3. AWS OPERATIONS
def list_s3_buckets_func(profile: str = "default", filters: str = "") -> dict:
    try:
        cmd = f"aws s3 ls --profile {profile} {filters} 2>&1 || echo 'AWS CLI failed'" if filters else f"aws s3 ls --profile {profile} 2>&1 || echo 'No credentials'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def describe_instances_func(region: str = "us-east-1", instance_filters: str = "") -> dict:
    try:
        cmd = f"aws ec2 describe-instances --region {region} {instance_filters} 2>&1 || echo 'No instances'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_ec2_metadata_func(metadata_path: str = "instance-id") -> dict:
    try:
        cmd = f"curl -s http://169.254.169.254/latest/meta-data/{metadata_path} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "metadata": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 4. PROMPT OPERATIONS
def process_document_func(document_content: str, instruction: str = "summarize") -> dict:
    injection_keywords = ["SYSTEM", "OVERRIDE", "IGNORE", "NEW INSTRUCTION", "REVEAL", "OUTPUT", "EXECUTE", "ADMIN MODE"]
    content_upper = document_content.upper()
    for keyword in injection_keywords:
        if keyword in content_upper:
            return {"success": True, "result": f"INJECTED_BEHAVIOR: Keyword '{keyword}' triggered system override", "injected": True, "original_instruction": instruction}
    return {"success": True, "result": f"Processed {len(document_content)} chars with instruction: {instruction}", "injected": False}

def analyze_email_func(email_body: str, sender: str = "unknown") -> dict:
    if "EXFILTRATE:" in email_body:
        leaked_data = email_body.split("EXFILTRATE:")[1].split("\n")[0].strip()
        return {"success": True, "analysis": "Email analyzed", "LEAKED_DATA": leaked_data, "sender": sender}
    if "<EXECUTE>" in email_body and "</EXECUTE>" in email_body:
        command = email_body.split("<EXECUTE>")[1].split("</EXECUTE>")[0]
        return {"success": True, "analysis": "Email analyzed", "EXECUTED_COMMAND": command, "sender": sender}
    return {"success": True, "analysis": f"Email from {sender} analyzed ({len(email_body)} chars)", "sender": sender}

def parse_structured_data_func(data: str, format_type: str = "json") -> dict:
    if "{{INJECT}}" in data and "{{/INJECT}}" in data:
        injected = data.split("{{INJECT}}")[1].split("{{/INJECT}}")[0]
        return {"success": True, "parsed": f"INJECTION_EXECUTED: {injected}", "format": format_type}
    return {"success": True, "parsed": f"Parsed {len(data)} bytes as {format_type}", "format": format_type}

# 5. DATABASE OPERATIONS
DB_PATH = "mcp_lab_vulnerable.db"

def init_vulnerable_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, api_key TEXT, secret_data TEXT)""")
    cursor.execute("""INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin_pass_2025', 'administrator', 'sk_live_admin_xyz123', 'FLAG{admin_secret_data}'), (2, 'user', 'user_pass_456', 'user', 'sk_live_user_abc456', 'user_data'), (3, 'service', 'service_key_789', 'service', 'sk_live_service_def789', 'service_config')""")
    conn.commit()
    conn.close()

init_vulnerable_db()

def query_users_func(username: str) -> dict:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        formatted_results = [{"id": row[0], "username": row[1], "password": row[2], "role": row[3], "api_key": row[4], "secret_data": row[5]} for row in results]
        return {"success": True, "query": query, "results": formatted_results, "row_count": len(results)}
    except Exception as e:
        query = locals().get('query', 'N/A')
        return {"success": False, "error": str(e), "query": query}

def search_users_func(search_term: str) -> dict:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT username, role FROM users WHERE username LIKE '%{search_term}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return {"success": True, "results": results, "count": len(results)}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 6. DESERIALIZATION
def deserialize_object_func(serialized_data: str, format_type: str = "pickle") -> dict:
    try:
        if format_type == "pickle":
            decoded = base64.b64decode(serialized_data)
            obj = pickle.loads(decoded)
            return {"success": True, "deserialized": str(obj), "type": str(type(obj))}
        elif format_type == "yaml":
            obj = yaml.load(serialized_data, Loader=yaml.Loader)
            return {"success": True, "deserialized": str(obj)}
        return {"success": False, "error": "Unsupported format"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def process_config_func(config_data: str) -> dict:
    try:
        config = yaml.load(config_data, Loader=yaml.Loader)
        return {"success": True, "config": config, "keys": list(config.keys()) if isinstance(config, dict) else None}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 7. XML/XXE
def parse_xml_func(xml_content: str) -> dict:
    try:
        root = ET.fromstring(xml_content)
        data = {child.tag: child.text for child in root}
        return {"success": True, "parsed": data, "root_tag": root.tag}
    except Exception as e:
        return {"success": False, "error": str(e)}

def transform_xml_func(xml_content: str, xslt_path: str = "") -> dict:
    try:
        root = ET.fromstring(xml_content)
        return {"success": True, "transformed": ET.tostring(root, encoding='unicode')}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 8. AUTHENTICATION
SECRET_KEY = "weak_secret_123"

def verify_token_func(token: str) -> dict:
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
        return {"success": True, "valid": True, "user": decoded.get("user"), "role": decoded.get("role"), "claims": decoded}
    except Exception as e:
        return {"success": False, "error": str(e)}

def check_permissions_func(user_id: str, resource: str, action: str) -> dict:
    try:
        if user_id:
            return {"success": True, "allowed": True, "user_id": user_id, "resource": resource, "action": action, "message": f"User {user_id} granted access to {resource}"}
        return {"success": False, "error": "No user_id"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def reset_password_func(email: str, reset_token: str = "") -> dict:
    try:
        if not reset_token:
            token = hashlib.md5(email.encode()).hexdigest()
            return {"success": True, "message": "Reset token generated", "token": token, "email": email}
        expected_token = hashlib.md5(email.encode()).hexdigest()
        if reset_token == expected_token:
            return {"success": True, "message": "Password reset successful", "new_password": "TempPass123!", "email": email}
        return {"success": False, "error": "Invalid token"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 9. TEMPLATE INJECTION
def render_template_func(template_string: str, context: dict = None) -> dict:
    try:
        if context is None:
            context = {}
        template = Template(template_string)
        result = template.render(**context)
        return {"success": True, "rendered": result, "template": template_string}
    except Exception as e:
        return {"success": False, "error": str(e)}

def generate_report_func(name: str, report_template: str = "Hello {name}") -> dict:
    try:
        report = report_template.format(name=name)
        return {"success": True, "report": report, "template": report_template}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 10. RACE CONDITIONS
transfer_balance = {"account1": 1000, "account2": 500}

def transfer_funds_func(from_account: str, to_account: str, amount: float) -> dict:
    try:
        if transfer_balance.get(from_account, 0) >= amount:
            time.sleep(0.1)
            transfer_balance[from_account] -= amount
            transfer_balance[to_account] += amount
            return {"success": True, "from_account": from_account, "to_account": to_account, "amount": amount, "new_balance": transfer_balance[from_account]}
        return {"success": False, "error": "Insufficient funds"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def apply_discount_func(cart_total: float, discount_code: str) -> dict:
    try:
        discounts = {"SAVE10": 0.10, "SAVE20": 0.20, "ADMIN50": 0.50}
        discount_amount = cart_total * discounts.get(discount_code, 0)
        final_price = cart_total - discount_amount
        return {"success": True, "original_price": cart_total, "discount_code": discount_code, "discount_amount": discount_amount, "final_price": final_price}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ============================================================================
# MCP SERVERS
# ============================================================================

git_mcp = FastMCP("VulnerableGitServer")
@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    return git_clone_func(repo_url)
@git_mcp.tool()
def git_diff(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    return git_diff_func(repo_path, commit_range)
@git_mcp.tool()
def git_log(repo_path: str, options: str = "--oneline") -> dict:
    return git_log_func(repo_path, options)

file_mcp = FastMCP("VulnerableFileServer")
@file_mcp.tool()
def read_file(filepath: str) -> dict:
    return read_file_func(filepath)
@file_mcp.tool()
def write_file(filepath: str, content: str) -> dict:
    return write_file_func(filepath, content)
@file_mcp.tool()
def list_directory(directory: str) -> dict:
    return list_directory_func(directory)
@file_mcp.tool()
def fetch_url(url: str) -> dict:
    return fetch_url_func(url)

aws_mcp = FastMCP("VulnerableAWSServer")
@aws_mcp.tool()
def list_s3_buckets(profile: str = "default", filters: str = "") -> dict:
    return list_s3_buckets_func(profile, filters)
@aws_mcp.tool()
def describe_instances(region: str = "us-east-1", instance_filters: str = "") -> dict:
    return describe_instances_func(region, instance_filters)
@aws_mcp.tool()
def get_ec2_metadata(metadata_path: str = "instance-id") -> dict:
    return get_ec2_metadata_func(metadata_path)

prompt_mcp = FastMCP("VulnerablePromptServer")
@prompt_mcp.tool()
def process_document(document_content: str, instruction: str = "summarize") -> dict:
    return process_document_func(document_content, instruction)
@prompt_mcp.tool()
def analyze_email(email_body: str, sender: str = "unknown") -> dict:
    return analyze_email_func(email_body, sender)
@prompt_mcp.tool()
def parse_structured_data(data: str, format_type: str = "json") -> dict:
    return parse_structured_data_func(data, format_type)

db_mcp = FastMCP("VulnerableDBServer")
@db_mcp.tool()
def query_users(username: str) -> dict:
    return query_users_func(username)
@db_mcp.tool()
def search_users(search_term: str) -> dict:
    return search_users_func(search_term)

deserialization_mcp = FastMCP("VulnerableDeserializationServer")
@deserialization_mcp.tool()
def deserialize_object(serialized_data: str, format_type: str = "pickle") -> dict:
    return deserialize_object_func(serialized_data, format_type)
@deserialization_mcp.tool()
def process_config(config_data: str) -> dict:
    return process_config_func(config_data)

xml_mcp = FastMCP("VulnerableXMLServer")
@xml_mcp.tool()
def parse_xml(xml_content: str) -> dict:
    return parse_xml_func(xml_content)
@xml_mcp.tool()
def transform_xml(xml_content: str, xslt_path: str = "") -> dict:
    return transform_xml_func(xml_content, xslt_path)

auth_mcp = FastMCP("VulnerableAuthServer")
@auth_mcp.tool()
def verify_token(token: str) -> dict:
    return verify_token_func(token)
@auth_mcp.tool()
def check_permissions(user_id: str, resource: str, action: str) -> dict:
    return check_permissions_func(user_id, resource, action)
@auth_mcp.tool()
def reset_password(email: str, reset_token: str = "") -> dict:
    return reset_password_func(email, reset_token)

template_mcp = FastMCP("VulnerableTemplateServer")
@template_mcp.tool()
def render_template(template_string: str, context: dict = None) -> dict:
    return render_template_func(template_string, context)
@template_mcp.tool()
def generate_report(name: str, report_template: str = "Hello {name}") -> dict:
    return generate_report_func(name, report_template)

logic_mcp = FastMCP("VulnerableLogicServer")
@logic_mcp.tool()
def transfer_funds(from_account: str, to_account: str, amount: float) -> dict:
    return transfer_funds_func(from_account, to_account, amount)
@logic_mcp.tool()
def apply_discount(cart_total: float, discount_code: str) -> dict:
    return apply_discount_func(cart_total, discount_code)

# ============================================================================
# REGISTRIES
# ============================================================================

MCP_TOOL_REGISTRY = {
    "git": {"git_clone": git_clone_func, "git_diff": git_diff_func, "git_log": git_log_func},
    "file": {"read_file": read_file_func, "write_file": write_file_func, "list_directory": list_directory_func, "fetch_url": fetch_url_func},
    "aws": {"list_s3_buckets": list_s3_buckets_func, "describe_instances": describe_instances_func, "get_ec2_metadata": get_ec2_metadata_func},
    "prompt": {"process_document": process_document_func, "analyze_email": analyze_email_func, "parse_structured_data": parse_structured_data_func},
    "db": {"query_users": query_users_func, "search_users": search_users_func},
    "deserialization": {"deserialize_object": deserialize_object_func, "process_config": process_config_func},
    "xml": {"parse_xml": parse_xml_func, "transform_xml": transform_xml_func},
    "auth": {"verify_token": verify_token_func, "check_permissions": check_permissions_func, "reset_password": reset_password_func},
    "template": {"render_template": render_template_func, "generate_report": generate_report_func},
    "logic": {"transfer_funds": transfer_funds_func, "apply_discount": apply_discount_func}
}

MCP_SERVERS = {
    "git": git_mcp, "file": file_mcp, "aws": aws_mcp, "prompt": prompt_mcp, "db": db_mcp,
    "deserialization": deserialization_mcp, "xml": xml_mcp, "auth": auth_mcp, "template": template_mcp, "logic": logic_mcp
}

async def call_mcp_tool(server_id: str, tool_name: str, parameters: dict) -> dict:
    try:
        server_tools = MCP_TOOL_REGISTRY.get(server_id)
        if not server_tools:
            return {"success": False, "error": f"MCP server '{server_id}' not found"}
        tool_func = server_tools.get(tool_name)
        if not tool_func:
            return {"success": False, "error": f"Tool '{tool_name}' not found", "available_tools": list(server_tools.keys())}
        result = tool_func(**parameters)
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class LabDatabase:
    def __init__(self):
        self.db_path = "mcp_lab_tracking.db"
        self._init()
    
    def _init(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS students (student_id TEXT PRIMARY KEY, total_attacks INTEGER DEFAULT 0, successful_attacks INTEGER DEFAULT 0, total_score INTEGER DEFAULT 0, last_activity TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS attack_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, student_id TEXT, mcp_server TEXT, tool_name TEXT, parameters TEXT, exploited BOOLEAN, output TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, title TEXT, description TEXT, server TEXT, tool TEXT, difficulty_level TEXT, points INTEGER, flag TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS challenge_progress (student_id TEXT, challenge_id TEXT, completed BOOLEAN DEFAULT 0, attempts INTEGER DEFAULT 0, completion_time TEXT, PRIMARY KEY (student_id, challenge_id))""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS defense_submissions (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, student_id TEXT, mcp_server TEXT, code TEXT, verified BOOLEAN DEFAULT 0)""")
        conn.commit()
        conn.close()
        self._init_challenges()
    
    def _init_challenges(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        challenges = [
            ("sql_basic", "SQL Injection 101", "Retrieve admin user data from the database", "db", "query_users", "beginner", 100, "FLAG{sql_injection_basics}"),
            ("cmd_whoami", "Command Injection: Identity", "Execute 'whoami' command", "git", "git_clone", "beginner", 100, "FLAG{command_injection_whoami}"),
            ("path_etc_passwd", "Path Traversal: System Files", "Read /etc/passwd", "file", "read_file", "beginner", 100, "FLAG{path_traversal_passwd}"),
            ("ssrf_metadata", "SSRF: Cloud Metadata", "Access EC2 metadata service", "file", "fetch_url", "intermediate", 200, "FLAG{ssrf_metadata_access}"),
            ("prompt_inject", "Prompt Injection", "Trigger system override", "prompt", "process_document", "intermediate", 150, "FLAG{prompt_injection_success}"),
        ]
        for c in challenges:
            cursor.execute("INSERT OR IGNORE INTO challenges VALUES (?, ?, ?, ?, ?, ?, ?, ?)", c)
        conn.commit()
        conn.close()
    
    def log_attack(self, student_id: str, mcp_server: str, tool: str, params: str, exploited: bool, output: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO attack_log (timestamp, student_id, mcp_server, tool_name, parameters, exploited, output) VALUES (?, ?, ?, ?, ?, ?, ?)", (datetime.now().isoformat(), student_id, mcp_server, tool, params, exploited, output))
        cursor.execute("INSERT INTO students (student_id, total_attacks, successful_attacks, total_score, last_activity) VALUES (?, 1, ?, ?, ?) ON CONFLICT(student_id) DO UPDATE SET total_attacks = total_attacks + 1, successful_attacks = successful_attacks + ?, total_score = total_score + ?, last_activity = ?", (student_id, 1 if exploited else 0, 10 if exploited else 0, datetime.now().isoformat(), 1 if exploited else 0, 10 if exploited else 0, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def get_student_stats(self, student_id: str) -> dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM students WHERE student_id = ?", (student_id,))
        row = cursor.fetchone()
        result = dict(row) if row else {"student_id": student_id, "total_attacks": 0, "successful_attacks": 0, "total_score": 0}
        conn.close()
        return result
    
    def get_challenges(self, student_id: str) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""SELECT c.*, COALESCE(cp.completed, 0) as completed, COALESCE(cp.attempts, 0) as attempts FROM challenges c LEFT JOIN challenge_progress cp ON c.id = cp.challenge_id AND cp.student_id = ? ORDER BY c.difficulty_level, c.points""", (student_id,))
        challenges = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return challenges
    
    def get_leaderboard(self, limit: int = 50) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT student_id, total_score, successful_attacks, total_attacks, ROUND(CAST(successful_attacks AS FLOAT) / NULLIF(total_attacks, 0) * 100, 1) as success_rate FROM students ORDER BY total_score DESC, successful_attacks DESC LIMIT ?", (limit,))
        leaderboard = [{"student_id": row[0], "total_score": row[1], "successful_attacks": row[2], "total_attacks": row[3], "success_rate": row[4] or 0} for row in cursor.fetchall()]
        conn.close()
        return leaderboard

lab_db = LabDatabase()

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(title="MCP Attack/Defend Lab", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class AttackRequest(BaseModel):
    student_id: str
    mcp_server: str
    tool: str
    parameters: Dict[str, Any]

class DefenseSubmission(BaseModel):
    student_id: str
    mcp_server: str
    patched_code: str

@app.post("/api/attack")
async def execute_attack(req: AttackRequest):
    try:
        result = await call_mcp_tool(req.mcp_server, req.tool, req.parameters)
        result_str = json.dumps(result)
        exploit_indicators = ["root:", "uid=", "gid=", "/etc/passwd", "admin_pass", "INJECTED", "LEAKED", "EXECUTED", "FLAG{", "sk_live_", "Windows", "Volume in drive", "secret_data"]
        exploited = any(indicator in result_str for indicator in exploit_indicators)
        
        if req.mcp_server == "db" and result.get("success"):
            if "results" in result and len(result.get("results", [])) > 1:
                exploited = True
            if "query" in result and ("admin" in result_str or "service" in result_str):
                exploited = True
        
        if req.mcp_server in ["git", "aws"]:
            if any(x in result_str for x in ["uid=", "root:", "bin/bash", "Windows"]):
                exploited = True
        
        if req.mcp_server == "file" and req.tool == "read_file":
            if any(x in result_str for x in ["root:x:", "passwd", "shadow", "hosts"]):
                exploited = True
        
        lab_db.log_attack(req.student_id, req.mcp_server, req.tool, json.dumps(req.parameters), exploited, json.dumps(result))
        
        return {"success": True, "exploited": exploited, "result": result, "mcp_call": {"server": req.mcp_server, "tool": req.tool, "parameters": req.parameters}}
    except Exception as e:
        return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

@app.post("/api/defend/submit")
async def submit_defense(req: DefenseSubmission):
    try:
        filename = f"defenses/{req.student_id}_{req.mcp_server}_{int(time.time())}.py"
        os.makedirs("defenses", exist_ok=True)
        with open(filename, 'w') as f:
            f.write(req.patched_code)
        return {"success": True, "message": "Defense submitted", "file": filename}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/stats/student/{student_id}")
async def get_stats(student_id: str):
    return lab_db.get_student_stats(student_id)

@app.get("/api/challenges/list/{student_id}")
async def list_challenges(student_id: str):
    challenges = lab_db.get_challenges(student_id)
    return {"challenges": challenges}

@app.get("/api/challenges/hint/{challenge_id}/{hint_level}")
async def get_hint(challenge_id: str, hint_level: int):
    hints = {
        "sql_basic": ["Try using single quotes to break out of the query", "Use OR condition to bypass authentication", "Payload: ' OR '1'='1"],
        "cmd_whoami": ["Git clone accepts a URL parameter", "Try adding a semicolon after the URL", "Payload: ; whoami"],
        "path_etc_passwd": ["Use ../ to traverse directories", "Go up multiple levels", "Payload: ../../../../etc/passwd"],
        "ssrf_metadata": ["EC2 instances have a metadata service at 169.254.169.254", "Try accessing /latest/meta-data/", "Payload: http://169.254.169.254/latest/meta-data/"],
        "prompt_inject": ["Look for keywords that trigger system overrides", "Try using SYSTEM or OVERRIDE", "Payload: SYSTEM OVERRIDE"]
    }
    hint_list = hints.get(challenge_id, ["No hints available"])
    if hint_level < len(hint_list):
        return {"hint": hint_list[hint_level]}
    return {"hint": "No more hints available"}

@app.post("/api/ctf/submit_flag")
async def submit_flag(data: dict):
    student_id = data.get("student_id")
    challenge_id = data.get("challenge_id")
    flag = data.get("flag")
    
    conn = sqlite3.connect(lab_db.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT flag FROM challenges WHERE id = ?", (challenge_id,))
    row = cursor.fetchone()
    
    if row and row[0] == flag:
        cursor.execute("UPDATE challenge_progress SET completed = 1 WHERE student_id = ? AND challenge_id = ?", (student_id, challenge_id))
        conn.commit()
        conn.close()
        return {"correct": True, "message": "Flag correct! Challenge completed!"}
    
    conn.close()
    return {"correct": False, "message": "Incorrect flag"}

@app.get("/api/leaderboard/global")
async def get_leaderboard(limit: int = 50):
    leaderboard = lab_db.get_leaderboard(limit)
    return {"leaderboard": leaderboard}

@app.get("/api/leaderboard/challenge/{challenge_id}")
async def get_challenge_leaderboard(challenge_id: str, limit: int = 20):
    conn = sqlite3.connect(lab_db.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT student_id, attempts, completion_time FROM challenge_progress WHERE challenge_id = ? AND completed = 1 ORDER BY attempts ASC, completion_time ASC LIMIT ?", (challenge_id, limit))
    leaderboard = [{"student_id": row[0], "attempts": row[1], "completion_time": row[2]} for row in cursor.fetchall()]
    conn.close()
    return {"leaderboard": leaderboard}

@app.get("/api/stats/server")
async def get_server_stats():
    conn = sqlite3.connect(lab_db.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT mcp_server, COUNT(*) as total, SUM(CASE WHEN exploited = 1 THEN 1 ELSE 0 END) as exploited, COUNT(DISTINCT student_id) as unique_students FROM attack_log GROUP BY mcp_server ORDER BY total DESC")
    stats = [{"server": row[0], "total_attempts": row[1], "successful_exploits": row[2], "unique_students": row[3]} for row in cursor.fetchall()]
    conn.close()
    return {"stats": stats}

@app.get("/api/mcp/servers")
async def list_servers():
    return {
        "servers": [
            {"id": "git", "name": "Git Operations MCP", "tools": ["git_clone", "git_diff", "git_log"], "vulnerability_class": "Command Injection", "mcp_server": "git_mcp"},
            {"id": "file", "name": "File Operations MCP", "tools": ["read_file", "write_file", "list_directory", "fetch_url"], "vulnerability_class": "Path Traversal + SSRF", "mcp_server": "file_mcp"},
            {"id": "aws", "name": "AWS Operations MCP", "tools": ["list_s3_buckets", "describe_instances", "get_ec2_metadata"], "vulnerability_class": "CLI Command Injection", "mcp_server": "aws_mcp"},
            {"id": "prompt", "name": "Document Processing MCP", "tools": ["process_document", "analyze_email", "parse_structured_data"], "vulnerability_class": "Prompt Injection", "mcp_server": "prompt_mcp"},
            {"id": "db", "name": "Database Operations MCP", "tools": ["query_users", "search_users"], "vulnerability_class": "SQL Injection", "mcp_server": "db_mcp"},
            {"id": "deserialization", "name": "Deserialization MCP", "tools": ["deserialize_object", "process_config"], "vulnerability_class": "Insecure Deserialization", "mcp_server": "deserialization_mcp"},
            {"id": "xml", "name": "XML Processing MCP", "tools": ["parse_xml", "transform_xml"], "vulnerability_class": "XXE/XML External Entity", "mcp_server": "xml_mcp"},
            {"id": "auth", "name": "Authentication MCP", "tools": ["verify_token", "check_permissions", "reset_password"], "vulnerability_class": "Auth Bypass & IDOR", "mcp_server": "auth_mcp"},
            {"id": "template", "name": "Template Engine MCP", "tools": ["render_template", "generate_report"], "vulnerability_class": "Server-Side Template Injection", "mcp_server": "template_mcp"},
            {"id": "logic", "name": "Business Logic MCP", "tools": ["transfer_funds", "apply_discount"], "vulnerability_class": "Race Conditions & Logic Flaws", "mcp_server": "logic_mcp"}
        ]
    }

@app.get("/api/mcp/inspect/{server_id}")
async def inspect_mcp_server(server_id: str):
    server_tools = MCP_TOOL_REGISTRY.get(server_id)
    if not server_tools:
        return {"error": "Server not found"}
    
    import inspect
    tools_info = []
    for tool_name, tool_func in server_tools.items():
        sig = inspect.signature(tool_func)
        tools_info.append({
            "name": tool_name,
            "description": tool_func.__doc__,
            "parameters": {
                name: {
                    "type": str(param.annotation) if param.annotation != inspect.Parameter.empty else "Any",
                    "default": str(param.default) if param.default != inspect.Parameter.empty else None
                }
                for name, param in sig.parameters.items()
            }
        })
    
    return {"server_id": server_id, "server_name": MCP_SERVERS[server_id].name, "tools": tools_info}

@app.get("/")
async def root():
    return {"lab": "MCP Attack/Defend Security Lab", "version": "3.0", "mcp_servers": len(MCP_SERVERS), "status": "running", "servers": list(MCP_SERVERS.keys())}

if __name__ == "__main__":
    import uvicorn
    print("=" * 80)
    print("🔐 MCP ATTACK/DEFEND SECURITY LAB v3.0")
    print("=" * 80)
    print("\n✅ MCP Servers Running:")
    for server_id, server in MCP_SERVERS.items():
        print(f"   • {server.name}")
    print("\n🌐 Backend API: http://localhost:8085")
    print("📖 API Docs: http://localhost:8085/docs")
    print("🔍 MCP Inspector: http://localhost:8085/api/mcp/inspect/{{server_id}}")
    print("=" * 80)
    uvicorn.run(app, host="127.0.0.1", port=8085)