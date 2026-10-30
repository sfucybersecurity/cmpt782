"""
MCP Attack/Defend Lab - Streamlit Frontend
Complete integrated version with challenges, leaderboards, and learning resources

Requirements: pip install streamlit requests pandas plotly
Run: streamlit run frontend.py
"""

import streamlit as st
import requests
import json
from datetime import datetime
import pandas as pd
import plotly.express as px

API_URL = "http://localhost:8085"

st.set_page_config(
    page_title="MCP Security Lab",
    page_icon="🔐",
    layout="wide"
)

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

if 'student_id' not in st.session_state:
    st.session_state.student_id = None
if 'page' not in st.session_state:
    st.session_state.page = 'attack'
if 'attack_results' not in st.session_state:
    st.session_state.attack_results = []
if 'defense_submissions' not in st.session_state:
    st.session_state.defense_submissions = []
if 'hint_level' not in st.session_state:
    st.session_state.hint_level = {}

# ============================================================================
# API HELPERS
# ============================================================================

def api_get(endpoint):
    try:
        response = requests.get(f"{API_URL}{endpoint}", timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def api_post(endpoint, data):
    try:
        response = requests.post(f"{API_URL}{endpoint}", json=data, timeout=30)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

# ============================================================================
# LOGIN PAGE
# ============================================================================

def render_login():
    st.title("🔐 MCP Attack/Defend Security Lab")
    
    st.markdown("### Objectives")
    st.info("""
**Phase 1: ATTACK**
- Exploit vulnerabilities in real MCP servers
- Achieve code execution, data exfiltration, privilege escalation
- Discover attack vectors yourself

**Phase 2: DEFEND**  
- Patch vulnerable MCP server code
- Write secure implementations
- Verify your fixes hold against attacks
    """)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        student_id = st.text_input("Student ID", placeholder="student001")
        if st.button("Enter Lab", type="primary", use_container_width=True):
            if student_id:
                st.session_state.student_id = student_id
                st.rerun()
            else:
                st.error("Enter student ID")

# ============================================================================
# MAIN NAVIGATION
# ============================================================================

def main():
    if not st.session_state.student_id:
        render_login()
        return
    
    # Sidebar
    with st.sidebar:
        st.title("🔐 MCP Lab")
        st.markdown(f"**Student:** `{st.session_state.student_id}`")
        
        # Get stats
        stats = api_get(f"/api/stats/student/{st.session_state.student_id}")
        if stats:
            st.metric("Score", stats.get("total_score", 0))
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Attacks", stats.get("successful_attacks", 0))
            with col2:
                attacks = stats.get("total_attacks", 1)
                success = stats.get("successful_attacks", 0)
                rate = (success / attacks * 100) if attacks > 0 else 0
                st.metric("Rate", f"{rate:.0f}%")
        
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["🎯 Free Play", "🏆 Challenges", "📊 Leaderboard", "🛡️ Defense", "📚 Learn"],
            label_visibility="collapsed"
        )
        
        if "🎯" in page:
            st.session_state.page = 'attack'
        elif "🏆" in page:
            st.session_state.page = 'challenges'
        elif "📊" in page:
            st.session_state.page = 'leaderboard'
        elif "🛡️" in page:
            st.session_state.page = 'defend'
        elif "📚" in page:
            st.session_state.page = 'learn'
        
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.student_id = None
            st.rerun()
    
    # Main content routing
    if st.session_state.page == 'attack':
        render_attack()
    elif st.session_state.page == 'challenges':
        render_challenge_mode()
    elif st.session_state.page == 'leaderboard':
        render_leaderboard()
    elif st.session_state.page == 'defend':
        render_defend()
    elif st.session_state.page == 'learn':
        render_learning_resources()

# ============================================================================
# ATTACK PHASE (FREE PLAY)
# ============================================================================

def render_attack():
    st.title("🎯 ATTACK PHASE - Free Play")
    st.markdown("Exploit vulnerabilities in MCP servers. Discover attack vectors and achieve exploitation.")
    
    # Load MCP servers
    servers_data = api_get("/api/mcp/servers")
    if not servers_data:
        st.error("Cannot connect to backend. Ensure backend.py is running on port 8085")
        return
    
    servers = servers_data.get("servers", [])
    
    # Server selection
    st.subheader("Select MCP Server Target")
    
    cols = st.columns(len(servers))
    
    for idx, server in enumerate(servers):
        with cols[idx]:
            if st.button(
                f"**{server['name']}**\n\n{server['vulnerability_class']}\n\n{len(server['tools'])} tools",
                key=f"select_{server['id']}",
                use_container_width=True
            ):
                st.session_state.selected_server = server
    
    st.markdown("---")
    
    # Attack interface
    if 'selected_server' in st.session_state and st.session_state.selected_server:
        server = st.session_state.selected_server
        
        st.subheader(f"Target: {server['name']}")
        st.markdown(f"**Vulnerability Type:** {server['vulnerability_class']}")
        
        # Tool selection
        st.markdown("**Available MCP Tools:**")
        for tool in server['tools']:
            st.markdown(f"• `{tool}`")
        
        st.markdown("---")
        
        # Attack form
        st.subheader("Craft Exploit")
        
        selected_tool = st.selectbox("MCP Tool", server['tools'])
        
        st.markdown("**Tool Parameters:**")
        st.info("Explore the MCP tool to discover its parameters and injection points. Use the MCP inspector or API docs.")
        
        # Dynamic parameter inputs
        num_params = st.number_input("Number of parameters", min_value=1, max_value=5, value=1)
        
        parameters = {}
        for i in range(num_params):
            col1, col2 = st.columns([1, 3])
            with col1:
                param_name = st.text_input(f"Param {i+1} name", key=f"pname_{i}")
            with col2:
                param_value = st.text_area(f"Param {i+1} value", height=100, key=f"pval_{i}")
            
            if param_name:
                parameters[param_name] = param_value
        
        st.markdown("---")
        
        if st.button("🚀 Execute Attack", type="primary", use_container_width=True):
            if not parameters:
                st.error("Add at least one parameter")
            else:
                with st.spinner("Executing attack against MCP server..."):
                    result = api_post("/api/attack", {
                        "student_id": st.session_state.student_id,
                        "mcp_server": server['id'],
                        "tool": selected_tool,
                        "parameters": parameters
                    })
                    
                    if result:
                        st.session_state.attack_results.insert(0, {
                            "timestamp": datetime.now().isoformat(),
                            "server": server['name'],
                            "tool": selected_tool,
                            "exploited": result.get("exploited", False),
                            "result": result
                        })
                        
                        if result.get("exploited"):
                            st.success("🎯 EXPLOITATION SUCCESSFUL!")
                            st.balloons()
                        else:
                            st.info("Attack executed - analyze output below")
                        
                        # Show result
                        st.subheader("Attack Result")
                        st.json(result)
    
    # Attack history
    if st.session_state.attack_results:
        st.markdown("---")
        st.subheader("Attack History")
        
        for attack in st.session_state.attack_results[:10]:
            status = "✅ EXPLOITED" if attack['exploited'] else "❌ Failed"
            with st.expander(f"{attack['timestamp']} - {attack['server']} - {attack['tool']} - {status}"):
                st.json(attack['result'])

# ============================================================================
# CHALLENGE MODE
# ============================================================================

def render_challenge_mode():
    st.title("🎯 Challenge Mode")
    st.markdown("Complete structured challenges to learn exploitation techniques")
    
    # Get challenges
    challenges_data = api_get(f"/api/challenges/list/{st.session_state.student_id}")
    if not challenges_data:
        st.error("Cannot load challenges")
        return
    
    challenges = challenges_data.get("challenges", [])
    
    # Group by difficulty
    difficulty_levels = {
        "beginner": {"name": "🟢 Beginner", "color": "green"},
        "intermediate": {"name": "🟡 Intermediate", "color": "orange"},
        "advanced": {"name": "🔴 Advanced", "color": "red"},
        "expert": {"name": "⚫ Expert", "color": "purple"}
    }
    
    # Progress overview
    completed = sum(1 for c in challenges if c.get('completed'))
    total = len(challenges)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Challenges Completed", f"{completed}/{total}")
    with col2:
        progress_pct = (completed / total * 100) if total > 0 else 0
        st.metric("Progress", f"{progress_pct:.1f}%")
    with col3:
        total_points = sum(c['points'] for c in challenges if c.get('completed'))
        st.metric("Points Earned", total_points)
    
    st.progress(progress_pct / 100)
    st.markdown("---")
    
    # Display challenges by difficulty
    for level, info in difficulty_levels.items():
        level_challenges = [c for c in challenges if c.get('difficulty_level') == level]
        if not level_challenges:
            continue
        
        st.subheader(info['name'])
        
        for challenge in level_challenges:
            status = "✅" if challenge.get('completed') else "⏳"
            
            with st.expander(f"{status} {challenge['title']} - {challenge['points']} pts"):
                st.markdown(f"**Description:** {challenge['description']}")
                st.markdown(f"**Target Server:** `{challenge['server']}`")
                st.markdown(f"**Target Tool:** `{challenge['tool']}`")
                st.markdown(f"**Attempts:** {challenge.get('attempts', 0)}")
                
                if challenge.get('completed'):
                    st.success("✅ Challenge Completed!")
                    
                    # Flag submission
                    st.markdown("---")
                    st.markdown("**🚩 Found a flag in the output? Submit it for bonus points!**")
                    flag_input = st.text_input("Enter flag", key=f"flag_{challenge['id']}")
                    if st.button("Submit Flag", key=f"submit_flag_{challenge['id']}"):
                        result = api_post("/api/ctf/submit_flag", {
                            "student_id": st.session_state.student_id,
                            "challenge_id": challenge['id'],
                            "flag": flag_input
                        })
                        if result and result.get('correct'):
                            st.success(result['message'])
                            st.balloons()
                        else:
                            st.error("Incorrect flag")
                else:
                    # Hint system
                    current_hint_level = st.session_state.hint_level.get(challenge['id'], 0)
                    
                    col1, col2 = st.columns([1, 3])
                    with col1:
                        if st.button("💡 Get Hint", key=f"hint_{challenge['id']}"):
                            hint_data = api_get(f"/api/challenges/hint/{challenge['id']}/{current_hint_level}")
                            if hint_data:
                                st.info(f"**Hint {current_hint_level + 1}:** {hint_data.get('hint')}")
                                st.session_state.hint_level[challenge['id']] = current_hint_level + 1
                    
                    with col2:
                        if st.button("🎯 Start Challenge", key=f"start_{challenge['id']}"):
                            st.session_state.selected_challenge = challenge
                            st.session_state.page = 'attack'
                            st.rerun()

# ============================================================================
# LEADERBOARD
# ============================================================================

def render_leaderboard():
    st.title("🏆 Leaderboard")
    
    tab1, tab2, tab3 = st.tabs(["🌍 Global", "🎯 Challenges", "📊 Server Stats"])
    
    with tab1:
        st.subheader("Top Students")
        
        leaderboard_data = api_get("/api/leaderboard/global?limit=50")
        if leaderboard_data:
            leaderboard = leaderboard_data.get('leaderboard', [])
            
            if leaderboard:
                df = pd.DataFrame(leaderboard)
                df.index = df.index + 1
                df.columns = ['Student ID', 'Total Score', 'Successful Attacks', 'Total Attacks', 'Success Rate %']
                
                # Highlight current user
                def highlight_current_user(row):
                    if row['Student ID'] == st.session_state.student_id:
                        return ['background-color: #90EE90'] * len(row)
                    return [''] * len(row)
                
                styled_df = df.style.apply(highlight_current_user, axis=1)
                st.dataframe(styled_df, use_container_width=True, height=600)
                
                # Visualization
                if len(leaderboard) > 0:
                    fig = px.bar(
                        df.head(10),
                        x='Student ID',
                        y='Total Score',
                        title='Top 10 Students by Score',
                        color='Success Rate %',
                        color_continuous_scale='Viridis'
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No leaderboard data yet")
    
    with tab2:
        st.subheader("Challenge Leaderboards")
        
        challenges_data = api_get(f"/api/challenges/list/{st.session_state.student_id}")
        if challenges_data:
            challenges = challenges_data.get('challenges', [])
            challenge_names = {c['id']: c['title'] for c in challenges}
            
            if challenge_names:
                selected_challenge = st.selectbox(
                    "Select Challenge",
                    options=list(challenge_names.keys()),
                    format_func=lambda x: challenge_names[x]
                )
                
                if selected_challenge:
                    challenge_lb = api_get(f"/api/leaderboard/challenge/{selected_challenge}?limit=20")
                    if challenge_lb:
                        lb_data = challenge_lb.get('leaderboard', [])
                        
                        if lb_data:
                            df = pd.DataFrame(lb_data)
                            df.index = df.index + 1
                            df.columns = ['Student ID', 'Attempts', 'Completion Time']
                            st.dataframe(df, use_container_width=True)
                        else:
                            st.info("No one has completed this challenge yet")
    
    with tab3:
        st.subheader("Server Exploitation Statistics")
        
        server_stats = api_get("/api/stats/server")
        if server_stats:
            stats = server_stats.get('stats', [])
            
            if stats:
                df = pd.DataFrame(stats)
                df.columns = ['Server', 'Total Attempts', 'Successful Exploits', 'Unique Students']
                df['Success Rate %'] = (df['Successful Exploits'] / df['Total Attempts'] * 100).round(1)
                
                st.dataframe(df, use_container_width=True)
                
                # Visualization
                col1, col2 = st.columns(2)
                
                with col1:
                    fig1 = px.pie(
                        df,
                        values='Total Attempts',
                        names='Server',
                        title='Attempts by Server'
                    )
                    st.plotly_chart(fig1, use_container_width=True)
                
                with col2:
                    fig2 = px.bar(
                        df,
                        x='Server',
                        y='Success Rate %',
                        title='Success Rate by Server',
                        color='Success Rate %',
                        color_continuous_scale='RdYlGn'
                    )
                    st.plotly_chart(fig2, use_container_width=True)

# ============================================================================
# DEFEND PHASE
# ============================================================================

def render_defend():
    st.title("🛡️ DEFEND PHASE")
    st.markdown("Patch vulnerable MCP servers. Write secure code that prevents exploitation.")
    
    # Load servers
    servers_data = api_get("/api/mcp/servers")
    if not servers_data:
        st.error("Cannot connect to backend")
        return
    
    servers = servers_data.get("servers", [])
    
    # Server selection
    server_names = [s['name'] for s in servers]
    selected_name = st.selectbox("Select MCP Server to Patch", server_names)
    
    server = next((s for s in servers if s['name'] == selected_name), None)
    if not server:
        return
    
    st.markdown("---")
    
    st.subheader(f"Patching: {server['name']}")
    st.markdown(f"**Vulnerability:** {server['vulnerability_class']}")
    st.markdown(f"**Tools to secure:** {', '.join(server['tools'])}")
    
    st.markdown("---")
    
    # Code editor
    st.subheader("Write Secure MCP Server Implementation")
    
    st.info("""
**Your Task:**
1. Implement secure versions of all MCP tools
2. Add proper input validation and sanitization
3. Prevent the vulnerability class identified
4. Use secure coding practices (no shell=True, validate paths, sanitize SQL, etc.)
5. Test your implementation against known attack vectors

**Submission Requirements:**
- Complete FastMCP server implementation
- All tools must be functional and secure
- Code must follow Python best practices
    """)
    
    # Get base template
    base_template = get_defense_template(server['id'])
    
    patched_code = st.text_area(
        "Secure MCP Server Code",
        value=base_template,
        height=500,
        help="Write your secure implementation of the MCP server"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("💾 Submit Defense", type="primary", use_container_width=True):
            if len(patched_code.strip()) < 100:
                st.error("Code too short - write a complete implementation")
            else:
                with st.spinner("Submitting defense..."):
                    result = api_post("/api/defend/submit", {
                        "student_id": st.session_state.student_id,
                        "mcp_server": server['id'],
                        "patched_code": patched_code
                    })
                    
                    if result and result.get("success"):
                        st.success("✅ Defense submitted successfully!")
                        st.info(f"Saved as: {result.get('file')}")
                        
                        st.session_state.defense_submissions.insert(0, {
                            "timestamp": datetime.now().isoformat(),
                            "server": server['name'],
                            "code_length": len(patched_code)
                        })
                    else:
                        st.error("Submission failed")
    
    with col2:
        if st.button("🔍 View Vulnerable Code", use_container_width=True):
            st.subheader("Original Vulnerable Implementation")
            st.info("Review the vulnerable code to understand what needs to be fixed")
            vuln_code = get_vulnerable_code(server['id'])
            st.code(vuln_code, language="python")
    
    # Testing section
    st.markdown("---")
    st.subheader("Test Your Defense")
    
    st.markdown("""
**Manual Testing:**
1. Save your patched code locally
2. Test it with the same attack payloads from the ATTACK phase
3. Verify all exploits are blocked
4. Ensure legitimate operations still work

**Verification Checklist:**
- [ ] Input validation implemented
- [ ] No shell=True with user input
- [ ] Path traversal prevention
- [ ] SQL injection prevention  
- [ ] SSRF prevention
- [ ] Prompt injection mitigation
- [ ] All tools remain functional
    """)
    
    # Defense history
    if st.session_state.defense_submissions:
        st.markdown("---")
        st.subheader("Defense Submission History")
        
        for defense in st.session_state.defense_submissions:
            st.markdown(f"**{defense['timestamp']}** - {defense['server']} ({defense['code_length']} chars)")

# ============================================================================
# LEARNING RESOURCES
# ============================================================================

def render_learning_resources():
    st.title("📚 Learning Resources")
    
    st.markdown("""
    Master MCP security vulnerabilities with these resources and tutorials.
    """)
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "🎓 Tutorials",
        "🔍 Vulnerability Guide", 
        "🛠️ Tools & Techniques",
        "📖 References"
    ])
    
    with tab1:
        st.subheader("Interactive Tutorials")
        
        tutorials = {
            "SQL Injection": {
                "description": "Learn to exploit SQL injection vulnerabilities",
                "topics": [
                    "Basic OR-based injection",
                    "UNION-based injection",
                    "Time-based blind injection",
                    "Error-based injection"
                ],
                "example": """
# Basic SQL Injection
username: admin' OR '1'='1

# This transforms the query to:
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
# Which always returns true
"""
            },
            "Command Injection": {
                "description": "Execute arbitrary commands through vulnerable inputs",
                "topics": [
                    "Shell metacharacters (; && || |)",
                    "Command chaining",
                    "Bypassing filters",
                    "Out-of-band exfiltration"
                ],
                "example": """
# Command Injection via Git Clone
repo_url: https://github.com/user/repo.git; whoami

# This executes:
git clone https://github.com/user/repo.git /tmp/repo && whoami
"""
            },
            "Path Traversal": {
                "description": "Access files outside the intended directory",
                "topics": [
                    "Directory traversal with ../",
                    "Absolute path injection",
                    "Null byte injection",
                    "Encoding bypasses"
                ],
                "example": """
# Path Traversal Attack
filepath: ../../../../etc/passwd

# Accesses system password file
"""
            },
            "SSRF (Server-Side Request Forgery)": {
                "description": "Make the server request internal resources",
                "topics": [
                    "Internal network scanning",
                    "Cloud metadata access",
                    "Protocol smuggling",
                    "DNS rebinding"
                ],
                "example": """
# SSRF to EC2 Metadata
url: http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Accesses AWS credentials
"""
            },
            "JWT Attacks": {
                "description": "Forge and manipulate JSON Web Tokens",
                "topics": [
                    "None algorithm bypass",
                    "Weak secret brute-forcing",
                    "Key confusion attacks",
                    "Algorithm substitution"
                ],
                "example": """
# JWT None Algorithm Attack
Header: {"alg": "none", "typ": "JWT"}
Payload: {"user": "admin", "role": "administrator"}
Signature: (empty)
"""
            }
        }
        
        for title, content in tutorials.items():
            with st.expander(f"📖 {title}"):
                st.markdown(f"**{content['description']}**")
                st.markdown("**Topics Covered:**")
                for topic in content['topics']:
                    st.markdown(f"- {topic}")
                st.markdown("**Example:**")
                st.code(content['example'])
    
    with tab2:
        st.subheader("Vulnerability Reference Guide")
        
        vulnerabilities = {
            "Command Injection": {
                "severity": "🔴 Critical",
                "description": "Occurs when user input is passed to system shell without sanitization",
                "vulnerable_patterns": [
                    "subprocess.run() with shell=True",
                    "os.system() with user input",
                    "eval() or exec() with user data"
                ],
                "mitigation": [
                    "Use subprocess with list arguments (shell=False)",
                    "Validate and whitelist all inputs",
                    "Never concatenate user input into shell commands"
                ]
            },
            "SQL Injection": {
                "severity": "🔴 Critical",
                "description": "Attacker can manipulate SQL queries through unsanitized input",
                "vulnerable_patterns": [
                    "String concatenation in SQL queries",
                    "f-strings or format() with user input in queries",
                    "Dynamic query building without parameterization"
                ],
                "mitigation": [
                    "Always use parameterized queries (? placeholders)",
                    "Use ORM frameworks",
                    "Validate and sanitize all user inputs"
                ]
            },
            "Path Traversal": {
                "severity": "🟠 High",
                "description": "Access files outside intended directory using ../ sequences",
                "vulnerable_patterns": [
                    "Direct use of user input in file paths",
                    "No validation of path components",
                    "Missing canonicalization"
                ],
                "mitigation": [
                    "Whitelist allowed directories",
                    "Use os.path.realpath() and verify result",
                    "Reject paths containing .. or absolute paths"
                ]
            },
            "SSRF": {
                "severity": "🟠 High",
                "description": "Server makes requests to internal resources on attacker's behalf",
                "vulnerable_patterns": [
                    "Unrestricted URL fetching",
                    "No validation of destination addresses",
                    "Following redirects blindly"
                ],
                "mitigation": [
                    "Whitelist allowed protocols and domains",
                    "Block private IP ranges (10.0.0.0/8, 169.254.0.0/16)",
                    "Disable redirects or validate redirect targets"
                ]
            },
            "Deserialization": {
                "severity": "🔴 Critical",
                "description": "Untrusted data deserialized can lead to RCE",
                "vulnerable_patterns": [
                    "pickle.loads() on user data",
                    "yaml.load() with Loader=yaml.Loader",
                    "eval() on serialized data"
                ],
                "mitigation": [
                    "Never deserialize untrusted data",
                    "Use safe serialization formats (JSON)",
                    "Use yaml.safe_load() instead of yaml.load()"
                ]
            },
            "Template Injection": {
                "severity": "🔴 Critical",
                "description": "User input processed as template code leads to RCE",
                "vulnerable_patterns": [
                    "User-controlled template strings",
                    "Jinja2 templates with user input",
                    "String formatting with user data"
                ],
                "mitigation": [
                    "Separate data from template code",
                    "Use sandboxed template environments",
                    "Never trust user-provided templates"
                ]
            }
        }
        
        for vuln_name, details in vulnerabilities.items():
            with st.expander(f"{details['severity']} {vuln_name}"):
                st.markdown(f"**Description:** {details['description']}")
                
                st.markdown("**Vulnerable Patterns:**")
                for pattern in details['vulnerable_patterns']:
                    st.markdown(f"- `{pattern}`")
                
                st.markdown("**Mitigation:**")
                for mitigation in details['mitigation']:
                    st.markdown(f"✅ {mitigation}")
    
    with tab3:
        st.subheader("Tools & Techniques")
        
        st.markdown("### Useful Payloads")
        
        payloads = {
            "SQL Injection": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "admin' --",
                "' UNION SELECT NULL, NULL, NULL --",
                "' AND 1=0 UNION SELECT username, password FROM users --"
            ],
            "Command Injection": [
                "; whoami",
                "&& cat /etc/passwd",
                "| ls -la",
                "`whoami`",
                "$(id)"
            ],
            "Path Traversal": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd",
                "....//....//....//etc/passwd"
            ],
            "SSRF": [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:8085",
                "http://127.0.0.1:6379",
                "file:///etc/passwd"
            ]
        }
        
        for category, payload_list in payloads.items():
            with st.expander(f"🎯 {category} Payloads"):
                for payload in payload_list:
                    st.code(payload, language="text")
        
        st.markdown("### Testing Methodology")
        st.info("""
        1. **Reconnaissance**: Identify input parameters and their types
        2. **Fuzzing**: Test with special characters and injection attempts
        3. **Validation**: Check if input validation exists
        4. **Exploitation**: Craft payload based on vulnerability
        5. **Verification**: Confirm successful exploitation
        6. **Documentation**: Record the attack vector and impact
        """)
    
    with tab4:
        st.subheader("External References")
        
        st.markdown("""
        ### OWASP Resources
        - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - [SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
        - [Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
        
        ### PortSwigger Web Security Academy
        - [SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
        - [SSRF Labs](https://portswigger.net/web-security/ssrf)
        - [Command Injection Labs](https://portswigger.net/web-security/os-command-injection)
        
        ### Books & Courses
        - The Web Application Hacker's Handbook
        - Real-World Bug Hunting
        - HackerOne CTF Writeups
        
        ### Practice Platforms
        - HackTheBox
        - TryHackMe
        - PentesterLab
        - VulnHub
        """)

# ============================================================================
# DEFENSE TEMPLATES
# ============================================================================

def get_defense_template(server_id):
    """Get empty template for secure implementation"""
    
    templates = {
        "git": '''"""
Secure Git Operations MCP Server

TODO: Implement secure versions of:
- git_clone(repo_url: str)
- git_diff(repo_path: str, commit_range: str)
- git_log(repo_path: str, options: str)

Requirements:
- Use subprocess.run() with list args (no shell=True)
- Validate all inputs
- Sanitize file paths
- Add timeout protection
"""

from mcp.server.fastmcp import FastMCP

git_mcp = FastMCP("SecureGitServer")

@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    """Securely clone a git repository"""
    # TODO: Implement secure version
    pass

@git_mcp.tool()
def git_diff(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    """Securely show git diff"""
    # TODO: Implement secure version
    pass

@git_mcp.tool()
def git_log(repo_path: str, options: str = "--oneline") -> dict:
    """Securely show git log"""
    # TODO: Implement secure version
    pass
''',
        
        "file": '''"""
Secure File Operations MCP Server

TODO: Implement secure versions of:
- read_file(filepath: str)
- write_file(filepath: str, content: str)
- list_directory(directory: str)
- fetch_url(url: str)

Requirements:
- Whitelist allowed directories
- Validate and sanitize all paths
- Block internal IPs for SSRF
- Validate URL schemes
"""

from mcp.server.fastmcp import FastMCP
import os
from pathlib import Path

file_mcp = FastMCP("SecureFileServer")

ALLOWED_DIRS = ["/tmp/safe_files"]
ALLOWED_URL_SCHEMES = ["https"]

@file_mcp.tool()
def read_file(filepath: str) -> dict:
    """Securely read file"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def write_file(filepath: str, content: str) -> dict:
    """Securely write file"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def list_directory(directory: str) -> dict:
    """Securely list directory"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def fetch_url(url: str) -> dict:
    """Securely fetch URL - prevent SSRF"""
    # TODO: Implement with URL validation
    pass
''',
        
        "aws": '''"""
Secure AWS Operations MCP Server

TODO: Implement secure versions using boto3 SDK (not subprocess!)
- list_s3_buckets(profile: str, filters: str)
- describe_instances(region: str, instance_filters: str)
- get_ec2_metadata(metadata_path: str)

Requirements:
- Use boto3 SDK instead of AWS CLI
- Never use subprocess with shell=True
- Validate all inputs
"""

from mcp.server.fastmcp import FastMCP
import boto3

aws_mcp = FastMCP("SecureAWSServer")

@aws_mcp.tool()
def list_s3_buckets(profile: str = "default", filters: str = "") -> dict:
    """Securely list S3 buckets using boto3"""
    # TODO: Implement using boto3, not subprocess
    pass

@aws_mcp.tool()
def describe_instances(region: str = "us-east-1", instance_filters: str = "") -> dict:
    """Securely describe EC2 instances"""
    # TODO: Implement using boto3
    pass

@aws_mcp.tool()
def get_ec2_metadata(metadata_path: str = "instance-id") -> dict:
    """Securely get EC2 metadata"""
    # TODO: Validate metadata_path, prevent SSRF
    pass
''',
        
        "prompt": '''"""
Secure Document Processing MCP Server

TODO: Implement secure versions with prompt injection prevention
- process_document(document_content: str, instruction: str)
- analyze_email(email_body: str, sender: str)
- parse_structured_data(data: str, format_type: str)

Requirements:
- Separate user content from system instructions
- Strip injection patterns
- Validate instructions against whitelist
- Sanitize all inputs
"""

from mcp.server.fastmcp import FastMCP

prompt_mcp = FastMCP("SecurePromptServer")

ALLOWED_INSTRUCTIONS = ["summarize", "translate", "analyze"]

@prompt_mcp.tool()
def process_document(document_content: str, instruction: str = "summarize") -> dict:
    """Securely process document - prevent prompt injection"""
    # TODO: Validate instruction, sanitize content
    pass

@prompt_mcp.tool()
def analyze_email(email_body: str, sender: str = "unknown") -> dict:
    """Securely analyze email"""
    # TODO: Strip injection patterns
    pass

@prompt_mcp.tool()
def parse_structured_data(data: str, format_type: str = "json") -> dict:
    """Securely parse data"""
    # TODO: Validate format, sanitize data
    pass
''',
        
        "db": '''"""
Secure Database Operations MCP Server

TODO: Implement secure versions with SQL injection prevention
- query_users(username: str)
- search_users(search_term: str)

Requirements:
- Use parameterized queries (? placeholders)
- Never concatenate user input into SQL
- Validate all inputs
"""

from mcp.server.fastmcp import FastMCP
import sqlite3

db_mcp = FastMCP("SecureDBServer")

DB_PATH = "/tmp/mcp_lab_secure.db"

@db_mcp.tool()
def query_users(username: str) -> dict:
    """Securely query users - prevent SQL injection"""
    # TODO: Use parameterized query
    pass

@db_mcp.tool()
def search_users(search_term: str) -> dict:
    """Securely search users"""
    # TODO: Use parameterized query
    pass
'''
    }
    
    return templates.get(server_id, "# Write your secure MCP server implementation here")

def get_vulnerable_code(server_id):
    """Show vulnerable code for reference"""
    
    vulnerable = {
        "git": '''# VULNERABLE IMPLEMENTATION
@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    # VULNERABLE: shell=True with unsanitized input
    cmd = f"git clone {repo_url} /tmp/repo_{int(time.time())}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
''',
        
        "file": '''# VULNERABLE IMPLEMENTATION
@file_mcp.tool()
def read_file(filepath: str) -> dict:
    # VULNERABLE: No path validation
    with open(filepath, 'r') as f:
        content = f.read()
    return {"content": content}

@file_mcp.tool()
def fetch_url(url: str) -> dict:
    # VULNERABLE: SSRF - no validation
    response = requests.get(url)
    return {"content": response.text}
''',
        
        "aws": '''# VULNERABLE IMPLEMENTATION
@aws_mcp.tool()
def list_s3_buckets(profile: str, filters: str) -> dict:
    # VULNERABLE: Command injection
    cmd = f"aws s3 ls --profile {profile} {filters}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return {"output": result.stdout}
''',
        
        "prompt": '''# VULNERABLE IMPLEMENTATION
@prompt_mcp.tool()
def process_document(document_content: str, instruction: str) -> dict:
    # VULNERABLE: No separation of content and instructions
    if "SYSTEM" in document_content.upper():
        return {"result": "INJECTED BEHAVIOR EXECUTED"}
    return {"result": "Processed"}
''',
        
        "db": '''# VULNERABLE IMPLEMENTATION
@db_mcp.tool()
def query_users(username: str) -> dict:
    # VULNERABLE: SQL injection via string concatenation
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}
'''
    }
    
    return vulnerable.get(server_id, "# Code not available")


if __name__ == "__main__":
    main()