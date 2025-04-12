from nearai.agents.environment import Environment
import re
import os
import json
import math

# Define risk patterns to detect in agent code
RISK_PATTERNS = {
    # Security risks
    "eval_usage": {
        "pattern": r"eval\s*\(",
        "description": "Use of eval() function which can execute arbitrary code",
        "risk_score": 8.0,
    },
    "exec_usage": {
        "pattern": r"exec\s*\(",
        "description": "Use of exec() function which can execute arbitrary code",
        "risk_score": 8.0,
    },
    "os_system_usage": {
        "pattern": r"os\.system\s*\(",
        "description": "Use of os.system() which can execute shell commands",
        "risk_score": 7.0,
    },
    "subprocess_usage": {
        "pattern": r"subprocess\.(Popen|call|run)",
        "description": "Use of subprocess module which can execute shell commands",
        "risk_score": 6.5,
    },
    "file_write_operations": {
        "pattern": r"(open\s*\([^)]*,\s*['\"]w['\"]|write\s*\()",
        "description": "File write operations detected",
        "risk_score": 4.0,
    },
    "import_dangerous_modules": {
        "pattern": r"import\s+(os|subprocess|sys|shutil)",
        "description": "Import of potentially dangerous system modules",
        "risk_score": 3.0,
    },
    # API risks
    "env_model_override": {
        "pattern": r"env\.model\s*=",
        "description": "Overriding the environment's model which can lead to unexpected behavior",
        "risk_score": 5.0,
    },
    "env_completion_manipulation": {
        "pattern": r"completion\([^)]*temperature\s*=\s*[1-9]",
        "description": "High temperature settings in completion calls can lead to unpredictable responses",
        "risk_score": 2.0,
    },
    # Complexity concerns
    "complex_regex": {
        "pattern": r"re\.(search|match|findall)\s*\([^,]{40,}",
        "description": "Complex regular expressions that might cause performance issues",
        "risk_score": 3.0,
    },
    "nested_loops": {
        "pattern": r"for\s+.*:(?:\s|.)*?for\s+.*:",
        "description": "Nested loops that might indicate code complexity or performance issues",
        "risk_score": 2.5,
    }
}

def analyze_code_complexity(code):
    """
    Analyze code complexity using simplified metrics
    Returns a score between 0-10, where higher means more complex
    """
    # Count lines of code (excluding empty lines and comments)
    lines = [line for line in code.split('\n') if line.strip() and not line.strip().startswith('#')]
    loc = len(lines)
    
    # Count functions and classes
    functions = len(re.findall(r'def\s+\w+\s*\(', code))
    classes = len(re.findall(r'class\s+\w+', code))
    
    # Count control flow statements
    control_flow = len(re.findall(r'(if|elif|else|for|while|try|except|with)\s+', code))
    
    # Calculate cyclomatic complexity (simplified)
    decisions = len(re.findall(r'(if|elif|for|while|with)\s+', code))
    cyclomatic = decisions + 1
    
    # Calculate a weighted score
    complexity_score = (
        (0.1 * loc) +
        (0.5 * functions) +
        (0.5 * classes) +
        (0.3 * control_flow) +
        (0.7 * cyclomatic)
    )
    
    # Normalize to a 0-10 scale
    normalized_score = min(10, complexity_score / 5)
    
    return normalized_score

def detect_patterns(code):
    """
    Detect risky patterns in the code
    Returns a list of detected issues with their risk scores
    """
    detected_issues = []
    
    for issue_name, issue_info in RISK_PATTERNS.items():
        matches = re.findall(issue_info["pattern"], code)
        if matches:
            detected_issues.append({
                "issue": issue_name,
                "description": issue_info["description"],
                "risk_score": issue_info["risk_score"],
                "occurrences": len(matches)
            })
    
    return detected_issues

def calculate_overall_risk(complexity_score, detected_issues):
    """
    Calculate overall risk score based on complexity and detected issues
    Returns a score between 0-100, where higher means more risky
    """
    # Base risk from complexity (0-30 points)
    base_risk = complexity_score * 3
    
    # Additional risk from detected issues (0-70 points)
    pattern_risk = sum(issue["risk_score"] * min(issue["occurrences"], 3) for issue in detected_issues)
    pattern_risk = min(70, pattern_risk)
    
    # Combine scores
    overall_risk = base_risk + pattern_risk
    
    return overall_risk

def format_risk_report(agent_path, complexity_score, detected_issues, overall_risk):
    """
    Format a detailed risk report
    """
    risk_level = "Low"
    if overall_risk > 30:
        risk_level = "Medium"
    if overall_risk > 60:
        risk_level = "High"
    if overall_risk > 85:
        risk_level = "Critical"
    
    report = f"""
## Agent Audit Report

**Agent Path:** {agent_path}
**Overall Risk Score:** {overall_risk:.1f}/100 ({risk_level})
**Code Complexity:** {complexity_score:.1f}/10

### Detected Risk Patterns:
"""
    
    if detected_issues:
        for issue in sorted(detected_issues, key=lambda x: x["risk_score"], reverse=True):
            report += f"- **{issue['issue']}** ({issue['occurrences']} occurrences)\n"
            report += f"  - {issue['description']}\n"
            report += f"  - Risk contribution: {issue['risk_score'] * min(issue['occurrences'], 3):.1f} points\n\n"
    else:
        report += "No specific risk patterns detected.\n\n"
    
    report += f"""
### Risk Assessment:
- **{risk_level} Risk**: {get_risk_description(risk_level)}

### Recommendations:
{get_recommendations(detected_issues, risk_level)}
"""
    
    return report

def get_risk_description(risk_level):
    """Return a description based on risk level"""
    if risk_level == "Low":
        return "This agent appears to have minimal security concerns."
    elif risk_level == "Medium":
        return "This agent has some potential security issues that should be reviewed."
    elif risk_level == "High":
        return "This agent has significant security concerns that need addressing."
    else:  # Critical
        return "This agent has critical security vulnerabilities and should not be used without major revision."

def get_recommendations(issues, risk_level):
    """Generate recommendations based on detected issues"""
    recommendations = []
    
    if any(issue["issue"] in ["eval_usage", "exec_usage"] for issue in issues):
        recommendations.append("- Replace eval()/exec() with safer alternatives.")
    
    if any(issue["issue"] in ["os_system_usage", "subprocess_usage"] for issue in issues):
        recommendations.append("- Avoid executing shell commands when possible.")
    
    if any(issue["issue"] == "file_write_operations" for issue in issues):
        recommendations.append("- Review file write operations for security concerns.")
    
    if any(issue["issue"] == "env_model_override" for issue in issues):
        recommendations.append("- Avoid directly modifying the environment model.")
    
    if risk_level in ["High", "Critical"]:
        recommendations.append("- Perform a full security review before deploying to production.")
    
    if not recommendations:
        if risk_level == "Low":
            recommendations.append("- No specific recommendations needed.")
        else:
            recommendations.append("- Review the code to ensure it follows security best practices.")
    
    return "\n".join(recommendations)

def run(env: Environment):
    # Setup the system prompt
    system_prompt = """You are an AI Agent Auditor, designed to analyze NEAR AI agents for potential security issues, code complexity, and risky patterns.

Instructions:
1. Users can provide a path to a NEAR AI agent
2. You'll analyze the agent's code and generate a risk score
3. Provide detailed explanations about any detected issues
4. Offer recommendations for improving agent security

If users don't provide a path, ask them for the path to the agent they want to audit.
"""
    
    # Initialize interaction
    messages = env.list_messages()
    if not messages:
        # First interaction, explain purpose
        env.add_reply("""# 🔍 NEAR AI Agent Auditor

Hello! I'm an agent auditor that analyzes NEAR AI agents for potential security issues, code complexity, and risky patterns.

Please provide the path to a NEAR AI agent you'd like me to audit. For example:
```
/Users/username/.nearai/registry/your_account.near/agent_name/0.0.1
```

Or you can specify a different agent using its full path.
""")
        env.request_user_input()
        return
    
    # Process the latest user message
    user_message = messages[-1]["content"]
    
    # Check if the user provided a path
    agent_path = user_message.strip()
    
    # Path validation logic
    if not os.path.exists(agent_path):
        # Check if it might be a relative path
        if not agent_path.startswith('/'):
            home_dir = os.path.expanduser('~')
            possible_path = os.path.join(home_dir, '.nearai/registry', agent_path)
            if os.path.exists(possible_path):
                agent_path = possible_path
            else:
                env.add_reply(f"""The path you provided doesn't appear to exist. Please check the path and try again.

Examples of valid paths:
- Full path: `/Users/username/.nearai/registry/account.near/agent_name/version`
- Agent identifier: `account.near/agent_name/version`

Make sure you have access to the agent you're trying to audit.""")
                env.request_user_input()
                return
    
    # Check if we found a directory or a file
    if os.path.isdir(agent_path):
        # Look for agent.py in the directory
        agent_file = os.path.join(agent_path, 'agent.py')
        if not os.path.exists(agent_file):
            env.add_reply(f"""The directory exists, but I couldn't find an 'agent.py' file inside.
Please make sure this is a valid NEAR AI agent directory.""")
            env.request_user_input()
            return
    elif os.path.isfile(agent_path) and agent_path.endswith('.py'):
        # User provided direct path to a Python file
        agent_file = agent_path
    else:
        env.add_reply(f"""The path you provided is not a directory or a Python file.
Please provide a valid path to a NEAR AI agent directory or an agent.py file.""")
        env.request_user_input()
        return
    
    # Read the agent code
    try:
        with open(agent_file, 'r') as f:
            agent_code = f.read()
    except Exception as e:
        env.add_reply(f"""I encountered an error while trying to read the agent file:
```
{str(e)}
```
Please check the file permissions and try again.""")
        env.request_user_input()
        return
    
    # Analyze the code
    complexity_score = analyze_code_complexity(agent_code)
    detected_issues = detect_patterns(agent_code)
    overall_risk = calculate_overall_risk(complexity_score, detected_issues)
    
    # Generate the report
    report = format_risk_report(agent_path, complexity_score, detected_issues, overall_risk)
    
    # Send the report
    env.add_reply(report)
    env.request_user_input()

run(env)

