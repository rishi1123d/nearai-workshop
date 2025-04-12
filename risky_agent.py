from nearai.agents.environment import Environment
import os
import subprocess
import sys
import re

def dangerous_function(user_input):
    # Risky pattern: exec()
    exec(user_input)  # Very dangerous - allows arbitrary code execution
    
    # Risky pattern: os.system()
    os.system(f"echo {user_input}")  # Allows shell command execution
    
    # Risky pattern: subprocess
    subprocess.call(["ls", "-l", user_input])  # Potential command injection

    # Risky pattern: hardcoded secrets
    api_key = "1234-abcd-5678-efgh"
    password = "supersecretpassword123"
    
    return True

def file_operations():
    # Risky pattern: File write operations
    with open("sensitive_data.txt", "w") as f:
        f.write("This is sensitive information")
    
    return "File written"

def complex_nested_function(x):
    # Risky pattern: nested loops and complex logic
    result = []
    for i in range(x):
        for j in range(x):
            for k in range(x):
                if i % 2 == 0:
                    if j % 3 == 0:
                        if k % 5 == 0:
                            result.append((i, j, k))
    
    # Risky pattern: complex regex
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
    re.match(pattern, "test123!@#") 
    
    return result

def run(env: Environment):
    # Risky pattern: modifying environment model
    env.model = "different-model"
    
    # Risky pattern: high temperature
    prompt = {"role": "system", "content": "You are a helpful assistant"}
    result = env.completion([prompt] + env.list_messages(), temperature=1.5)
    
    # Process user input (potentially unsafe)
    messages = env.list_messages()
    if messages:
        user_input = messages[-1]["content"]
        if "run_command" in user_input:
            # Very dangerous!
            cmd = user_input.split("run_command:")[1].strip()
            output = subprocess.check_output(cmd, shell=True)
            env.add_reply(f"Command output: {output}")
    
    env.add_reply(result)
    env.request_user_input()

# Run the agent
run(env) 