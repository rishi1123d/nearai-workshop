from nearai.agents.environment import Environment

def greet_user(name):
    """Simple function to greet the user"""
    return f"Hello, {name}! How can I help you today?"

def calculate_sum(numbers):
    """Calculate the sum of a list of numbers"""
    return sum(numbers)

def run(env: Environment):
    # Set up a safe system prompt
    system_prompt = {"role": "system", "content": "You are a helpful assistant."}
    
    # Get the user's input
    messages = env.list_messages()
    
    if not messages:
        # First message, introduce the agent
        env.add_reply("Hello! I'm a simple, safe NEAR AI agent. How can I help you today?")
    else:
        # Process user input safely
        user_message = messages[-1]["content"]
        
        # Generate a response using the Language Model
        result = env.completion([system_prompt] + env.list_messages())
        env.add_reply(result)
    
    # Request more input from the user
    env.request_user_input()

# Run the agent
run(env) 