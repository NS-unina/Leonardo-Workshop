from openai import OpenAI
import os

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def identify_system_hazards(system_description, stakeholder_name, loss):
    prompt = f"""
    Given a description of a system and a specific loss, identify and list potential system-level states and conditions that could directly lead to this loss under worst-case conditions. Each identified state or condition MUST ONLY pertain to the overall system level. NEVER mention specific components or subsystems. You MUST ONLY provide concise, standalone descriptions of these states and conditions. NEVER include any cause, explanation, result, or solution to the condition.

    System Description: {system_description}

    Loss:
    {stakeholder_name} - {loss}

    Potential System-Level States and Conditions:
    """

    response = client.chat.completions.create(model="gpt-4-turbo",
    messages=[{"role": "system", "content": "You are an expert in system safety analysis."},
              {"role": "user", "content": prompt}])

    return response.choices[0].message.content

# Example usage
system_description = "The system helps the plane to take off automatically."
stakeholder_name = "Passengers"
loss = "Loss of life or injury"

hazards = identify_system_hazards(system_description, stakeholder_name, loss)
print(hazards)
