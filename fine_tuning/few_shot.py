import json
import os

"""Few shotting creates a new model that is embedded with examples of ideal output. A new modelfile is generated with 
embeded examples in the system prompt. """

class LlamaFineTuner:
    def __init__(self, training_file="training_data.jsonl"):
        self.training_file = training_file
        self.model_name = "wazuh-enrich-fewshot" 

    def shot_prompting(self):
        examples = []
        with open(self.training_file, 'r') as f:
            for line in f:
                examples.append(json.loads(line))
        
        # Create few-shot prompt with actual examples
        few_shot_examples = ""
        for i, example in enumerate(examples[:5]):  
            user_content = example["messages"][0]["content"]
            assistant_content = example["messages"][1]["content"]
            
            # Extract just the alert JSON part
            alert_start = user_content.find("Alert JSON:")
            alert_part = user_content[alert_start:].split("YARA Matches:")[0].replace("Alert JSON:", "").strip()
            
            few_shot_examples += f"\\n\\nExample {i+1}:\\nAlert: {alert_part}\\nResponse: {assistant_content}"
        
        prompt_template = """You are a security enrichment assistant.
ALWAYS respond with ONLY a single valid JSON object. NO markdown, NO newlines, NO extra text. Output should be raw JSON. Example:
{{"summary_text": "Example summary.", "tags": ["pam", "authentication_success"], "risk_score": 0.2, "false_positive_likelihood": 0.05, "alert_category": "Authentication", "remediation_steps": ["Review sudoers configuration."], "related_cves": [], "external_refs": []}}
INSTRUCTIONS:
- All property names and string values MUST use double quotes.
- For unknown fields, use "", 0, 0.0, or [].
- Output only these fields, in this order.
- DO NOT add any extra fields, explanation, markdown, or whitespace.
- Do NOT wrap the JSON in single or double quotes.
- Do NOT output the JSON as a string. Output only the raw JSON object.
- If you cannot comply, output: {{"summary_text": "ERROR", ...}}
Learn from these examples:{}
Always respond with valid JSON only. No explanations.
"""
        
        prompt = prompt_template.format(few_shot_examples)
        
        # Edit parameters to customize fewshot model
        modelfile_content = f"""FROM llama3:8b

PARAMETER temperature 0.05
PARAMETER top_p 0.8
PARAMETER top_c 0.3
PARAMETER num_ctx 6144

SYSTEM \"\"\"{prompt}\"\"\"
"""
        # Save modelfile
        script_dir = os.path.dirname(os.path.abspath(__file__))
        modelfile_path = os.path.join(script_dir, f"Modelfile.wazuh-enrich-fewshot")
        with open(modelfile_path, 'w') as f:
            f.write(modelfile_content)

def main():
    tuner = LlamaFineTuner()
    tuner.shot_prompting()

if __name__ == "__main__":
    main()