#!/usr/bin/env python3
"""
LLM Remediator - Uses Google's Gemini LLM to suggest safer IAM policy alternatives.
"""

import os
import json
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# --- WARNING: HARDCODED API KEY --- #
# Hardcoding API keys is a security risk and not recommended for production
# or shared code. Consider using environment variables or a secrets manager.
# For development/testing purposes only as per user request.
HARDCODED_GOOGLE_API_KEY = "AIzaSyCw1dKWQc6Ri_Dj9m1FAK7oIIt-847mbh4"
# --- END WARNING --- #

GEMINI_CLIENT_INITIALIZED = False

if HARDCODED_GOOGLE_API_KEY:
    try:
        genai.configure(api_key=HARDCODED_GOOGLE_API_KEY)
        GEMINI_CLIENT_INITIALIZED = True
        print("LLM Remediator: Gemini client configured successfully using hardcoded API key.")
    except Exception as e:
        print(f"LLM Remediator: Error configuring Gemini client with hardcoded API key: {e}")
else:
    # This case should ideally not be hit if the key is truly hardcoded above
    print("LLM Remediator: Hardcoded API key is empty. LLM suggestions will be skipped.")

# Safety settings to block potentially harmful content - adjust as needed
# For this use case (code generation/suggestion), we might be a bit more permissive 
# but still block overtly harmful content.
SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
}

def get_llm_suggestion(iam_statement_json_str: str, risk_description: str, model_name: str = "gemini-1.5-flash") -> dict | None:
    """
    Gets a safer IAM policy statement suggestion from Gemini.

    Args:
        iam_statement_json_str: The risky IAM policy statement as a JSON string.
        risk_description: A description of the identified risk.
        model_name: The Gemini model to use (user specified "gemini-1.5-flash").

    Returns:
        A dictionary containing "suggested_statement" (dict or list) and "explanation" (str),
        or None if an error occurs or the API key is not available/client not initialized.
    """
    if not GEMINI_CLIENT_INITIALIZED:
        print("LLM Remediator: Gemini client not initialized. Skipping LLM suggestion.")
        return None

    prompt = f"""
You are an expert AWS IAM security advisor. Your task is to analyze a potentially risky IAM policy statement and provide a safer alternative.
The alternative should strictly adhere to the principle of least privilege.

Original Risky IAM Statement (JSON format):
```json
{iam_statement_json_str}
```

Identified Risk:
{risk_description}

Please provide your response as a single, valid JSON object with the following two keys ONLY:
1.  "suggested_statement": A valid JSON IAM policy statement object (or an array of statement objects if multiple are needed for the fix). This statement should be the safer alternative. Ensure this is valid JSON that can be directly embedded into an IAM policy's "Statement" array.
2.  "explanation": A concise explanation of why your suggested statement is safer, how it addresses the identified risk, and how it applies the principle of least privilege.

Your entire response MUST be a single JSON object. Do not include any other text, markdown, or explanations outside of this JSON structure. Start your response with `{{` and end with `}}`.

Example of the JSON structure for your response:
```json
{{
  "suggested_statement": {{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::examplebucket/specific-path/*",
    "Condition": {{
      "StringEquals": {{
        "aws:SourceIp": "192.0.2.0/24"
      }}
    }}
  }},
  "explanation": "The original statement was too broad. The suggested statement limits actions to s3:GetObject, specifies a more precise resource path, and adds an IP-based condition to restrict access, thereby following the principle of least privilege."
}}
```
"""

    try:
        print(f"LLM Remediator (Gemini): Requesting suggestion for risk: {risk_description[:100]}...")
        model = genai.GenerativeModel(
            model_name,
            safety_settings=SAFETY_SETTINGS,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json" # Request JSON output
            )
        )
        response = model.generate_content(prompt)
        
        # Debug: Print raw response text before parsing, useful if JSON is malformed
        # print(f"LLM Remediator (Gemini): Raw response text: {response.text[:500]}")

        if response.text:
            # Gemini with response_mime_type="application/json" should return a clean JSON string.
            # However, it might be nested or have leading/trailing characters sometimes, so clean it.
            # A common pattern is ```json\n{...}\n``` so we try to extract the JSON part.
            cleaned_response_text = response.text.strip()
            if cleaned_response_text.startswith("```json"):
                cleaned_response_text = cleaned_response_text[7:] # Remove ```json\n
            if cleaned_response_text.endswith("```"):
                cleaned_response_text = cleaned_response_text[:-3] # Remove ```
            cleaned_response_text = cleaned_response_text.strip() # Ensure no leading/trailing whitespace

            try:
                suggestion_data = json.loads(cleaned_response_text)
            except json.JSONDecodeError as e:
                print(f"LLM Remediator (Gemini): Error decoding LLM JSON response: {e}. Trying to find JSON object within the text.")
                # Fallback: try to find a JSON object within the text if direct parsing fails
                try:
                    start_index = cleaned_response_text.find('{')
                    end_index = cleaned_response_text.rfind('}') + 1
                    if start_index != -1 and end_index != 0:
                        json_str_candidate = cleaned_response_text[start_index:end_index]
                        suggestion_data = json.loads(json_str_candidate)
                    else:
                        raise # Reraise if no brackets found
                except Exception as fallback_e:
                    print(f"LLM Remediator (Gemini): Fallback JSON extraction also failed: {fallback_e}")
                    print(f"LLM Raw Response: {response.text[:500]}")
                    return None

            if "suggested_statement" in suggestion_data and "explanation" in suggestion_data:
                print("LLM Remediator (Gemini): Suggestion received and parsed.")
                return suggestion_data
            else:
                print("LLM Remediator (Gemini): Error - LLM response missing 'suggested_statement' or 'explanation' key.")
                print(f"LLM Parsed Response: {suggestion_data}")
                return None
        else:
            print("LLM Remediator (Gemini): Error - Empty response from LLM.")
            if response.prompt_feedback:
                 print(f"LLM Remediator (Gemini): Prompt Feedback: {response.prompt_feedback}")
            return None

    except Exception as e:
        print(f"LLM Remediator (Gemini): An unexpected error occurred: {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'prompt_feedback'): # For some API errors
            print(f"Prompt Feedback: {e.response.prompt_feedback}")
        return None

if __name__ == '__main__':
    if GEMINI_CLIENT_INITIALIZED:
        print("Testing LLM Remediator (Gemini) with hardcoded key...")
        example_statement_str = json.dumps({
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        })
        example_risk = "The policy grants full administrative access via wildcard in Action and Resource, violating the principle of least privilege."
        
        suggestion = get_llm_suggestion(example_statement_str, example_risk)
        
        if suggestion:
            print("\n--- LLM Suggestion (Gemini) ---")
            print("Suggested Statement:")
            print(json.dumps(suggestion.get("suggested_statement"), indent=2))
            print("\nExplanation:")
            print(suggestion.get("explanation"))
            print("-------------------------------")
        else:
            print("Failed to get LLM suggestion from Gemini.")
    else:
        print("Skipping LLM Remediator (Gemini) test: Client not initialized (check hardcoded API key and configuration).") 