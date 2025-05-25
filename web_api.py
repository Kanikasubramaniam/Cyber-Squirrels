#!/usr/bin/env python3
"""
Flask Web API for IAM Policy Auditor
"""

import os
import tempfile
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

# Assuming iam_auditor.py is in the same directory or accessible in PYTHONPATH
from iam_auditor import PolicyAuditor, console # console for potential server-side logging
# Also import LLM remediator check to pass to PolicyAuditor
try:
    from llm_remediator import GEMINI_CLIENT_INITIALIZED
    CAN_USE_LLM = GEMINI_CLIENT_INITIALIZED
except ImportError:
    CAN_USE_LLM = False

app = Flask(__name__)

# Configure a temporary upload folder (optional, but good practice)
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'json'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome to the IAM Policy Auditor API!",
        "usage": "Send a POST request to /audit with a JSON file to analyze an IAM policy.",
        "example_curl": "curl -X POST -F \"file=@/path/to/your_policy.json\" http://127.0.0.1:5000/audit"
    })

@app.route('/audit', methods=['POST'])
def audit_iam_policy():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(temp_file_path)
            
            # Pass enable_llm_suggestions=True if the API key is available
            # The PolicyAuditor itself will print a warning if it still can't be used.
            auditor = PolicyAuditor(enable_llm_suggestions=CAN_USE_LLM)
            
            # The load_policy method in PolicyAuditor checks for basic JSON validity 
            # and IAM structure. If it fails, it returns an empty dict, 
            # and audit_policy will subsequently return an empty list of findings.
            # For more granular error reporting from load_policy in an API context,
            # load_policy could be modified to raise exceptions.
            
            findings = auditor.audit_file(temp_file_path)
            
            if not findings:
                # This could mean the policy is secure, or the file was invalid 
                # (e.g., not JSON, or missing Version/Statement).
                # We can try to load it again to see if it was a structural issue known to load_policy
                loaded_policy_check = auditor.load_policy(temp_file_path)
                if not loaded_policy_check: # load_policy returns {} on error
                     return jsonify({"message": "Policy file is invalid or not a valid IAM policy structure (e.g., missing Version or Statement field).", "findings": []}), 400
                return jsonify({"message": "No security issues found or policy is well-configured.", "findings": []}), 200
            
            return jsonify({"message": "Audit complete.", "findings": findings}), 200
            
        except Exception as e:
            # Log the exception on the server for debugging
            console.print(f"[bold red]Server Error:[/] An error occurred: {str(e)}")
            return jsonify({"error": "An internal server error occurred during auditing."}), 500
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    else:
        return jsonify({"error": "Invalid file type. Only .json files are allowed."}), 400

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist (though mkdtemp handles this)
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True) # debug=True is for development only 