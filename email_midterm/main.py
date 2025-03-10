import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext, filedialog
import re
import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import urllib.parse
import ssl
import socket
from email.parser import BytesParser
from email import policy
import threading
import io

class EmailSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Security Tool")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        # Initialize models
        self.spam_model = None
        self.phishing_model = None
        self.vectorizer = None
        
        # Set up example datasets
        self.setup_example_datasets()
        
        # Create tabs
        self.create_tabs()
        
        # Try to load pre-trained models if they exist
        self.load_models()

    def setup_example_datasets(self):
        # Create spam dataset if it doesn't exist
        if not os.path.exists('spam_dataset.csv'):
            spam_data = {
                'text': [
                    "Congratulations! You've won a million dollars in our lottery!",
                    "Please verify your account details by clicking this link",
                    "Buy Viagra at 90% discount, limited time offer!",
                    "URGENT: Your inheritance of $5,000,000 is waiting for transfer",
                    "Your account has been suspended. Verify NOW!",
                    "FREE iPhone 15 Pro for the first 10 customers!!!",
                    "Nigerian prince needs your help to transfer $10 million",
                    "Hello, I hope this email finds you well. Here are the meeting notes from yesterday.",
                    "Thank you for your purchase. Your order #12345 has been shipped.",
                    "The quarterly report is attached for your review.",
                    "Reminder: Team meeting tomorrow at 10 AM in Conference Room B.",
                    "Your invoice is attached. Payment is due by the end of the month.",
                    "Please find attached the presentation for tomorrow's client meeting.",
                    "I've updated the project timeline. Let me know if you have questions.",
                    "Could you please review the attached document before Friday?",
                ],
                'label': [
                    1, 1, 1, 1, 1, 1, 1, 
                    0, 0, 0, 0, 0, 0, 0, 0
                ]
            }
            pd.DataFrame(spam_data).to_csv('spam_dataset.csv', index=False)
        
        # Create phishing dataset if it doesn't exist
        if not os.path.exists('phishing_dataset.csv'):
            phishing_data = {
                'text': [
                    "Dear customer, your bank account has been locked. Click http://fake-bank.com to verify your identity.",
                    "Your PayPal account has been limited. Please update your information at http://paypa1-secure.com/login",
                    "<html><form action='http://phishing.com'>Please enter your credit card: <input type='text' name='cc'></form></html>",
                    "ALERT: Suspicious activity detected on your account. Verify at http://amazon-verify.com",
                    "Your password will expire today. Reset immediately at http://office365-login.net",
                    "Your Facebook account has been compromised. Login at http://facebook-login.tk to secure it.",
                    "IRS Tax Refund: Claim your $900 at http://irs-refund.xyz",
                    "Thank you for your order #12345 from Amazon. Track your delivery here.",
                    "Your Netflix subscription has been renewed. See your billing details in your account.",
                    "Dropbox: John shared a document with you. Click to view.",
                    "Your flight confirmation: NYC to LAX on June 15, 2023.",
                    "GitHub: A new commit was pushed to your repository.",
                    "Invitation: Join our team meeting on Zoom tomorrow at 3 PM.",
                    "LinkedIn: You have 5 new connection requests.",
                    "Your subscription to The New York Times has been confirmed."
                ],
                'is_phishing': [
                    1, 1, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0
                ]
            }
            pd.DataFrame(phishing_data).to_csv('phishing_dataset.csv', index=False)

    def create_tabs(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)
        
        # Create tabs
        self.tab_spam = tk.Frame(self.notebook, bg="#f0f0f0")
        self.tab_phishing = tk.Frame(self.notebook, bg="#f0f0f0")
        self.tab_training = tk.Frame(self.notebook, bg="#f0f0f0")
        
        self.notebook.add(self.tab_spam, text="Spam Detection")
        self.notebook.add(self.tab_phishing, text="Phishing Detection")
        self.notebook.add(self.tab_training, text="Model Training")
        
        # Setup each tab
        self.setup_spam_tab()
        self.setup_phishing_tab()
        self.setup_training_tab()

    def setup_spam_tab(self):
        # Create frames
        input_frame = tk.Frame(self.tab_spam, bg="#f0f0f0")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Email input area
        tk.Label(input_frame, text="Enter email content to check for spam:", bg="#f0f0f0").pack(anchor=tk.W)
        self.spam_input = scrolledtext.ScrolledText(input_frame, height=10)
        self.spam_input.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons
        button_frame = tk.Frame(input_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(button_frame, text="Check Email", command=self.check_spam).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Load Email File", command=lambda: self.load_email_file(self.spam_input)).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear", command=lambda: self.spam_input.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        
        # Results area
        tk.Label(input_frame, text="Results:", bg="#f0f0f0").pack(anchor=tk.W, pady=(10, 0))
        self.spam_result = scrolledtext.ScrolledText(input_frame, height=8)
        self.spam_result.pack(fill=tk.BOTH, expand=True, pady=5)
        self.spam_result.config(state=tk.DISABLED)

    def setup_phishing_tab(self):
        # Create frames
        input_frame = tk.Frame(self.tab_phishing, bg="#f0f0f0")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Email input area
        tk.Label(input_frame, text="Enter email content to check for phishing:", bg="#f0f0f0").pack(anchor=tk.W)
        self.phishing_input = scrolledtext.ScrolledText(input_frame, height=10)
        self.phishing_input.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons
        button_frame = tk.Frame(input_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(button_frame, text="Check Email", command=self.check_phishing).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Load Email File", command=lambda: self.load_email_file(self.phishing_input)).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear", command=lambda: self.phishing_input.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        
        # Results area
        tk.Label(input_frame, text="Results:", bg="#f0f0f0").pack(anchor=tk.W, pady=(10, 0))
        self.phishing_result = scrolledtext.ScrolledText(input_frame, height=8)
        self.phishing_result.pack(fill=tk.BOTH, expand=True, pady=5)
        self.phishing_result.config(state=tk.DISABLED)

    def setup_training_tab(self):
        # Create frames
        training_frame = tk.Frame(self.tab_training, bg="#f0f0f0")
        training_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Spam model training
        spam_frame = tk.LabelFrame(training_frame, text="Spam Model Training", bg="#f0f0f0")
        spam_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(spam_frame, text="Dataset:", bg="#f0f0f0").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.spam_dataset_var = tk.StringVar(value="Use built-in spam dataset")
        spam_dataset_options = ttk.Combobox(spam_frame, textvariable=self.spam_dataset_var, width=30)
        spam_dataset_options['values'] = ("Use built-in spam dataset", "Custom dataset")
        spam_dataset_options.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        spam_dataset_options.current(0)
        
        self.spam_dataset_path = tk.Entry(spam_frame, width=40)
        self.spam_dataset_path.grid(row=0, column=2, padx=5, pady=5)
        self.spam_dataset_path.config(state=tk.DISABLED)
        
        self.spam_browse_btn = tk.Button(spam_frame, text="Browse", command=lambda: self.browse_dataset(self.spam_dataset_path))
        self.spam_browse_btn.grid(row=0, column=3, padx=5, pady=5)
        self.spam_browse_btn.config(state=tk.DISABLED)
        
        spam_dataset_options.bind("<<ComboboxSelected>>", lambda e: self.toggle_dataset_entry("spam"))
        
        tk.Button(spam_frame, text="Train Spam Model", command=lambda: self.train_model("spam")).grid(row=1, column=1, pady=10)
        
        # Phishing model training
        phishing_frame = tk.LabelFrame(training_frame, text="Phishing Model Training", bg="#f0f0f0")
        phishing_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(phishing_frame, text="Dataset:", bg="#f0f0f0").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.phishing_dataset_var = tk.StringVar(value="Use built-in phishing dataset")
        phishing_dataset_options = ttk.Combobox(phishing_frame, textvariable=self.phishing_dataset_var, width=30)
        phishing_dataset_options['values'] = ("Use built-in phishing dataset", "Custom dataset")
        phishing_dataset_options.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        phishing_dataset_options.current(0)
        
        self.phishing_dataset_path = tk.Entry(phishing_frame, width=40)
        self.phishing_dataset_path.grid(row=0, column=2, padx=5, pady=5)
        self.phishing_dataset_path.config(state=tk.DISABLED)
        
        self.phishing_browse_btn = tk.Button(phishing_frame, text="Browse", command=lambda: self.browse_dataset(self.phishing_dataset_path))
        self.phishing_browse_btn.grid(row=0, column=3, padx=5, pady=5)
        self.phishing_browse_btn.config(state=tk.DISABLED)
        
        phishing_dataset_options.bind("<<ComboboxSelected>>", lambda e: self.toggle_dataset_entry("phishing"))
        
        tk.Button(phishing_frame, text="Train Phishing Model", command=lambda: self.train_model("phishing")).grid(row=1, column=1, pady=10)
        
        # Status area
        tk.Label(training_frame, text="Training Status:", bg="#f0f0f0").pack(anchor=tk.W, pady=(10, 0))
        self.training_status = scrolledtext.ScrolledText(training_frame, height=10)
        self.training_status.pack(fill=tk.BOTH, expand=True, pady=5)
        self.training_status.config(state=tk.DISABLED)

    def toggle_dataset_entry(self, model_type):
        if model_type == "spam":
            if self.spam_dataset_var.get() == "Custom dataset":
                self.spam_dataset_path.config(state=tk.NORMAL)
                self.spam_browse_btn.config(state=tk.NORMAL)
            else:
                self.spam_dataset_path.config(state=tk.DISABLED)
                self.spam_browse_btn.config(state=tk.DISABLED)
        else:  # phishing
            if self.phishing_dataset_var.get() == "Custom dataset":
                self.phishing_dataset_path.config(state=tk.NORMAL)
                self.phishing_browse_btn.config(state=tk.NORMAL)
            else:
                self.phishing_dataset_path.config(state=tk.DISABLED)
                self.phishing_browse_btn.config(state=tk.DISABLED)

    def load_email_file(self, text_widget):
        file_path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=(("Email files", "*.eml"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not file_path:
            return
            
        try:
            if file_path.endswith('.eml'):
                with open(file_path, 'rb') as fp:
                    msg = BytesParser(policy=policy.default).parse(fp)
                    if msg.get_content_type() == 'text/plain':
                        text = msg.get_content()
                    else:
                        # Handle multipart messages
                        text = ""
                        for part in msg.iter_parts():
                            if part.get_content_type() == 'text/plain':
                                text += part.get_content()
            else:
                with open(file_path, 'r', encoding='utf-8') as file:
                    text = file.read()
                    
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")

    def browse_dataset(self, entry_widget):
        file_path = filedialog.askopenfilename(
            title="Select Dataset",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    def update_text_widget(self, widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def load_models(self):
        try:
            if os.path.exists('spam_model.pkl'):
                with open('spam_model.pkl', 'rb') as f:
                    self.spam_model = pickle.load(f)
                self.update_text_widget(self.training_status, "Spam model loaded successfully!\n")
                
            if os.path.exists('phishing_model.pkl'):
                with open('phishing_model.pkl', 'rb') as f:
                    self.phishing_model = pickle.load(f)
                self.update_text_widget(self.training_status, self.training_status.get("1.0", tk.END) + "Phishing model loaded successfully!\n")
                
            if os.path.exists('vectorizer.pkl'):
                with open('vectorizer.pkl', 'rb') as f:
                    self.vectorizer = pickle.load(f)
                self.update_text_widget(self.training_status, self.training_status.get("1.0", tk.END) + "Vectorizer loaded successfully!\n")
            
            # If models don't exist, offer to train them
            if not os.path.exists('spam_model.pkl') or not os.path.exists('phishing_model.pkl'):
                self.update_text_widget(self.training_status, 
                    self.training_status.get("1.0", tk.END) + 
                    "\nNo pre-trained models found. You can train models using the built-in datasets by clicking the Train buttons.\n")
        except Exception as e:
            self.update_text_widget(self.training_status, f"Error loading models: {str(e)}\n")

    def check_spam(self):
        email_content = self.spam_input.get("1.0", tk.END).strip()
        
        if not email_content:
            messagebox.showerror("Error", "Please enter email content!")
            return
            
        if self.spam_model is None or self.vectorizer is None:
            messagebox.showwarning("Warning", "Spam detection model not trained. Please train the model first.")
            return
        
        try:
            # Feature 1: Content-based spam detection
            features = self.vectorizer.transform([email_content])
            prediction = self.spam_model.predict(features)[0]
            probability = self.spam_model.predict_proba(features)[0]
            
            result = f"SPAM DETECTION RESULTS:\n\n"
            result += f"Classification: {'SPAM' if prediction == 1 else 'HAM (Not Spam)'}\n"
            result += f"Confidence: {probability[1]*100:.2f}%\n\n"
            
            # Additional analysis
            spam_indicators = []
            
            # Check for common spam phrases
            spam_phrases = [
                "viagra", "lottery", "winner", "free money", "million dollars",
                "nigerian prince", "claim your prize", "bank details", "urgent",
                "password", "account suspended", "verify your account"
            ]
            
            for phrase in spam_phrases:
                if phrase in email_content.lower():
                    spam_indicators.append(f"Contains spam phrase: '{phrase}'")
            
            # Check for excessive use of capital letters
            capitals_ratio = sum(1 for c in email_content if c.isupper()) / max(len(email_content), 1)
            if capitals_ratio > 0.3:
                spam_indicators.append(f"Excessive capital letters ({capitals_ratio*100:.1f}%)")
            
            # Check for excessive punctuation
            punctuation_ratio = sum(1 for c in email_content if c in "!?$*") / max(len(email_content), 1)
            if punctuation_ratio > 0.05:
                spam_indicators.append(f"Excessive punctuation ({punctuation_ratio*100:.1f}%)")
            
            if spam_indicators:
                result += "Suspicious indicators found:\n"
                for indicator in spam_indicators:
                    result += f"- {indicator}\n"
            else:
                result += "No specific spam indicators found.\n"
                
            self.update_text_widget(self.spam_result, result)
            
        except Exception as e:
            self.update_text_widget(self.spam_result, f"Error analyzing email: {str(e)}")

    def check_phishing(self):
        email_content = self.phishing_input.get("1.0", tk.END).strip()
        
        if not email_content:
            messagebox.showerror("Error", "Please enter email content!")
            return
            
        if self.phishing_model is None or self.vectorizer is None:
            # If no model is trained, we'll still perform rule-based detection
            messagebox.showinfo("Info", "Phishing model not trained. Using rule-based detection only.")
            prediction = 0
            probability = [0.5, 0.5]
        else:
            # Feature 2: Machine learning based phishing detection
            features = self.vectorizer.transform([email_content])
            prediction = self.phishing_model.predict(features)[0]
            probability = self.phishing_model.predict_proba(features)[0]
        
        try:
            result = f"PHISHING DETECTION RESULTS:\n\n"
            
            # Extract URLs
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'
            urls = re.findall(url_pattern, email_content)
            
            # Extract potential login forms
            form_pattern = r'<form.*?>.*?</form>'
            forms = re.findall(form_pattern, email_content, re.DOTALL | re.IGNORECASE)
            
            # Check for suspicious links (mismatch between text and URL)
            link_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1'
            links = re.findall(link_pattern, email_content, re.IGNORECASE)
            
            # Check for password or credential requests
            credential_patterns = [
                r'password', r'login', r'sign in', r'verify your account',
                r'update your information', r'credit card', r'ssn', r'social security'
            ]
            credential_requests = []
            for pattern in credential_patterns:
                if re.search(pattern, email_content, re.IGNORECASE):
                    credential_requests.append(pattern)
            
            # Check for sense of urgency
            urgency_patterns = [
                r'urgent', r'immediate action', r'within 24 hours', r'account.*?suspend',
                r'limited time', r'act now', r'immediately'
            ]
            urgency_indicators = []
            for pattern in urgency_patterns:
                if re.search(pattern, email_content, re.IGNORECASE):
                    urgency_indicators.append(pattern)
            
            # Calculate phishing score based on indicators
            phishing_score = 0
            
            if urls:
                result += f"Found {len(urls)} URLs:\n"
                for url in urls[:3]:  # Limit display to first 3
                    result += f"- {url}\n"
                    
                    # Check for suspicious URL characteristics
                    parsed_url = urllib.parse.urlparse(url)
                    if any(c in parsed_url.netloc for c in ['@', '..']):
                        result += "  ⚠️ Suspicious URL format\n"
                        phishing_score += 1
                    
                    # Check for IP address instead of domain
                    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                    if re.match(ip_pattern, parsed_url.netloc):
                        result += "  ⚠️ IP address used instead of domain name\n"
                        phishing_score += 2
                
                if len(urls) > 3:
                    result += f"... and {len(urls) - 3} more\n"
                result += "\n"
            
            if forms:
                result += f"Found {len(forms)} form elements (potential credential harvesting)\n"
                phishing_score += len(forms) * 2
            
            if links:
                mismatched_links = 0
                for _, href in links:
                    if 'login' in href.lower() or 'account' in href.lower():
                        mismatched_links += 1
                
                if mismatched_links > 0:
                    result += f"Found {mismatched_links} suspicious links\n"
                    phishing_score += mismatched_links
            
            if credential_requests:
                result += "Requests for sensitive information:\n"
                for req in credential_requests:
                    result += f"- Contains '{req}'\n"
                phishing_score += len(credential_requests) * 1.5
                result += "\n"
            
            if urgency_indicators:
                result += "Urgency indicators:\n"
                for indicator in urgency_indicators:
                    result += f"- Contains '{indicator}'\n"
                phishing_score += len(urgency_indicators)
                result += "\n"
            
            # Feature 3: Enhanced security checks (SSL/domain verification)
            spoof_indicators = []
            for url in urls:
                try:
                    parsed_url = urllib.parse.urlparse(url)
                    if parsed_url.netloc:
                        # Check if domain exists
                        try:
                            socket.gethostbyname(parsed_url.netloc)
                        except:
                            spoof_indicators.append(f"Domain does not exist: {parsed_url.netloc}")
                            phishing_score += 3
                except:
                    pass
            
            if spoof_indicators:
                result += "Domain verification failures:\n"
                for indicator in spoof_indicators:
                    result += f"- {indicator}\n"
                result += "\n"
            
            # Normalize phishing score to percentage
            max_score = 10
            phishing_percentage = min(100, (phishing_score / max_score) * 100)
            
            # Final classification
            if self.phishing_model is not None:
                result += f"Machine learning model classification: {'PHISHING' if prediction == 1 else 'LEGITIMATE'}\n"
                result += f"ML Model confidence: {probability[1]*100:.2f}%\n\n"
            
            result += f"Rule-based phishing score: {phishing_percentage:.1f}%\n"
            
            if phishing_percentage > 70 or (self.phishing_model is not None and probability[1] > 0.7):
                result += "VERDICT: HIGH RISK - Very likely to be a phishing attempt\n"
            elif phishing_percentage > 40 or (self.phishing_model is not None and probability[1] > 0.4):
                result += "VERDICT: MODERATE RISK - Contains suspicious elements\n"
            else:
                result += "VERDICT: LOW RISK - Likely legitimate\n"
                
            self.update_text_widget(self.phishing_result, result)
            
        except Exception as e:
            self.update_text_widget(self.phishing_result, f"Error analyzing email: {str(e)}")

    def train_model(self, model_type):
        dataset_path = None
        
        if model_type == "spam":
            if self.spam_dataset_var.get() == "Use built-in spam dataset":
                dataset_path = 'spam_dataset.csv'
            else:
                dataset_path = self.spam_dataset_path.get().strip()
                if not dataset_path:
                    messagebox.showerror("Error", "Please select a spam dataset file!")
                    return
        else:  # phishing
            if self.phishing_dataset_var.get() == "Use built-in phishing dataset":
                dataset_path = 'phishing_dataset.csv'
            else:
                dataset_path = self.phishing_dataset_path.get().strip()
                if not dataset_path:
                    messagebox.showerror("Error", "Please select a phishing dataset file!")
                    return
                
        # Start training in a separate thread
        threading.Thread(target=self._train_model_thread, args=(model_type, dataset_path)).start()
    
    def _train_model_thread(self, model_type, dataset_path):
        try:
            self.update_text_widget(self.training_status, f"Loading {model_type} dataset from {dataset_path}...\n")
            
            # Load dataset
            df = pd.read_csv(dataset_path)
            
            # Check required columns
            if model_type == "spam":
                required_cols = ["text", "label"]  # Assuming dataset has these columns
            else:
                required_cols = ["text", "is_phishing"]  # Adjust column names as needed
                
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                error_msg = f"Missing required columns in dataset: {', '.join(missing_cols)}\n"
                self.update_text_widget(self.training_status, error_msg)
                return
                
            # Prepare data
            X = df['text'].values
            if model_type == "spam":
                y = df['label'].values
            else:
                y = df['is_phishing'].values
                
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Create and train vectorizer if not exists
            if self.vectorizer is None:
                self.update_text_widget(self.training_status, "Creating TF-IDF vectorizer...\n")
                self.vectorizer = TfidfVectorizer(max_features=5000)
                X_train_features = self.vectorizer.fit_transform(X_train)
            else:
                X_train_features = self.vectorizer.transform(X_train)
                
            # Create and train model
            self.update_text_widget(self.training_status, f"Training {model_type} model...\n")
            
            if model_type == "spam":
                self.spam_model = MultinomialNB()
                self.spam_model.fit(X_train_features, y_train)
                model_to_save = self.spam_model
                model_filename = "spam_model.pkl"
            else:
                self.phishing_model = MultinomialNB()
                self.phishing_model.fit(X_train_features, y_train)
                model_to_save = self.phishing_model
                model_filename = "phishing_model.pkl"
                
            # Evaluate model
            X_test_features = self.vectorizer.transform(X_test)
            y_pred = model_to_save.predict(X_test_features)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Save models
            with open(model_filename, 'wb') as f:
                pickle.dump(model_to_save, f)
                
            if not os.path.exists('vectorizer.pkl'):
                with open('vectorizer.pkl', 'wb') as f:
                    pickle.dump(self.vectorizer, f)
                    
            # Update status
            report = classification_report(y_test, y_pred)
            status_text = (
                f"{model_type.capitalize()} model trained successfully!\n"
                f"Accuracy: {accuracy:.2f}\n\n"
                f"Classification Report:\n{report}\n"
                f"Model saved as {model_filename}\n"
            )
            self.update_text_widget(self.training_status, status_text)
            
        except Exception as e:
            error_msg = f"Error training {model_type} model: {str(e)}\n"
            self.update_text_widget(self.training_status, error_msg)


def main():
    root = tk.Tk()
    app = EmailSecurityApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()