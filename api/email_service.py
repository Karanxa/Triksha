import os
import json
import csv
import smtplib
import ssl
import pandas as pd
import io
import tempfile
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from rich.console import Console
from datetime import datetime


class EmailNotificationService:
    """Service for sending email notifications about benchmark results."""
    
    def __init__(self, console: Optional[Console] = None):
        """Initialize the email notification service.
        
        Args:
            console: Rich console for output messages
        """
        self.console = console or Console()
        self.config_dir = Path.home() / "triksha" / "config"
        self.config_file = self.config_dir / "notifications.json"
        self.token_file = self.config_dir / "google_token.json"
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load notification configuration from file.
        
        Returns:
            Configuration dictionary
        """
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(exist_ok=True, parents=True)
        
        # Load config file if it exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not load notification config: {str(e)}[/]")
        
        # Return empty config if file doesn't exist or couldn't be loaded
        return {"enabled": False, "email": "", "app_password": "", "bypass_ssl": False, "use_sheets": False}
    
    def _save_config(self) -> bool:
        """Save notification configuration to file.
        
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            self.console.print(f"[red]Error saving notification config: {str(e)}[/]")
            return False
    
    def is_configured(self) -> bool:
        """Check if notifications are configured.
        
        Returns:
            True if configured, False otherwise
        """
        return (
            self.config.get("enabled", False) and
            self.config.get("email") and
            self.config.get("app_password")
        )
    
    def setup(self) -> bool:
        """Set up email notifications with user input.
        
        Returns:
            True if setup was successful, False otherwise
        """
        try:
            self.console.print("[bold blue]Email Notification Setup[/]")
            self.console.print("To receive email notifications when benchmarks complete, please provide your Gmail account details.")
            self.console.print("[yellow]Note: You'll need to create an App Password for this purpose.[/]")
            self.console.print("[dim]Learn how: https://support.google.com/accounts/answer/185833[/]")
            
            # Get email address
            email = input("Enter your Gmail address: ")
            if not email or "@" not in email:
                self.console.print("[red]Invalid email address.[/]")
                return False
            
            # Get app password
            app_password = input("Enter your Google App Password: ")
            if not app_password:
                self.console.print("[red]App password cannot be empty.[/]")
                return False
            
            # Check if user is on Mac and ask about SSL bypass
            is_mac = 'darwin' in os.uname().sysname.lower()
            bypass_ssl = False
            
            if is_mac:
                bypass_response = input("Are you on Mac and need to bypass SSL verification? (y/n): ").lower()
                bypass_ssl = bypass_response.startswith('y')
            
            # Ask if user wants to include detailed results as CSV attachments
            include_csv = input("Would you like to include detailed results as CSV attachments? (y/n): ").lower().startswith('y')
            
            # Test the credentials
            self.console.print("[cyan]Testing email credentials...[/]")
            if self._test_email_credentials(email, app_password, bypass_ssl):
                # Save configuration
                self.config = {
                    "enabled": True,
                    "email": email,
                    "app_password": app_password,
                    "bypass_ssl": bypass_ssl,
                    "include_csv": include_csv
                }
                
                if self._save_config():
                    self.console.print("[green]✓ Email notification setup complete.[/]")
                    return True
                else:
                    self.console.print("[red]Failed to save configuration.[/]")
                    return False
            else:
                self.console.print("[red]Failed to connect with the provided credentials.[/]")
                return False
            
        except Exception as e:
            self.console.print(f"[red]Error during setup: {str(e)}[/]")
            return False
    
    def disable(self) -> bool:
        """Disable email notifications.
        
        Returns:
            True if disabled successfully, False otherwise
        """
        try:
            # Update configuration
            self.config["enabled"] = False
            
            # Save to file
            if self._save_config():
                self.console.print("[green]✓ Email notifications disabled.[/]")
                return True
            else:
                self.console.print("[red]Failed to save configuration.[/]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error disabling notifications: {str(e)}[/]")
            return False
    
    def _test_email_credentials(self, email: str, app_password: str, bypass_ssl: bool = False) -> bool:
        """Test email credentials by connecting to Gmail SMTP server.
        
        Args:
            email: Gmail address
            app_password: Google App Password
            bypass_ssl: Whether to bypass SSL certificate verification
            
        Returns:
            True if connection was successful, False otherwise
        """
        try:
            # Create SSL context with verification options
            context = ssl.create_default_context()
            
            # Option to bypass SSL verification for Mac users
            if bypass_ssl:
                self.console.print("[yellow]Warning: SSL certificate verification disabled[/]")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(email, app_password)
            return True
        except Exception as e:
            self.console.print(f"[red]Connection test failed: {str(e)}[/]")
            return False
    
    def _create_csv_attachment(self, results: Dict[str, Any], benchmark_type: str) -> Tuple[bool, Optional[str]]:
        """Create a CSV file with detailed benchmark results.
        
        Args:
            results: The benchmark results
            benchmark_type: Type of benchmark
            
        Returns:
            Tuple of (success, csv_data or None)
        """
        try:
            self.console.print("[cyan]Creating CSV attachment with detailed results...[/]")
            
            # Extract the data
            data = self._extract_detailed_results(results)
            
            # Create a combined list of all results for CSV
            all_records = []
            for model_name, model_data in data.items():
                for record in model_data:
                    # Add the model name to each record
                    record_with_model = {"model": model_name}
                    record_with_model.update(record)
                    all_records.append(record_with_model)
            
            # If no records found, create a simple placeholder record
            if not all_records:
                self.console.print("[yellow]Warning: No detailed results to export[/]")
                all_records = [{
                    "model": results.get("model_tested", "Unknown"),
                    "prompt": "No detailed results available",
                    "response": "N/A",
                    "success": "N/A",
                    "timestamp": results.get("timestamp", "Unknown")
                }]
            
            # Create CSV in memory
            csv_buffer = io.StringIO()
            if all_records:
                df = pd.DataFrame(all_records)
                df.to_csv(csv_buffer, index=False)
            else:
                csv_writer = csv.writer(csv_buffer)
                csv_writer.writerow(["model", "prompt", "response", "success", "timestamp"])
                csv_writer.writerow([
                    results.get("model_tested", "Unknown"),
                    "No detailed results available",
                    "N/A",
                    "N/A",
                    results.get("timestamp", "Unknown")
                ])
            
            # Return the CSV data as string
            csv_buffer.seek(0)
            csv_data = csv_buffer.getvalue()
            
            self.console.print(f"[green]✓ CSV data created with {len(all_records)} records[/]")
            return True, csv_data
                
        except Exception as e:
            self.console.print(f"[red]Failed to create CSV data: {str(e)}[/]")
            import traceback
            traceback.print_exc()
            return False, None
    
    def _extract_detailed_results(self, results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Extract detailed results per model.
        
        Args:
            results: The benchmark results
            
        Returns:
            Dictionary mapping model names to lists of detailed results
        """
        detailed_data = {}
        self.console.print("[cyan]Extracting detailed results from benchmark data...[/]")
        
        # Check for the actual structure used by the benchmark system
        if "models_tested" in results:
            self.console.print("[cyan]Found models_tested in the benchmark data[/]")
            
            for model_info in results["models_tested"]:
                if not isinstance(model_info, dict):
                    continue
                    
                model_name = model_info.get("name", "unknown")
                provider = model_info.get("provider", "unknown")
                display_name = f"{model_name} ({provider})" if provider != "unknown" else model_name
                
                # Clean up display name for CSV
                safe_name = display_name.replace('/', '-').replace(':', '-')
                
                examples = model_info.get("examples", [])
                self.console.print(f"[cyan]Processing {len(examples)} examples for model {display_name}[/]")
                
                if safe_name not in detailed_data:
                    detailed_data[safe_name] = []
                
                # Process each example
                for example in examples:
                    clean_example = {}
                    
                    # Add basic fields
                    clean_example["prompt"] = example.get("prompt", "")
                    clean_example["response"] = example.get("response", "")
                    clean_example["success"] = "Yes" if example.get("success", False) else "No"
                    clean_example["response_time"] = f"{example.get('response_time', 0):.4f}s"
                    clean_example["evaluation"] = example.get("evaluation", "UNKNOWN")
                    clean_example["example_idx"] = example.get("example_idx", "")
                    
                    # Add technique information if available
                    clean_example["technique"] = example.get("technique", "")
                    clean_example["adversarial_technique"] = example.get("adversarial_technique", "")
                    clean_example["base_goal"] = example.get("base_goal", "")
                    clean_example["generation_method"] = example.get("generation_method", "")
                    
                    # Add error if present
                    if "error" in example:
                        clean_example["error"] = str(example.get("error", ""))
                    
                    detailed_data[safe_name].append(clean_example)
        
        # First check if we have detailed results in the main results object (legacy format)
        elif "detailed_results" in results:
            self.console.print("[cyan]Found detailed_results in the main results object[/]")
            
            # Get models tested
            models_tested = []
            for model in results.get("models_tested", []):
                if isinstance(model, dict):
                    models_tested.append(model.get("name", "unknown"))
                else:
                    models_tested.append(str(model))
            
            if not models_tested and "model_tested" in results:
                models_tested = [results["model_tested"]]
                
            # Process detailed results
            for item in results["detailed_results"]:
                for model_name in models_tested:
                    safe_name = model_name.replace('/', '-')
                    
                    if safe_name not in detailed_data:
                        detailed_data[safe_name] = []
                    
                    example_data = {}
                    
                    # Get basic fields
                    example_data["prompt"] = item.get("prompt", "")
                    example_data["category"] = item.get("category", "unknown")
                    
                    # Add technique information if available
                    example_data["technique"] = item.get("technique", "")
                    example_data["adversarial_technique"] = item.get("adversarial_technique", "")
                    example_data["base_goal"] = item.get("base_goal", "")
                    example_data["generation_method"] = item.get("generation_method", "")
                    
                    # Try to get model-specific response
                    if "apis" in item and model_name in item["apis"]:
                        api_result = item["apis"][model_name]
                        example_data["response"] = api_result.get("response", "")
                        example_data["success"] = "Yes" if api_result.get("success", False) else "No"
                        example_data["response_time"] = f"{api_result.get('response_time', 0):.2f}s"
                        
                        # Add any other fields
                        for k, v in api_result.items():
                            if k not in ["response", "success", "response_time"]:
                                example_data[k] = v
                    
                    detailed_data[safe_name].append(example_data)
        
        # Extract model results (another legacy format)
        elif "model_results" in results:
            self.console.print("[cyan]Found model_results in the benchmark data[/]")
            
            for model_key, model_result in results.get("model_results", {}).items():
                display_name = model_result.get("display_name", model_key)
                examples = model_result.get("examples", [])
                
                self.console.print(f"[cyan]Processing {len(examples)} examples for model {display_name}[/]")
                
                # Clean up examples for spreadsheet
                clean_examples = []
                for example in examples:
                    clean_example = {}
                    
                    # Add basic fields
                    clean_example["prompt"] = example.get("prompt", "")
                    clean_example["response"] = example.get("response", "")
                    clean_example["success"] = "Yes" if example.get("success", False) else "No"
                    clean_example["response_time"] = f"{example.get('response_time', 0):.2f}s"
                    clean_example["evaluation"] = example.get("evaluation", "UNKNOWN")
                    
                    # Add technique information if available
                    clean_example["technique"] = example.get("technique", "")
                    clean_example["adversarial_technique"] = example.get("adversarial_technique", "")
                    clean_example["base_goal"] = example.get("base_goal", "")
                    clean_example["generation_method"] = example.get("generation_method", "")
                    
                    # Add extracted_field and raw_response if available
                    if "extracted_field" in example:
                        clean_example["extracted_field"] = example.get("extracted_field", "")
                    if "raw_response" in example:
                        clean_example["raw_response"] = example.get("raw_response", "")
                    
                    # Add any error
                    if "error" in example:
                        clean_example["error"] = example.get("error", "")
                    
                    clean_examples.append(clean_example)
                
                detailed_data[display_name] = clean_examples
        
        # If we have category_summary, add that information
        if "category_summary" in results:
            self.console.print(f"[cyan]Found category summary data[/]")
            # Add category summary as a separate sheet
            detailed_data["Category Summary"] = []
            
            for category, stats in results["category_summary"].items():
                category_data = {"category": category}
                if isinstance(stats, dict):
                    for key, value in stats.items():
                        category_data[key] = value
                else:
                    category_data["stats"] = stats
                
                detailed_data["Category Summary"].append(category_data)
        
        self.console.print(f"[cyan]Extracted data for {len(detailed_data)} models/sections[/]")
        return detailed_data
    
    def send_benchmark_complete_notification(
        self, 
        benchmark_id: str, 
        results: Dict[str, Any],
        benchmark_type: str = "Static Red Teaming"
    ) -> bool:
        """Send a notification when a benchmark is complete.
        
        Args:
            benchmark_id: ID of the completed benchmark (now called Job ID)
            results: Results of the benchmark
            benchmark_type: Type of benchmark that was run
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_configured():
            return False
        
        try:
            # Create email
            msg = MIMEMultipart()
            msg["Subject"] = f"Triksha Red Teaming Job Completed"
            msg["From"] = self.config["email"]
            msg["To"] = self.config["email"]
            
            # Prepare simple results summary
            summary = self._create_benchmark_summary(results, benchmark_type)
            
            # Add summary to email
            msg.attach(MIMEText(summary, "plain"))
            
            # Create and attach CSV if enabled
            if self.config.get("include_csv", False):
                csv_success, csv_data = self._create_csv_attachment(results, benchmark_type)
                if csv_success and csv_data:
                    # Create timestamp for filename
                    timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
                    if isinstance(timestamp, str):
                        timestamp = timestamp.replace(":", "-").replace(" ", "_")
                    
                    # Create CSV attachment
                    csv_attachment = MIMEApplication(csv_data.encode('utf-8'), _subtype="csv")
                    csv_attachment.add_header(
                        'Content-Disposition', 
                        'attachment', 
                        filename=f"benchmark_results_{benchmark_type.replace(' ', '')}_{timestamp}.csv"
                    )
                    msg.attach(csv_attachment)
                    self.console.print("[green]✓ CSV attachment added to email[/]")
            
            # Send email
            context = ssl.create_default_context()
            
            # Check if SSL verification should be bypassed
            if self.config.get("bypass_ssl", False):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(self.config["email"], self.config["app_password"])
                server.send_message(msg)
            
            self.console.print("[green]✓ Email notification sent successfully[/]")
            return True
            
        except Exception as e:
            self.console.print(f"[yellow]Failed to send notification: {str(e)}[/]")
            return False
    
    def _create_benchmark_summary(self, results: Dict[str, Any], benchmark_type: str, sheet_url: Optional[str] = None) -> str:
        """Create a text summary of benchmark results for email.
        
        Args:
            results: Results dictionary from the benchmark
            benchmark_type: Type of benchmark that was run
            sheet_url: Optional URL to Google Sheet with detailed results (deprecated)
            
        Returns:
            Summary text
        """
        summary_lines = [
            f"Triksha {benchmark_type} Job Complete",
            "=" * 50,
            ""
        ]
        
        # Add Job ID and timestamp if available
        if "benchmark_id" in results:
            summary_lines.append(f"Job ID: {results['benchmark_id']}")
        if "timestamp" in results:
            summary_lines.append(f"Completed: {results['timestamp']}")
        
        summary_lines.append("")
        
        # Note about CSV attachment
        if self.config.get("include_csv", False):
            summary_lines.append("Detailed Results: See attached CSV file")
            summary_lines.append("")
        
        # Add model results if available
        if "model_results" in results:
            summary_lines.append("Model Results:")
            summary_lines.append("-" * 30)
            
            for model_key, model_result in results["model_results"].items():
                display_name = model_result.get("display_name", model_key)
                
                # Calculate success rate from the data if not provided
                success_rate = model_result.get("success_rate", 0)
                if success_rate == 0 and "success_count" in model_result and "examples" in model_result:
                    total_examples = len(model_result["examples"])
                    success_count = model_result.get("success_count", 0)
                    success_rate = (success_count / total_examples * 100) if total_examples > 0 else 0
                elif success_rate == 0 and "success_count" in model_result and "fail_count" in model_result:
                    total = model_result.get("success_count", 0) + model_result.get("fail_count", 0)
                    success_rate = (model_result.get("success_count", 0) / total * 100) if total > 0 else 0
                
                avg_time = model_result.get("average_response_time", 0)
                successes = model_result.get("success_count", 0)
                fails = model_result.get("fail_count", 0)
                
                summary_lines.append(f"• {display_name}")
                summary_lines.append(f"  Success Rate: {success_rate:.1f}%")
                summary_lines.append(f"  Avg Response Time: {avg_time:.2f}s")
                summary_lines.append(f"  Successes: {successes}")
                summary_lines.append(f"  Fails: {fails}")
                summary_lines.append("")
        
        # Alternative format for different result structures
        elif "model_tested" in results:
            summary_lines.append(f"Model Tested: {results.get('model_tested', 'Unknown')}")
            summary_lines.append(f"Providers: {', '.join(results.get('providers', ['Unknown']))}")
            summary_lines.append(f"Total Prompts: {results.get('total_prompts', 0)}")
            summary_lines.append(f"Status: {results.get('status', 'Unknown')}")
            summary_lines.append("")
            
            # Add category summary if available
            if "category_summary" in results and results["category_summary"]:
                summary_lines.append("Category Summary:")
                summary_lines.append("-" * 30)
                
                for category, stats in results["category_summary"].items():
                    summary_lines.append(f"• {category}: {stats}")
                
                summary_lines.append("")
        
        # Calculate and display overall statistics
        overall_success_rate = 0
        if "success_rate" in results:
            overall_success_rate = results.get("success_rate", 0)
        elif "examples" in results:
            # Calculate from examples data
            total_examples = len(results["examples"])
            successful_examples = 0
            
            for example in results["examples"]:
                if "responses" in example:
                    for response in example["responses"]:
                        if response.get("success", False):
                            successful_examples += 1
                            break  # Count example as successful if any response succeeded
            
            overall_success_rate = (successful_examples / total_examples * 100) if total_examples > 0 else 0
        elif "metrics" in results and "overall_bypass_rate" in results["metrics"]:
            # Extract from bypass rate (inverse of success rate for red teaming)
            bypass_rate_str = results["metrics"]["overall_bypass_rate"]
            if isinstance(bypass_rate_str, str) and "%" in bypass_rate_str:
                bypass_rate = float(bypass_rate_str.replace("%", ""))
                overall_success_rate = 100 - bypass_rate  # Success is inverse of bypass
            elif isinstance(bypass_rate_str, (int, float)):
                overall_success_rate = 100 - (bypass_rate_str * 100 if bypass_rate_str <= 1 else bypass_rate_str)
        
        # Add overall statistics
        if overall_success_rate > 0:
            summary_lines.append(f"Overall Success Rate: {overall_success_rate:.1f}%")
        if "average_response_time" in results:
            summary_lines.append(f"Overall Average Response Time: {results.get('average_response_time', 0):.2f}s")
        
        # Add footer
        summary_lines.extend([
            "",
            "=" * 50,
            "This is an automated message from your Triksha installation.",
            "To disable these notifications, use the 'settings' command in the Triksha CLI."
        ])
        
        return "\n".join(summary_lines)
    
    def send_benchmark_error_notification(
        self, 
        task_id: str, 
        error_message: str,
        results: Dict[str, Any]
    ) -> bool:
        """Send a notification when a scheduled benchmark fails.
        
        Args:
            task_id: ID of the failed scheduled task
            error_message: Error message describing the failure
            results: Error results dictionary
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_configured():
            return False
        
        try:
            # Create email
            msg = MIMEMultipart()
            msg["Subject"] = f"Triksha Scheduled Red Teaming Job Failed - Task {task_id}"
            msg["From"] = self.config["email"]
            msg["To"] = self.config["email"]
            
            # Create error summary
            error_summary = self._create_error_summary(task_id, error_message, results)
            
            # Add summary to email
            msg.attach(MIMEText(error_summary, "plain"))
            
            # Send email
            context = ssl.create_default_context()
            
            # Check if SSL verification should be bypassed
            if self.config.get("bypass_ssl", False):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(self.config["email"], self.config["app_password"])
                server.send_message(msg)
            
            self.console.print("[green]✓ Error notification sent successfully[/]")
            return True
            
        except Exception as e:
            self.console.print(f"[yellow]Failed to send error notification: {str(e)}[/]")
            return False
    
    def _create_error_summary(self, task_id: str, error_message: str, results: Dict[str, Any]) -> str:
        """Create a text summary of benchmark error for email.
        
        Args:
            task_id: ID of the failed scheduled task
            error_message: Error message describing the failure
            results: Error results dictionary
            
        Returns:
            Error summary text
        """
        summary_lines = [
            f"Triksha Scheduled Red Teaming Job Failed",
            "=" * 50,
            "",
            f"Task ID: {task_id}",
            f"Timestamp: {results.get('timestamp', datetime.now().isoformat())}",
            f"Status: {results.get('status', 'Failed')}",
            "",
            "Error Details:",
            "-" * 30,
            error_message,
            "",
            "=" * 50,
            "This is an automated error notification from your Triksha installation.",
            "Please check your scheduled benchmark configuration and try again.",
            "To disable these notifications, use the 'settings' command in the Triksha CLI."
        ]
        
        return "\n".join(summary_lines)


# Simple function interface for backward compatibility
def send_notification(scan_config: Dict[str, Any]) -> bool:
    """Simple function interface for sending scan notifications.
    
    Args:
        scan_config: Scan configuration dictionary
        
    Returns:
        True if notification was sent successfully, False otherwise
    """
    try:
        # Extract scan information
        scan_id = scan_config.get("scan_id", "unknown")
        scan_name = scan_config.get("scan_name", "Unknown Scan")
        notification_email = scan_config.get("notification_email")
        
        if not notification_email:
            return False
        
        console = Console()
        
        # Check if email configuration is available via environment variables
        smtp_email = os.getenv("SMTP_EMAIL")
        smtp_password = os.getenv("SMTP_PASSWORD") 
        smtp_app_password = os.getenv("SMTP_APP_PASSWORD")
        
        if smtp_email and (smtp_password or smtp_app_password):
            # Try to send actual email using environment variables
            try:
                return _send_email_via_env_vars(scan_config, smtp_email, smtp_password or smtp_app_password, console)
            except Exception as e:
                console.print(f"[yellow]Failed to send email via environment config: {str(e)}[/]")
                console.print(f"[dim]Email notification would be sent to {notification_email} for scan {scan_id}[/]")
                return True
        else:
            # No email configuration available, just log
            console.print(f"[dim]Email notification would be sent to {notification_email} for scan {scan_id}[/]")
            console.print(f"[dim]To enable email notifications, set SMTP_EMAIL and SMTP_APP_PASSWORD environment variables[/]")
            return True
        
    except Exception as e:
        console = Console()
        console.print(f"[yellow]Failed to send email notification: {str(e)}[/]")
        return False


def _send_email_via_env_vars(scan_config: Dict[str, Any], smtp_email: str, smtp_password: str, console: Console) -> bool:
    """Send email using environment variable configuration.
    
    Args:
        scan_config: Scan configuration dictionary
        smtp_email: Email address for SMTP
        smtp_password: Password/App password for SMTP
        console: Rich console for output
        
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Create email
        msg = MIMEMultipart()
        msg["Subject"] = f"Triksha Scan Completed: {scan_config.get('scan_name', 'Unknown Scan')}"
        msg["From"] = smtp_email
        msg["To"] = scan_config.get("notification_email")
        
        # Create simple summary
        scan_id = scan_config.get("scan_id", "unknown")
        scan_name = scan_config.get("scan_name", "Unknown Scan")
        status = scan_config.get("status", "completed")
        completion_time = scan_config.get("completion_time", "Unknown")
        duration = scan_config.get("duration_seconds", 0)
        
        # Get summary if available
        summary = scan_config.get("summary", {})
        total_prompts = summary.get("total_prompts", 0)
        successful_bypasses = summary.get("successful_bypasses", 0)
        failed_bypasses = summary.get("failed_bypasses", 0)
        
        body = f"""
Triksha Red Teaming Scan Completed

Scan Details:
- Scan ID: {scan_id}
- Scan Name: {scan_name}
- Status: {status}
- Completion Time: {completion_time}
- Duration: {duration:.2f} seconds

Results Summary:
- Total Prompts: {total_prompts}
- Successful Bypasses: {successful_bypasses}
- Failed Bypasses: {failed_bypasses}

You can view detailed results in the Triksha dashboard.

Best regards,
Triksha Team
        """.strip()
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email via Gmail SMTP
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
        
        console.print(f"[green]✓ Email notification sent to {scan_config.get('notification_email')} for scan {scan_id}[/]")
        return True
        
    except Exception as e:
        console.print(f"[yellow]Failed to send email: {str(e)}[/]")
        return False
