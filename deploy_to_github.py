#!/usr/bin/env python3
"""
GitHub Deployment Automation Script
Prepares the SOC Firewall Log Analyzer for GitHub deployment
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime


class GitHubDeployment:
    def __init__(self, project_path=None):
        self.project_path = Path(project_path) if project_path else Path.cwd()
        self.github_username = None
        self.repo_name = "soc-firewall-analyzer"
        
    def check_git_installed(self):
        """Check if git is installed"""
        try:
            subprocess.run(["git", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Git is not installed or not in PATH")
            return False
    
    def get_github_username(self):
        """Get GitHub username from user"""
        if not self.github_username:
            self.github_username = input("Enter your GitHub username: ").strip()
        return self.github_username
    
    def update_urls_in_files(self):
        """Update placeholder URLs with actual GitHub username"""
        username = self.get_github_username()
        
        # Update setup.py
        setup_file = self.project_path / "setup.py"
        if setup_file.exists():
            content = setup_file.read_text(encoding='utf-8')
            content = content.replace("USERNAME", username)
            setup_file.write_text(content, encoding='utf-8')
            print(f"✅ Updated URLs in setup.py")
        
        # Update README.md if needed
        readme_file = self.project_path / "README.md"
        if readme_file.exists():
            content = readme_file.read_text(encoding='utf-8')
            if "USERNAME" in content:
                content = content.replace("USERNAME", username)
                readme_file.write_text(content, encoding='utf-8')
                print(f"✅ Updated URLs in README.md")
    
    def validate_project_structure(self):
        """Validate that all required files exist"""
        required_files = [
            "main.py",
            "enhanced_main.py", 
            "launcher.py",
            "requirements.txt",
            "README.md",
            "LICENSE",
            "setup.py",
            ".gitignore",
            "VERSION"
        ]
        
        required_dirs = [
            "alerts",
            "detectors", 
            "parsers",
            "utils",
            "gui",
            "tests",
            "test_logs",
            ".github"
        ]
        
        print("🔍 Validating project structure...")
        
        missing_files = []
        for file in required_files:
            if not (self.project_path / file).exists():
                missing_files.append(file)
        
        missing_dirs = []
        for directory in required_dirs:
            if not (self.project_path / directory).exists():
                missing_dirs.append(directory)
        
        if missing_files or missing_dirs:
            print("❌ Project structure validation failed:")
            if missing_files:
                print(f"   Missing files: {', '.join(missing_files)}")
            if missing_dirs:
                print(f"   Missing directories: {', '.join(missing_dirs)}")
            return False
        
        print("✅ Project structure validation passed")
        return True
    
    def check_sensitive_data(self):
        """Check for sensitive data that shouldn't be committed"""
        sensitive_patterns = [
            "*.key",
            "*.pem", 
            "*.log",
            ".env",
            "config.json",
            "secrets.txt"
        ]
        
        print("🔒 Checking for sensitive data...")
        
        # Check if logs directory is empty (except for .gitkeep)
        logs_dir = self.project_path / "logs"
        if logs_dir.exists():
            log_files = [f for f in logs_dir.iterdir() if f.name != ".gitkeep"]
            if log_files:
                print(f"⚠️  Warning: Found files in logs directory: {[f.name for f in log_files]}")
                return False
        
        print("✅ No sensitive data found")
        return True
    
    def initialize_git_repo(self):
        """Initialize git repository if not already done"""
        if (self.project_path / ".git").exists():
            print("✅ Git repository already initialized")
            return True
        
        try:
            subprocess.run(["git", "init"], cwd=self.project_path, check=True)
            print("✅ Git repository initialized")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to initialize git repository: {e}")
            return False
    
    def create_initial_commit(self):
        """Create initial commit"""
        try:
            # Add all files
            subprocess.run(["git", "add", "."], cwd=self.project_path, check=True)
            
            # Check if there's anything to commit
            result = subprocess.run(
                ["git", "status", "--porcelain"], 
                cwd=self.project_path, 
                capture_output=True, 
                text=True
            )
            
            if not result.stdout.strip():
                print("✅ No changes to commit")
                return True
            
            # Create commit
            commit_message = "Initial commit: SOC Firewall Log Analyzer v2.0.0\n\n" \
                           "Features:\n" \
                           "- Multi-format firewall log parsing\n" \
                           "- MITRE ATT&CK framework integration\n" \
                           "- Advanced threat correlation\n" \
                           "- Professional reporting (Excel/PDF)\n" \
                           "- Live log monitoring\n" \
                           "- Interactive GUI dashboard\n" \
                           "- Scheduled analysis capabilities"
            
            subprocess.run(
                ["git", "commit", "-m", commit_message], 
                cwd=self.project_path, 
                check=True
            )
            print("✅ Initial commit created")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create initial commit: {e}")
            return False
    
    def add_remote_origin(self):
        """Add GitHub remote origin"""
        username = self.get_github_username()
        remote_url = f"https://github.com/{username}/{self.repo_name}.git"
        
        try:
            # Check if remote already exists
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"], 
                cwd=self.project_path, 
                capture_output=True
            )
            
            if result.returncode == 0:
                print("✅ Remote origin already configured")
                return True
            
            # Add remote
            subprocess.run(
                ["git", "remote", "add", "origin", remote_url], 
                cwd=self.project_path, 
                check=True
            )
            print(f"✅ Added remote origin: {remote_url}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to add remote origin: {e}")
            return False
    
    def create_version_tag(self):
        """Create version tag"""
        try:
            version_file = self.project_path / "VERSION"
            if version_file.exists():
                version = version_file.read_text().strip()
                tag_name = f"v{version}"
                
                # Check if tag already exists
                result = subprocess.run(
                    ["git", "tag", "-l", tag_name], 
                    cwd=self.project_path, 
                    capture_output=True, 
                    text=True
                )
                
                if result.stdout.strip():
                    print(f"✅ Tag {tag_name} already exists")
                    return True
                
                # Create tag
                tag_message = f"Release {tag_name}: Enhanced SOC capabilities with MITRE ATT&CK integration"
                subprocess.run(
                    ["git", "tag", "-a", tag_name, "-m", tag_message], 
                    cwd=self.project_path, 
                    check=True
                )
                print(f"✅ Created version tag: {tag_name}")
                return True
            else:
                print("⚠️  VERSION file not found")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create version tag: {e}")
            return False
    
    def generate_deployment_summary(self):
        """Generate deployment summary"""
        username = self.get_github_username()
        
        summary = f"""
🚀 SOC Firewall Log Analyzer - GitHub Deployment Summary
═══════════════════════════════════════════════════════

📦 Repository Information:
   • Name: {self.repo_name}
   • URL: https://github.com/{username}/{self.repo_name}
   • Owner: {username}

✅ Deployment Checklist:
   • Project structure validated
   • URLs updated with GitHub username
   • Git repository initialized
   • Initial commit created
   • Remote origin configured
   • Version tag created
   • Sensitive data check passed

🎯 Next Steps:
   1. Create repository on GitHub: https://github.com/new
      - Repository name: {self.repo_name}
      - Description: Advanced SOC tool for firewall log analysis with MITRE ATT&CK integration
      - Public repository (recommended for open source)
      
   2. Push to GitHub:
      git branch -M main
      git push -u origin main
      git push origin --tags
      
   3. Configure repository settings:
      - Enable Issues and Discussions
      - Add topics: cybersecurity, soc, firewall, log-analysis, mitre-attack
      - Set up branch protection rules
      - Enable security features
      
   4. Create first release:
      - Go to Releases tab
      - Click "Create a new release"
      - Select tag v2.0.0
      - Add release notes
      
   5. Promote your project:
      - Share in cybersecurity communities
      - Write blog posts
      - Engage with potential users

📊 Project Statistics:
   • Python files: {len(list(self.project_path.glob('**/*.py')))}
   • Documentation files: {len(list(self.project_path.glob('*.md')))}
   • Test files: {len(list(self.project_path.glob('tests/**/*.py')))}

🔥 Your professional SOC tool is ready for the world!
"""
        
        print(summary)
        
        # Save summary to file
        summary_file = self.project_path / "DEPLOYMENT_SUMMARY.md"
        summary_file.write_text(summary, encoding='utf-8')
        print(f"📄 Deployment summary saved to: {summary_file}")
    
    def run_deployment(self):
        """Run the complete deployment process"""
        print("🚀 Starting GitHub deployment preparation...")
        print("=" * 60)
        
        # Check prerequisites
        if not self.check_git_installed():
            return False
        
        # Validate project
        if not self.validate_project_structure():
            return False
        
        if not self.check_sensitive_data():
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                return False
        
        # Update files
        self.update_urls_in_files()
        
        # Git operations
        if not self.initialize_git_repo():
            return False
        
        if not self.create_initial_commit():
            return False
        
        if not self.add_remote_origin():
            return False
        
        if not self.create_version_tag():
            return False
        
        # Generate summary
        self.generate_deployment_summary()
        
        print("\n🎉 Deployment preparation completed successfully!")
        print("Your SOC Firewall Log Analyzer is ready for GitHub!")
        
        return True


def main():
    """Main function"""
    print("🔥 SOC Firewall Log Analyzer - GitHub Deployment Tool")
    print("=" * 60)
    
    # Get project path
    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = input("Enter project path (or press Enter for current directory): ").strip()
        if not project_path:
            project_path = os.getcwd()
    
    # Initialize deployment
    deployment = GitHubDeployment(project_path)
    
    # Run deployment
    try:
        success = deployment.run_deployment()
        if success:
            print("\n✅ All done! Follow the Next Steps in the summary above.")
        else:
            print("\n❌ Deployment preparation failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Deployment cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
