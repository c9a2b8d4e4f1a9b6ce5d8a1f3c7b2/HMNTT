import json
import os
import subprocess
import shutil
import sys
from pathlib import Path

import requests

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from questions import SOURCE_REPO, MAX_REPO


def copy_security_md_to_repo(worktree_dir: Path):
    """Copy setup/SECURITY.md into the root of the generated repository."""
    project_root = Path(__file__).resolve().parent.parent
    source_security_file = project_root / "setup" / "SECURITY.md"
    target_security_file = worktree_dir / "SECURITY.md"

    if not source_security_file.exists():
        print(f"❌ Missing SECURITY.md source file: {source_security_file}")
        return False

    shutil.copy2(source_security_file, target_security_file)
    print(f"✅ Added SECURITY.md to repo root: {target_security_file}")
    return True

def copy_researcher_md_to_repo(worktree_dir: Path):
    """Copy setup/SECURITY.md into the root of the generated repository."""
    project_root = Path(__file__).resolve().parent.parent
    source_security_file = project_root / "setup" / "RESEARCHER.md"
    target_security_file = worktree_dir / "RESEARCHER.md"

    if not source_security_file.exists():
        print(f"❌ Missing RESEARCHER.md source file: {source_security_file}")
        return False

    shutil.copy2(source_security_file, target_security_file)
    print(f"✅ Added RESEARCHER.md to repo root: {target_security_file}")
    return True


def run_command(command, cwd=None):
    """Run a shell command and return the output with detailed error handling"""
    try:
        print(f"Running: {command}")
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.stdout:
            print(f"Output: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed with exit code {e.returncode}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False


def create_github_repo(repo_name, token, username, description="", private=False):
    """Create a new GitHub repository using the GitHub API"""
    url = "https://api.github.com/user/repos"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "name": repo_name,
        "description": description,
        "private": private,
        "auto_init": False  # We'll push our own content
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 201:
            print(f"✅ Created repository {repo_name}")
            return True
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed to create repository: {error_msg}")
            if response.status_code == 422:  # Unprocessable Entity
                print("Repository might already exist or name is invalid")
                return True
            return False
    except Exception as e:
        print(f"❌ API Error: {str(e)}")
        return False


def setup_github_repo(repo_name, source_repo, token, username):
    """Setup and push to a new GitHub repository"""
    try:
        if not create_github_repo(repo_name, token, username):
            return False

        if not copy_security_md_to_repo(Path.cwd()):
            return False

        if not copy_researcher_md_to_repo(Path.cwd()):
            return False

        # Initialize a new git repository
        if not run_command("git init"):
            return False

        # Add all files
        if not run_command("git add ."):
            return False

        # Configure git
        if not run_command('git config --global user.name "GitHub Actions"'):
            return False
        if not run_command('git config --global user.email "actions@github.com"'):
            return False

        # Commit changes
        if not run_command('git commit -m "Initial commit"'):
            return False

        # Add remote
        remote_url = f"https://{username}:{token}@github.com/{username}/{repo_name}.git"
        if not run_command(f'git remote add origin {remote_url}'):
            return False

        # Push to GitHub
        if not run_command('git push -u origin master'):
            print("Master branch not found, trying main...")
            # Try with master if main fails
            if not run_command('git push -u origin main'):
                return False

        # Clean up
        run_command('git remote remove origin')
        return True

    except Exception as e:
        print(f"❌ Error in setup_github_repo: {str(e)}")
        return False


def save_repo_url(repo_name, username):
    """Save repository URL to repositories.json"""
    try:
        repo_url = f"https://deepwiki.com/{username}/{repo_name}"
        file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'repositories.json')

        # Load existing repositories if file exists
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                try:
                    repos = json.load(f)
                except json.JSONDecodeError:
                    repos = []
        else:
            repos = []

        # Add new repository URL if not already in the list
        if repo_url not in repos:
            repos.append(repo_url)
            with open(file_path, 'w') as f:
                json.dump(repos, f, indent=2)
            print(f"✅ Saved repository URL to repositories.json")

    except Exception as e:
        print(f"❌ Failed to save repository URL: {str(e)}")


def get_existing_repos():
    """Get list of existing repositories from repositories.json"""
    repo_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'repositories.json')
    if not os.path.exists(repo_file):
        return set()

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            repos = json.load(f)
            # Convert to a set for faster lookups and extract just the repo names
            return {repo.rstrip('/').split('/')[-1].lower() for repo in repos}
    except Exception as e:
        print(f"⚠️  Warning: Could not read repositories.json: {e}")
        return set()


def load_repo_accounts():
    """Load GitHub usernames/tokens from key.json in insertion order."""
    key_file = Path(__file__).resolve().parent.parent / "key.json"
    if not key_file.exists():
        print(f"❌ key.json not found at {key_file}")
        return []

    try:
        with open(key_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Failed to read key.json: {e}")
        return []

    if not isinstance(data, dict) or not data:
        print("❌ key.json is empty or invalid")
        return []

    accounts = [(username, token) for username, token in data.items() if token]
    if not accounts:
        print("❌ key.json has no valid tokens")
        return []

    return accounts


def main():
    # Configuration
    source_repo = SOURCE_REPO
    base_name = source_repo.split("/")[-1]
    num_repos = MAX_REPO  # For testing, change to 100 for production

    accounts = load_repo_accounts()
    if not accounts:
        return

    print(f"Using {len(accounts)} account(s) for round-robin repo creation")

    # Create a temporary directory
    temp_dir = Path("temp_repo")
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir()

    existing_repos = get_existing_repos()
    print(f"Found {len(existing_repos)} existing repositories")

    try:
        # Clone the source repo with depth 1 to save bandwidth
        print(f"🔍 Cloning {source_repo}...")
        clone_cmd = f"git clone --depth 1 https://github.com/{source_repo}.git ."
        if not run_command(clone_cmd, cwd=temp_dir):
            print("❌ Failed to clone source repository")
            return

        # Change to the source directory
        os.chdir(temp_dir)

        # Remove .git directory
        shutil.rmtree(".git", ignore_errors=True)

        # Create and push repositories
        for i in range(1, num_repos + 1):
            repo_name = f"{base_name}--{i:03d}"

            if repo_name.lower() in existing_repos:
                print(f"⏩ Skipping {repo_name} - already exists")
                continue

            account_index = (i - 1) % len(accounts)
            username, token = accounts[account_index]
            print(
                f"\n🔄 Processing {i}/{num_repos}: {repo_name} "
                f"(account {account_index + 1}/{len(accounts)}: {username})"
            )

            # Setup and push to GitHub
            if setup_github_repo(repo_name, source_repo, token, username):
                print(f"✅ Successfully created {repo_name}")
                save_repo_url(repo_name, username)
                # Clean up for next iteration
                run_command("rm -rf .git")
            else:
                print(f"❌ Failed to create {repo_name}")

    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
    finally:
        # Clean up
        os.chdir("..")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
