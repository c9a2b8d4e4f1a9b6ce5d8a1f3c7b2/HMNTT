import shutil
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
from automation import GetReports


def get_automation_pending():
    """
    Get all URLs from JSON files in the automation_pending directory.

    Returns:
        list: A list of URLs found in all JSON files
    """
    automation_pending_dir = os.environ.get("AUTOMATION_PENDING_DIR", "automation_pending")
    urls = []

    # Ensure directory exists
    if not os.path.exists(automation_pending_dir):
        print(f"Directory {automation_pending_dir} does not exist")
        return urls

    # Get all JSON files in the directory
    json_files = list(Path(automation_pending_dir).glob("*.json"))

    if not json_files:
        print(f"No JSON files found in {automation_pending_dir}")
        return urls

    # Process each JSON file
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Handle both list of questions and single question objects
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'url' in item:
                            urls.append(item['url'])
                elif isinstance(data, dict) and 'url' in data:
                    urls.append(data['url'])

        except json.JSONDecodeError as e:
            print(f"Error parsing {json_file}: {e}")
        except Exception as e:
            print(f"Error processing {json_file}: {e}")

    return urls


def move_files_back_to_automation():
    """Move all files from automation_pending back to automation folder"""
    automation_dir = os.environ.get("AUTOMATION_DIR", "automation")
    automation_pending_dir = os.environ.get("AUTOMATION_PENDING_DIR", "automation_pending")

    moved_files = []

    try:
        # Ensure both directories exist
        os.makedirs(automation_dir, exist_ok=True)
        os.makedirs(automation_pending_dir, exist_ok=True)

        # Get all files in automation_pending
        pending_files = list(Path(automation_pending_dir).glob("*"))

        for file_path in pending_files:
            try:
                # Create destination path
                dest_path = os.path.join(automation_dir, file_path.name)

                # Handle filename conflicts
                if os.path.exists(dest_path):
                    # Append a timestamp to make filename unique
                    base_name = file_path.stem
                    extension = file_path.suffix
                    timestamp = int(time.time())
                    dest_path = os.path.join(automation_dir, f"{base_name}_{timestamp}{extension}")

                # Move the file
                shutil.move(str(file_path), dest_path)
                moved_files.append(dest_path)

            except Exception as e:
                print(f"Error moving {file_path} back to automation: {e}")
                continue

        if moved_files:
            print(f"Moved {len(moved_files)} files back to {automation_dir}")
        return moved_files

    except Exception as e:
        print(f"Error in move_files_back_to_automation: {e}")
        return []


def main():
    try:
        pending_urls = get_automation_pending()
        total = len(pending_urls)

        if total == 0:
            print("No pending reports to generate")
        else:
            print(f"Found {total} URLs needing reports")

            counter = 0
            report = GetReports(teardown=True)
            for i, url in enumerate(pending_urls):
                print(f"[{i + 1}/{total}] Generating report for: {url[:50]}...")
                report.get_report(url)
                counter += 1
                if counter >= 500:
                    break

            print(f"\n=== Completed {total} reports ===")

    except Exception as e:
        print(f"\n!!! ERROR: {e}")
        print("Attempting to move files back to automation directory...")
        moved = move_files_back_to_automation()
        if moved:
            print(f"Moved {len(moved)} files back to automation directory")
        else:
            print("No files were moved back")


if __name__ == '__main__':
    main()
