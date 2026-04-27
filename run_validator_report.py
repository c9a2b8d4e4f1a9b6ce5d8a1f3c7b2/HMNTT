import shutil
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
from audit_validation import GetValidatedReports


def get_validated_questions_pending():
    """
    Get all URLs from JSON files in the validated_pending directory.

    Returns:
        list: A list of URLs found in all JSON files
    """
    validation_pending_dir = os.environ.get("VALIDATION_PENDING_DIR", 'validation_pending')
    urls = []

    # Ensure directory exists
    if not os.path.exists(validation_pending_dir):
        print(f"Directory {validation_pending_dir} does not exist")
        return urls

    # Get all JSON files in the directory
    json_files = list(Path(validation_pending_dir).glob("*.json"))

    if not json_files:
        print(f"No JSON files found in {validation_pending_dir}")
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


def move_files_back_to_validated_questions():
    """Move all files from validated_pending back to validated folder"""
    validated_questions_dir = os.environ.get("VALIDATED_QUESTIONS_DIR", "validated_questions")
    validated_questions_pending_dir = os.environ.get("VALIDATION_PENDING_DIR", 'validated_questions_pending')

    moved_files = []

    try:
        # Ensure both directories exist
        os.makedirs(validated_questions_dir, exist_ok=True)
        os.makedirs(validated_questions_pending_dir, exist_ok=True)

        # Get all files in validated_pending
        pending_files = list(Path(validated_questions_pending_dir).glob("*"))

        for file_path in pending_files:
            try:
                # Create destination path
                dest_path = os.path.join(validated_questions_dir, file_path.name)

                # Handle filename conflicts
                if os.path.exists(dest_path):
                    # Append a timestamp to make filename unique
                    base_name = file_path.stem
                    extension = file_path.suffix
                    timestamp = int(time.time())
                    dest_path = os.path.join(validated_questions_dir, f"{base_name}_{timestamp}{extension}")

                # Move the file
                shutil.move(str(file_path), dest_path)
                moved_files.append(dest_path)

            except Exception as e:
                print(f"Error moving {file_path} back to validated: {e}")
                continue

        if moved_files:
            print(f"Moved {len(moved_files)} files back to {validated_questions_dir}")
        return moved_files

    except Exception as e:
        print(f"Error in move_files_back_to_validated: {e}")
        return []


def main():
    try:
        pending_urls = get_validated_questions_pending()
        total = len(pending_urls)

        if total == 0:
            print("No pending reports to generate")
        else:
            print(f"Found {total} URLs needing reports")

            report = GetValidatedReports(teardown=True)
            for i, url in enumerate(pending_urls):
                print(f"[{i + 1}/{total}] Generating report for: {url[:50]}...")
                report.get_report(url)

            print(f"\n=== Completed {total} reports ===")

    except Exception as e:
        print(f"\n!!! ERROR: {e}")
        print("Attempting to move files back to validated directory...")
        moved = move_files_back_to_validated_questions()
        if moved:
            print(f"Moved {len(moved)} files back to validated directory")
        else:
            print("No files were moved back")


if __name__ == '__main__':
    main()
