import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_validation import Validator


def move_files_to_automation():
    """Move all files from validated_questions_pending to automation directory."""
    src_dir = Path("validated_questions_pending")
    dest_dir = Path("automation")
    
    if not src_dir.exists():
        print(f"Source directory '{src_dir}' not found")
        return 0, 0
    
    dest_dir.mkdir(exist_ok=True)
    moved = errors = 0
    
    for src_file in src_dir.glob('*'):
        if not src_file.is_file():
            continue
            
        dest_file = dest_dir / src_file.name
        counter = 1
        while dest_file.exists():
            dest_file = dest_dir / f"{src_file.stem}_{counter}{src_file.suffix}"
            counter += 1
            
        try:
            shutil.move(str(src_file), str(dest_file))
            moved += 1
        except Exception as e:
            print(f"Error moving {src_file}: {e}")
            errors += 1
    
    print(f"Moved {moved} files, {errors} errors")
    return moved, errors


def load_processed_reports():
    """Load the set of already processed audit files from validated.json"""
    if not os.path.exists("validated.json"):
        return set()

    try:
        with open("validated.json", "r") as f:
            data = json.load(f)
            # Return a set of processed filenames
            return {item.get("filename", "") for item in data if "filename" in item}
    except Exception as e:
        print(f"Error loading collections: {e}")
        return set()


def get_audits_reports():
    # Get all .md files from the audits directory
    audits_dir = Path("validated_questions_pending")
    return sorted(audits_dir.glob("*.md"))


def move_files(src, dest_dir):
    """Move a file to a destination directory."""
    try:
        dest = Path(dest_dir) / src.name
        shutil.move(str(src), str(dest))
        print(f"Moved {src} to {dest}")
        return True
    except Exception as e:
        print(f"Error moving file {src}: {e}")
        return False


def main():
    try:
        # Get all audit files
        audit_files = get_audits_reports()
        total = len(audit_files)
        processed_files = load_processed_reports()

        print(f"Found {total} audit files to process")
        print(f"Already processed: {len(processed_files)}")

        processed_count = 0
        skipped_count = 0
        counter = 0

        for i, audit_file in enumerate(audit_files, 1):
            if audit_file.name in processed_files:
                print(f"[{i}/{total}] Skipping (already processed): {audit_file.name}")
                skipped_count += 1
                continue

            print(f"\n[{i}/{total}] Processing: {audit_file.name}")

            try:
                with open(audit_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Initialize the validator and process the content
                bot = Validator(teardown=True)
                print(f"Processing content from {audit_file.name}...")

                # Assuming bot.ask_question() is what processes the content
                # You might want to pass the filename as well
                bot.ask_question(audit_file.name, content)

                # Add to processed files
                processed_files.add(audit_file.name)
                processed_count += 1

                counter += 1
                if counter >= 25:
                    break

            except Exception as e:
                print(f"Error processing {audit_file.name}: {str(e)}")
                continue

        print(f"\n=== Summary ===")
        print(f"Total files: {total}")
        print(f"Processed: {processed_count}")
        print(f"Skipped: {skipped_count}")

    except Exception as e:
        print(f"Error: {e}")
        print("Moving files back to automation directory...")
        move_files_to_automation()


if __name__ == '__main__':
    main()
