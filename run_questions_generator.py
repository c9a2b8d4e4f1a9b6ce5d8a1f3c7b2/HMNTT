import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
from questions_generator import GenerateQuestions


def get_pending_scope_file(question_pending_dir="scope_pending"):
    """Get the first pending question file path if it exists."""
    try:
        pending_files = sorted(Path(question_pending_dir).glob('*.json'))
        return pending_files[0] if pending_files else None
    except Exception as e:
        print(f"Error finding pending question file: {e}")
        return None


def move_file(src, dest_dir):
    """Move a file to a destination directory."""
    try:
        dest = Path(dest_dir) / src.name
        shutil.move(str(src), str(dest))
        print(f"Moved {src} to {dest}")
        return True
    except Exception as e:
        print(f"Error moving file {src}: {e}")
        return False


scope_pending_dir = "scope_pending"
scope_dir = "scope"
pending_file = get_pending_scope_file()

if not pending_file:
    print("No pending question files found.")
    sys.exit(0)


def main():
    try:
        # Load questions once
        with open(pending_file, 'r', encoding='utf-8') as f:
            questions = json.load(f)

        if not isinstance(questions, list):
            raise ValueError(f"Expected a list of questions in {pending_file}, got {type(questions)}")

        total = len(questions)
        print(f"Found {total} questions in {pending_file}")

        # Process questions
        for i, question in enumerate(questions, 1):
            print(f"[{i}/{total}] Processing: {question[:50]}...")
            bot = GenerateQuestions(teardown=True)
            bot.ask_question(question)

            if i >= 25:  # Process maximum 25 questions
                print("Reached the limit of 25 questions")
                break

        # If we get here, processing was successful
        print(f"Successfully processed {i} questions")
        # Delete the processed file
        pending_file.unlink()
        print(f"Deleted processed file: {pending_file}")

    except Exception as e:
        print(f"Error during processing: {e}")
        # Move the file back to questions directory on error
        if pending_file.exists():
            if move_file(pending_file, scope_dir):
                print(f"Moved {pending_file} back to {scope_dir} due to error")
            else:
                print(f"Failed to move {pending_file} back to {scope_dir}")


if __name__ == '__main__':
    main()
