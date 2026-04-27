import json
import os
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path

import pyperclip
from decouple import config
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import validation_format, BASE_URL, scan_format


class Validator:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        self.options.add_argument("--headless")
        self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.validated_url = []
        super(Validator, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()

    def toggle_deep_research(self):
        wait = WebDriverWait(self.driver, 20)

        xpath = '//button[.//span[normalize-space(text())="Fast"]]'
        btn = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
        btn.click()

        xpath_primary = "//div[@role='menuitem' and .//span[normalize-space(text())='Deep Research']]"
        menu_item = wait.until(EC.element_to_be_clickable((By.XPATH, xpath_primary)))
        menu_item.click()

    def ask_question(self, filename, question_gotten):
        wait = WebDriverWait(self.driver, 1200)

        self.driver.get(BASE_URL)

        wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
        )



        for _ in range(10):
            try:


                # # wait for the form containing the textarea
                form = wait.until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
                )

                # find the textarea inside the form
                textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
                self.toggle_deep_research()

                # type the question
                textarea.click()
                textarea.clear()
                used_question = f"{question_gotten}".split("## Recommendation")[0]
                formatted_question = validation_format(used_question)

                # Use JavaScript to set the textarea value directly. It's more reliable for large text.
                self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
                # Dispatch an 'input' event to make sure the web application detects the change.
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                           textarea)
                textarea.send_keys(".. ")

                textarea.send_keys(Keys.ENTER)

                time.sleep(10)
                current_url = self.driver.current_url

                # add the current url to validated
                self.save_to_validated(filename, current_url)
                break
            except Exception as a:
                print(f"There was an error ")
                print(f"{self.driver.current_url}")
                time.sleep(10)
                continue


    def scan_past_vuln(self, filename, question_gotten):
        wait = WebDriverWait(self.driver, 1200)

        self.driver.get(BASE_URL)

        wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
        )


        for _ in range(10):
            try:

                # # wait for the form containing the textarea
                form = wait.until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
                )

                # find the textarea inside the form
                textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
                self.toggle_deep_research()

                # type the question
                textarea.click()
                textarea.clear()
                formatted_question = scan_format(question_gotten)

                # Use JavaScript to set the textarea value directly. It's more reliable for large text.
                self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
                # Dispatch an 'input' event to make sure the web application detects the change.
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                           textarea)
                textarea.send_keys(".. ")

                textarea.send_keys(Keys.ENTER)

                time.sleep(10)
                current_url = self.driver.current_url

                # add the current url to validated
                self.save_to_validated(filename, current_url)
                break
            except Exception as a:
                print(f"There was an error ")
                print(f"{self.driver.current_url}")
                time.sleep(10)
                continue

    def save_to_validated(self, filename, url):
        """Save question and URL to collections.json"""
        validated_file = config("VALIDATED_QUESTIONS_PATH")

        # Load existing data or start fresh
        try:
            if os.path.exists(validated_file):
                with open(validated_file, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid validated.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "filename": filename,
            "url": url,
            "timestamp": str(datetime.now()),
            "report_generated": False
        })

        # Save with proper formatting
        try:
            with open(validated_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving to validated: {e}")


class GetValidatedReports:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        # self.options.add_argument("--headless")
        # self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.validated_url = []
        super(GetValidatedReports, self).__init__()

    @staticmethod
    def _is_not_found_url(current_url):
        return "/search/not-found" in current_url

    def _wait_for_not_found_or_copy_buttons(self, wait):
        copy_button_selector = (By.CSS_SELECTOR, '[aria-label="Copy"]')

        def _page_ready(driver):
            if self._is_not_found_url(driver.current_url):
                return "not_found"

            copy_buttons = driver.find_elements(*copy_button_selector)
            if copy_buttons:
                return copy_buttons
            return False

        return wait.until(_page_ready)

    def get_report(self, url):

        try:
            self.driver.get(url)

            wait = WebDriverWait(self.driver, 120)

            page_state = self._wait_for_not_found_or_copy_buttons(wait)
            if page_state == "not_found":
                print(f"Skipping not-found report URL: '{url}'")
                return

            all_copy_buttons = page_state
            last_copy_button = all_copy_buttons[-1]
            wait.until(EC.element_to_be_clickable(last_copy_button)).click()

            xpath = "//div[@role='menuitem' and normalize-space(text())='Copy response']"
            el = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
            el.click()

            clipboard_content = pyperclip.paste()

            # Check if the content exists AND if it does NOT contain the "#NoVulnerability" string
            if clipboard_content and (
                    "NoVulnerability" not in clipboard_content and
                    "I cannot perform this security" not in clipboard_content):

                filename = f"validated/audit_{uuid.uuid4().hex}.md"
                with open(filename, "w") as f:
                    f.write(clipboard_content)
                print(f"Saved report for question {url} to {filename}")
            else:
                # This will now handle both empty clipboard and cases where no vulnerability was found
                print(f"No vulnerability found or clipboard was empty for: '{url}'")

            # Clear textarea for next question
            time.sleep(1)  # give it a moment to clear
        except Exception as e:
            print(f"There was an error in index {url}: {e}")


def generate_validated_questions_for_ask():
    audited_directory = os.environ.get('AUDITED_DIR', 'audited')
    validated_questions_directory = os.environ.get("VALIDATED_QUESTIONS_DIR", "validated_questions")
    validated_questions_pending_directory = os.environ.get("VALIDATION_PENDING_DIR", 'validated_questions_pending')

    # Create the directories if they don't exist
    os.makedirs(audited_directory, exist_ok=True)
    os.makedirs(validated_questions_directory, exist_ok=True)
    os.makedirs(validated_questions_pending_directory, exist_ok=True)

    # Get all JSON files in the automation directory
    audited_files = sorted(Path(audited_directory).glob('*.md'))

    if not audited_files:
        raise FileNotFoundError("No automation files found")

    moved_files = []
    counter = 0

    # Move up to 20 files
    for file_path in audited_files:
        try:
            if counter >= 25:
                break

            # Create destination path
            dest_path = os.path.join(validated_questions_pending_directory, file_path.name)

            # Skip if file with same name already exists in destination
            if os.path.exists(dest_path):
                # Append a timestamp to make filename unique
                base_name = file_path.stem
                extension = file_path.suffix
                timestamp = int(time.time())
                dest_path = os.path.join(validated_questions_pending_directory, f"{base_name}_{timestamp}{extension}")

            # Move the file
            shutil.move(str(file_path), dest_path)
            moved_files.append(dest_path)
            counter += 1
            print(f"Moved {file_path} to {dest_path}")

        except Exception as e:
            print(f"Error moving {file_path}: {e}")
            continue

    if not moved_files:
        print("No files were moved")
        return None

    # Generate file path
    validated_questions_file = f"{uuid.uuid4().hex}.json"  # Keep the same filename but ensure .json extension
    file_path = os.path.join(validated_questions_directory, validated_questions_file)

    # Create or update .env file with the file path
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'w') as f:
        f.write(f"VALIDATED_QUESTIONS_PATH={file_path}\n")

    os.environ['VALIDATED_QUESTIONS_PATH'] = file_path
    print(os.environ.get('VALIDATED_QUESTIONS_PATH'))

    print(f"Successfully moved {len(moved_files)} files to {validated_questions_pending_directory}")
    return moved_files


def generate_scanned_questions_for_ask():
    scanned_directory = os.environ.get('SCANNED_DIR', 'scanned')
    validated_questions_directory = os.environ.get("VALIDATED_QUESTIONS_DIR", "validated_questions")
    validated_questions_pending_directory = os.environ.get("VALIDATION_PENDING_DIR", 'validated_questions_pending')

    # Create the directories if they don't exist
    os.makedirs(scanned_directory, exist_ok=True)
    os.makedirs(validated_questions_directory, exist_ok=True)
    os.makedirs(validated_questions_pending_directory, exist_ok=True)

    # Get all JSON files in the automation directory
    audited_files = sorted(Path(scanned_directory).glob('*.md'))

    if not audited_files:
        raise FileNotFoundError("No automation files found")

    moved_files = []
    counter = 0

    # Move up to 20 files
    for file_path in audited_files:
        try:
            if counter >= 25:
                break

            # Create destination path
            dest_path = os.path.join(validated_questions_pending_directory, file_path.name)

            # Skip if file with same name already exists in destination
            if os.path.exists(dest_path):
                # Append a timestamp to make filename unique
                base_name = file_path.stem
                extension = file_path.suffix
                timestamp = int(time.time())
                dest_path = os.path.join(validated_questions_pending_directory, f"{base_name}_{timestamp}{extension}")

            # Move the file
            shutil.move(str(file_path), dest_path)
            moved_files.append(dest_path)
            counter += 1
            print(f"Moved {file_path} to {dest_path}")

        except Exception as e:
            print(f"Error moving {file_path}: {e}")
            continue

    if not moved_files:
        print("No files were moved")
        return None

    # Generate file path
    validated_questions_file = f"{uuid.uuid4().hex}.json"  # Keep the same filename but ensure .json extension
    file_path = os.path.join(validated_questions_directory, validated_questions_file)

    # Create or update .env file with the file path
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'w') as f:
        f.write(f"VALIDATED_QUESTIONS_PATH={file_path}\n")

    os.environ['VALIDATED_QUESTIONS_PATH'] = file_path
    print(os.environ.get('VALIDATED_QUESTIONS_PATH'))

    print(f"Successfully moved {len(moved_files)} files to {validated_questions_pending_directory}")
    return moved_files


def generate_file_path_get_validated():
    validated_directory = os.environ.get("VALIDATED_DIR", "validated")
    validated_questions_directory = os.environ.get('VALIDATED_QUESTIONS_DIR', 'validated_questions')
    validation_pending_directory = os.environ.get("VALIDATION_PENDING_DIR", 'validation_pending')

    # Create the directories if they don't exist
    os.makedirs(validated_directory, exist_ok=True)
    os.makedirs(validated_questions_directory, exist_ok=True)
    os.makedirs(validation_pending_directory, exist_ok=True)

    # Get all JSON files in the automation directory
    validated_questions_files = sorted(Path(validated_questions_directory).glob('*.json'))

    if not validated_questions_files:
        raise FileNotFoundError("No validation files found")

    moved_files = []
    counter = 0

    # Move up to 20 files
    for file_path in validated_questions_files:
        try:
            if counter >= 20:
                break

            # Create destination path
            dest_path = os.path.join(validation_pending_directory, file_path.name)

            # Skip if file with same name already exists in destination
            if os.path.exists(dest_path):
                # Append a timestamp to make filename unique
                base_name = file_path.stem
                extension = file_path.suffix
                timestamp = int(time.time())
                dest_path = os.path.join(validation_pending_directory, f"{base_name}_{timestamp}{extension}")

            # Move the file
            shutil.move(str(file_path), dest_path)
            moved_files.append(dest_path)
            counter += 1
            print(f"Moved {file_path} to {dest_path}")

        except Exception as e:
            print(f"Error moving {file_path}: {e}")
            continue

    if not moved_files:
        print("No files were moved")
        return None

    print(f"Successfully moved {len(moved_files)} files to {validation_pending_directory}")
    return moved_files

