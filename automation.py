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
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import audit_format, BASE_URL


class Deepwiki:
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
        self.collections_url = []
        super(Deepwiki, self).__init__()

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

    def ask_question(self, question_gotten):
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
                formatted_question = audit_format(question_gotten)

                # Use JavaScript to set the textarea value directly. It's more reliable for large text.
                self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
                # Dispatch an 'input' event to make sure the web application detects the change.
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                           textarea)
                textarea.send_keys(".. ")

                textarea.send_keys(Keys.ENTER)

                time.sleep(10)
                current_url = self.driver.current_url

                # add the current url to collections
                self.save_to_file_path(question_gotten, current_url)
                break
            except Exception as a:
                print(f"There was an error ")
                print(f"{self.driver.current_url}")
                time.sleep(10)
                continue

    def save_to_file_path(self, question, url):
        """Save question and URL to collections.json"""
        file_path = config("AUTOMATION_PATH")

        # Load existing data or start fresh
        try:
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid collections.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "question": question,
            "url": url,
            "timestamp": str(datetime.now()),
            "report_generated": False
        })

        # Save with proper formatting
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                print("dumped")
        except Exception as e:
            print(f"Error saving to collections: {e}")


class GetReports:
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
        self.implicit_wait_seconds = 50
        self.driver.implicitly_wait(self.implicit_wait_seconds)
        self.collections_url = []
        super(GetReports, self).__init__()

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
        os.makedirs("audited", exist_ok=True)
        try:
            self.driver.get(url)
            self.driver.implicitly_wait(0)
            wait = WebDriverWait(self.driver, 20, poll_frequency=0.25)

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
                    "NoVulnerability" not in clipboard_content  ):
                filename = f"audited/audit_{uuid.uuid4().hex}.md"
                with open(filename, "w") as f:
                    f.write(clipboard_content)
                print(f"Saved report for question {url} to {filename}")
            else:
                # This will now handle both empty clipboard and cases where no vulnerability was found
                print(f"No vulnerability found or clipboard was empty for: '{url}'")

            # Clear textarea for next question
            time.sleep(1)  # give it a moment to clear
        except TimeoutException:
            if self._is_not_found_url(self.driver.current_url):
                print(f"Skipping not-found report URL: '{url}'")
                return
            print(f"Timed out waiting for report UI for: '{url}'")
        except Exception as e:
            print(f"There was an error in index {url}: {e}")
        finally:
            self.driver.implicitly_wait(self.implicit_wait_seconds)


def generate_file_path():
    # Get the directory from environment variable, or use 'automation' as default
    automation_directory = os.environ.get('AUTOMATION_DIR', 'automation')
    question_directory = os.environ.get("QUESTION_DIR", 'question')
    question_pending_directory = os.environ.get("QUESTION_PENDING_DIR", 'question_pending')

    # Create the directories if they don't exist
    os.makedirs(automation_directory, exist_ok=True)
    os.makedirs(question_directory, exist_ok=True)
    os.makedirs(question_pending_directory, exist_ok=True)

    question_files = sorted(Path(question_directory).glob('*.json'))

    if not question_files:
        raise FileNotFoundError(f"No question files found in {question_directory}")

    # Get the first file
    source_file = question_files[0]
    file_name = source_file.name

    # Define destination path in pending directory
    destination_file = Path(question_pending_directory) / file_name
    automation_file = f"{source_file.stem}.json"  # Keep the same filename but ensure .json extension

    try:
        # Move the file to pending directory
        source_file.rename(destination_file)
        print(f"Moved {file_name} to {question_pending_directory}")
    except Exception as e:
        raise IOError(f"Failed to move {file_name} to {question_pending_directory}: {e}")

    # Generate file path
    file_path = os.path.join(automation_directory, automation_file)

    # Create or update .env file with the file path
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'w') as f:
        f.write(f"AUTOMATION_PATH={file_path}\n")

    os.environ['AUTOMATION_PATH'] = file_path
    print(os.environ.get('AUTOMATION_PATH'))

    return str(automation_file)


def generate_file_path_get_automated():
    audited_directory = os.environ.get("AUDITED_DIR", "audited")
    automation_directory = os.environ.get('AUTOMATION_DIR', 'automation')
    automation_pending_directory = os.environ.get("AUTOMATION_PENDING_DIR", 'automation_pending')

    # Create the directories if they don't exist
    os.makedirs(audited_directory, exist_ok=True)
    os.makedirs(automation_directory, exist_ok=True)
    os.makedirs(automation_pending_directory, exist_ok=True)

    # Get all JSON files in the automation directory
    automation_files = sorted(Path(automation_directory).glob('*.json'))

    if not automation_files:
        raise FileNotFoundError("No automation files found")

    moved_files = []
    counter = 0

    # Move up to 20 files
    for file_path in automation_files:
        try:
            if counter >= 20:
                break

            # Create destination path
            dest_path = os.path.join(automation_pending_directory, file_path.name)

            # Skip if file with same name already exists in destination
            if os.path.exists(dest_path):
                # Append a timestamp to make filename unique
                base_name = file_path.stem
                extension = file_path.suffix
                timestamp = int(time.time())
                dest_path = os.path.join(automation_pending_directory, f"{base_name}_{timestamp}{extension}")

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

    print(f"Successfully moved {len(moved_files)} files to {automation_pending_directory}")
    return moved_files
