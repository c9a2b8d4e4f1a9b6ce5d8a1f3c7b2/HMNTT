import json
import os
import random
import shutil
import sys
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

sys.path.append(str(Path(__file__).parent.parent))

from questions import  BASE_URL


class IndexDeepwiki:
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
        super(IndexDeepwiki, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()


    def index_repo(self, url):
        wait = WebDriverWait(self.driver, 20)

        try:
            self.driver.get(url)

            # # wait for the form containing the textarea
            form = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
            )

            if not "repository not indexed" in self.driver.page_source.lower():
                return

            # find the textarea inside the form
            textarea = form.find_element(By.CSS_SELECTOR, 'input')
            # type the question
            textarea.click()
            textarea.clear()

            email = f"devprotegik{random.randint(0,100)}@gmail.com"
            # # Use JavaScript to set the textarea value directly. It's more reliable for large text.
            # self.driver.execute_script("arguments[0].value = arguments[1];", textarea, email)
            # # Dispatch an 'input' event to make sure the web application detects the change.
            # self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
            #                            textarea)
            textarea.send_keys(email)
            textarea.send_keys(Keys.ENTER)
            time.sleep(3)
        except Exception as a:
            print(f"There was an error in index : {a}")


def main():
    try:
        # Load questions once
        repo_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'repositories.json')
        with open(repo_file, 'r', encoding='utf-8') as f:
            questions = json.load(f)

        if not isinstance(questions, list):
            raise ValueError(f"Expected a list of questions in {repo_file}, got {type(questions)}")

        total = len(questions)
        print(f"Found {total} questions in {repo_file}")

        # Process questions
        for i, question in enumerate(questions, 1):
            bot = IndexDeepwiki(teardown=True)

            print(f"[{i}/{total}] Processing: {question[:50]}...")
            bot.index_repo(question)

        # If we get here, processing was successful
        print(f"Successfully processed {i} questions")

    except Exception as e:
        print(f"Error during processing: {e}")


if __name__ == '__main__':
    main()
