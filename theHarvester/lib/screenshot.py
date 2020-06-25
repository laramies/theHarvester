from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import time

options = Options()
options.headless = True
browser = webdriver.Firefox(options=options)
browser.minimize_window()
#time.sleep(3)
browser.get('https://leidos.com')
browser.save_screenshot('test-screenshot.png')
browser.close()