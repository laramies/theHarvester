"""
Screenshot module that utilizes pyppeteer in async fashion
to break urls into list and assign them to workers in a queue
"""
import asyncio
from pyppeteer import launch


async def worker(queue):
    while True:
        # Get a "work item" out of the queue.
        stor = await queue.get()
        try:
            await stor
            queue.task_done()
            # Notify the queue that the "work item" has been processed.
        except Exception:
            queue.task_done()


async def screenshot_handler(lst):
    queue = asyncio.Queue()

    for stor_method in lst:
        # enqueue the coroutines
        queue.put_nowait(stor_method)
    # Create five worker tasks to process the queue concurrently.
    tasks = []
    for i in range(5):
        task = asyncio.create_task(worker(queue))
        tasks.append(task)

    # Wait until the queue is fully processed.
    await queue.join()

    # Cancel our worker tasks.
    for task in tasks:
        task.cancel()
    # Wait until all worker tasks are cancelled.
    await asyncio.gather(*tasks, return_exceptions=True)


async def take_screenshot(url):
    url = f'http://{url}' if ('http' not in url and 'https' not in url) else url
    url.replace('www.', '')
    print(f'Taking a screenshot of: {url}')
    browser = await launch(headless=True, ignoreHTTPSErrors=True, args=["--no-sandbox"])
    page = await browser.newPage()
    try:
        await page.setUserAgent(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36')
        # default wait time of 30 seconds
        await page.goto(url)
        await page.screenshot({'path': f'D:\\repos\\theHarvester\\theHarvester\\screenshot\\{url.replace("https://", "").replace("http://", "")}.png'})
    except Exception as e:
        print(f'Exception occurred: {e} ')
    # No matter what happens make sure browser is closed
    await browser.close()
