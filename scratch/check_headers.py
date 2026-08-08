import asyncio
import httpx
from kelan.dast.crawler import Crawler

async def main():
    crawler = Crawler(seed="https://www.erasurehq.in/", max_pages=1, max_depth=1)
    pages = await crawler.crawl()
    if not pages:
        print("No pages fetched!")
        return
    seed = pages[0]
    print("Fetched URL:", seed.url)
    print("Status:", seed.status)
    print("Headers:", seed.resp_headers)

if __name__ == "__main__":
    asyncio.run(main())
