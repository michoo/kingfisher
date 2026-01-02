import { chromium } from "playwright";
import fs from "node:fs";

const outDir = "pw-out";
fs.mkdirSync(outDir, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch({ headless: false });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordVideo: { dir: outDir, size: { width: 1280, height: 720 } },
  });

  const page = await context.newPage();

  await page.goto("http://127.0.0.1:7890", { waitUntil: "networkidle" });
  await sleep(25000);

//   await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
//   await sleep(800);

//   await page.evaluate(() => window.scrollTo(0, 0));
//   await sleep(800);

  await context.close(); // finalizes video
  await browser.close();

  console.log("Done. Video saved under:", outDir);
})();
