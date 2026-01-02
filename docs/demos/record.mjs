import { chromium } from "playwright";
import fs from "node:fs";

const outDir = "pw-out";
fs.mkdirSync(outDir, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const cursorOverlayScript = `
(() => {
  const style = document.createElement('style');
  style.textContent = \`
    #__pw_cursor {
      position: fixed;
      top: 0; left: 0;
      width: 18px; height: 18px;
      transform: translate(-100px, -100px);
      z-index: 2147483647;
      pointer-events: none;
    }
    #__pw_cursor svg { width: 18px; height: 18px; }
    #__pw_cursor .dot {
      fill: rgba(255,255,255,0.9);
      stroke: rgba(0,0,0,0.85);
      stroke-width: 2;
    }
    #__pw_click {
      position: fixed;
      width: 8px; height: 8px;
      border-radius: 50%;
      transform: translate(-100px, -100px);
      z-index: 2147483646;
      pointer-events: none;
      opacity: 0;
      border: 2px solid rgba(0,0,0,0.6);
    }
  \`;
  document.documentElement.appendChild(style);

  const cursor = document.createElement('div');
  cursor.id = '__pw_cursor';
  cursor.innerHTML = \`
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle class="dot" cx="12" cy="12" r="6"></circle>
    </svg>
  \`;
  document.documentElement.appendChild(cursor);

  const click = document.createElement('div');
  click.id = '__pw_click';
  document.documentElement.appendChild(click);

  let x = -100, y = -100;
  const move = (nx, ny) => {
    x = nx; y = ny;
    cursor.style.transform = \`translate(\${x}px, \${y}px)\`;
    click.style.transform = \`translate(\${x}px, \${y}px)\`;
  };

  window.addEventListener('pointermove', (e) => move(e.clientX, e.clientY), { passive: true });
  window.addEventListener('mousemove', (e) => move(e.clientX, e.clientY), { passive: true });

  window.addEventListener('pointerdown', () => {
    click.style.transition = 'none';
    click.style.opacity = '0.9';
    click.style.width = '8px';
    click.style.height = '8px';
    requestAnimationFrame(() => {
      click.style.transition = 'all 250ms ease-out';
      click.style.opacity = '0';
      click.style.width = '28px';
      click.style.height = '28px';
    });
  }, { passive: true });
})();
`;

// Converts native <select> dropdowns into in-page listboxes while focused/clicked,
// so the “dropdown” actually appears in the recorded page surface.
const selectListboxScript = `
(() => {
  const enhance = (sel) => {
    if (sel.__pwEnhanced) return;
    sel.__pwEnhanced = true;

    const originalSize = sel.getAttribute('size');

    const open = () => {
      // Prevent the native popup and instead expand in-page
      const n = Math.min(Math.max(sel.options.length, 2), 12);
      sel.setAttribute('size', String(n));
      sel.style.background = sel.style.background || 'white';
    };

    const close = () => {
      if (originalSize === null) sel.removeAttribute('size');
      else sel.setAttribute('size', originalSize);
    };

    sel.addEventListener('mousedown', (e) => {
      // Stop native dropdown UI
      e.preventDefault();
      open();
      sel.focus();
    });

    sel.addEventListener('blur', () => close());
    sel.addEventListener('change', () => close());
    sel.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' || e.key === 'Enter') close();
    });
  };

  const scan = () => document.querySelectorAll('select').forEach(enhance);

  // initial + dynamic pages
  scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
})();
`;

(async () => {
  const browser = await chromium.launch({
    headless: false,
    // Optional: keeps it from throttling when not focused
    args: ["--disable-renderer-backgrounding", "--disable-background-timer-throttling"],
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 1024 },
    recordVideo: { dir: outDir, size: { width: 1280, height: 1024 } },
  });

  // Make sure overlays exist before any page scripts run
  await context.addInitScript(cursorOverlayScript);
  await context.addInitScript(selectListboxScript);

  const page = await context.newPage();

  // networkidle is often a trap for SPAs; use domcontentloaded for recording
  await page.goto("http://127.0.0.1:7890", { waitUntil: "domcontentloaded" });

  // Give yourself time to interact manually
  await sleep(45000);

  await context.close(); // finalizes video
  await browser.close();

  console.log("Done. Video saved under:", outDir);
})();
