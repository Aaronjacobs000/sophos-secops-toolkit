// Motion: count-ups, FLIP re-ordering, enter and exit, and screen transitions.
// Everything checks reducedMotion() and falls back to an instant change.

const media = window.matchMedia("(prefers-reduced-motion: reduce)");
let forced = null;

export function reducedMotion() {
  return forced ?? media.matches;
}

/** Tests and screenshots can force motion off. */
export function setReducedMotion(on) {
  forced = on;
  document.documentElement.classList.toggle("no-motion", !!on);
}

const easeOut = (t) => 1 - Math.pow(1 - t, 3);
const tweens = new WeakMap();

/**
 * Animates the number shown in `el` from what it shows now to `to`.
 * `format` turns a number into the text. Interrupting a running tween starts
 * the new one from the value on screen, so rapid updates never jump.
 */
export function tweenNumber(el, to, format = (n) => String(Math.round(n)), ms = 900) {
  if (!el) return;
  const target = Number(to);
  if (!Number.isFinite(target)) {
    el.textContent = format(to);
    el.dataset.value = "";
    return;
  }
  const from = el.dataset.value !== undefined && el.dataset.value !== "" ? Number(el.dataset.value) : 0;
  el.dataset.value = String(target);
  const running = tweens.get(el);
  if (running) cancelAnimationFrame(running.raf);
  if (reducedMotion() || from === target || document.hidden) {
    el.textContent = format(target);
    return;
  }
  const current = running ? running.current : from;
  const start = performance.now();
  const state = { raf: 0, current };
  const step = (t) => {
    const p = Math.min(1, (t - start) / ms);
    state.current = current + (target - current) * easeOut(p);
    el.textContent = format(state.current);
    if (p < 1) state.raf = requestAnimationFrame(step);
    else tweens.delete(el);
  };
  state.raf = requestAnimationFrame(step);
  tweens.set(el, state);
  if (from !== target && el.dataset.flash !== "off" && el.isConnected && running === undefined && from !== 0) {
    el.animate([{ textShadow: "0 0 0 transparent" }, { textShadow: "0 0 18px var(--accent)" }, { textShadow: "0 0 0 transparent" }], { duration: 900, easing: "ease-out" });
  }
}

/** Snapshot every keyed child's position, so flipPlay can animate them to the new layout. */
export function flipSnapshot(container, selector = "[data-key]") {
  const rects = new Map();
  for (const el of container.querySelectorAll(selector)) rects.set(el.dataset.key, el.getBoundingClientRect());
  return rects;
}

/** Plays the FLIP: every element that moved glides from where it was. New ones fade in. */
export function flipPlay(container, before, selector = "[data-key]", options = {}) {
  if (reducedMotion()) return;
  const duration = options.duration ?? 620;
  let entering = 0;
  for (const el of container.querySelectorAll(selector)) {
    const prev = before.get(el.dataset.key) ?? options.fallbackRects?.get(el.dataset.key);
    const now = el.getBoundingClientRect();
    if (!prev) {
      el.animate(
        [
          { opacity: 0, transform: "translateY(10px) scale(0.97)" },
          { opacity: 1, transform: "none" },
        ],
        { duration: 520, delay: Math.min(entering++ * 28, 600), easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" },
      );
      continue;
    }
    const dx = prev.left - now.left;
    const dy = prev.top - now.top;
    if (Math.abs(dx) < 1 && Math.abs(dy) < 1) continue;
    el.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: "none" }], { duration, easing: "cubic-bezier(.2,.75,.15,1)" });
  }
}

/**
 * Keyed list reconciliation with FLIP. `items` are rendered by `create(item)`
 * and refreshed by `update(el, item)`. Removed elements fade out in place.
 */
export function reconcile(container, items, key, create, update, options = {}) {
  const before = flipSnapshot(container);
  const existing = new Map([...container.children].filter((c) => c.dataset.key !== undefined).map((c) => [c.dataset.key, c]));
  const keep = new Set();
  let prev = null;
  for (const item of items) {
    const k = String(key(item));
    keep.add(k);
    let el = existing.get(k);
    if (!el) {
      el = create(item);
      el.dataset.key = k;
    } else {
      update(el, item);
    }
    const next = prev ? prev.nextElementSibling : container.firstElementChild;
    if (next !== el) container.insertBefore(el, next);
    prev = el;
  }
  for (const [k, el] of existing) {
    if (keep.has(k)) continue;
    if (reducedMotion() || options.instantExit) {
      el.remove();
      continue;
    }
    const r = el.getBoundingClientRect();
    const parent = container.getBoundingClientRect();
    el.style.position = "absolute";
    el.style.left = `${r.left - parent.left}px`;
    el.style.top = `${r.top - parent.top}px`;
    el.style.width = `${r.width}px`;
    el.style.pointerEvents = "none";
    delete el.dataset.key;
    container.append(el);
    el.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "scale(0.94)" }], { duration: 320, easing: "ease-in", fill: "forwards" }).finished.then(() => el.remove(), () => el.remove());
  }
  flipPlay(container, before, "[data-key]", options);
}

/** Staggered entrance for a freshly built screen. */
export function revealChildren(root, selector = ".reveal") {
  const els = [...root.querySelectorAll(selector)];
  if (reducedMotion()) return;
  els.forEach((el, i) => {
    el.animate(
      [
        { opacity: 0, transform: "translateY(18px)", filter: "blur(6px)" },
        { opacity: 1, transform: "none", filter: "blur(0)" },
      ],
      { duration: 700, delay: 60 + i * 55, easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" },
    );
  });
}

/** A ring pulse on a tile whose value just changed. */
export function pulse(el, color = "var(--accent)") {
  if (!el || reducedMotion()) return;
  el.animate([{ boxShadow: `0 0 0 0 ${color}` }, { boxShadow: "0 0 0 10px transparent" }], { duration: 900, easing: "ease-out" });
}

/**
 * Runs a DOM swap inside a view transition when the browser has them, with a
 * direction for the slide. Without them, or with reduced motion, it swaps at once.
 */
export async function transition(swap, direction = "forward") {
  document.documentElement.dataset.dir = direction;
  if (!document.startViewTransition || reducedMotion()) {
    await swap();
    return;
  }
  const vt = document.startViewTransition(async () => {
    await swap();
  });
  try {
    await vt.finished;
  } catch {
    // A transition skipped by a newer one is fine.
  }
}

/** Draws an SVG path on, start to end. */
export function drawPath(path, ms = 1200, delay = 0) {
  if (reducedMotion() || !path.getTotalLength) return;
  const len = path.getTotalLength();
  path.style.strokeDasharray = `${len}`;
  path.style.strokeDashoffset = `${len}`;
  const a = path.animate([{ strokeDashoffset: len }, { strokeDashoffset: 0 }], { duration: ms, delay, easing: "cubic-bezier(.45,.05,.2,1)", fill: "forwards" });
  a.finished.then(() => {
    path.style.strokeDasharray = "";
    path.style.strokeDashoffset = "";
    a.cancel();
  }, () => undefined);
}
