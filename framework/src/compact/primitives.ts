// Pure TypeScript compact primitives (tokens, text measurement, motion, scoped input, selection)
// without importing `compact/app.tsx` or `compact/controls.tsx`, so custom-framed apps only bake
// the exact font slots they actually render.

import { createMemo, createSignal, type Accessor } from "solid-js";
import { ENUMS } from "../../../contracts/spec/spec.ts";

export * from "./tokens.ts";
export * from "./text.ts";
export {
  MOTION,
  FADES,
  SECTION_SHIFT,
  glide,
  place,
  createFollower,
  slideIn,
  slideOut,
  slideFrom,
  arrive,
  flip,
  pop,
  bump,
  type Rect,
} from "./motion.ts";
export {
  navKeyOf,
  onNavIn,
  onKeyIn,
  setActiveScope,
  activeInputScope,
  installCompactInput,
  GLOBAL_SCOPE,
  KEY_LABEL,
  type NavKey,
  type NavEvent,
  type NavHandler,
  type KeyHandler,
  type Scope,
} from "./input.ts";

export interface Selection {
  index: Accessor<number>;
  set: (index: number) => void;
  move: (delta: number, wrap?: boolean) => void;
}

export function createSelection(count: Accessor<number>, initial = 0): Selection {
  const [raw, setRaw] = createSignal(initial);
  const index = createMemo(() => {
    const n = count();
    if (n <= 0) return 0;
    return Math.max(0, Math.min(n - 1, raw()));
  });
  const set = (next: number) => {
    const n = count();
    setRaw(n <= 0 ? 0 : Math.max(0, Math.min(n - 1, next)));
  };
  const move = (delta: number, wrapAround = false) => {
    const n = count();
    if (n <= 0) return;
    const cur = index();
    if (wrapAround) setRaw(((cur + delta) % n + n) % n);
    else setRaw(Math.max(0, Math.min(n - 1, cur + delta)));
  };
  return { index, set, move };
}

export function display(shown: boolean): number | undefined {
  return shown ? undefined : ENUMS.Display.None;
}
