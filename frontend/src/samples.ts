// Demo inputs. The same files are used by the backend tests (../samples).
import safeC from "../../samples/safe.c?raw";
import safeJava from "../../samples/safe.java?raw";
import safeJs from "../../samples/safe.js?raw";
import safePy from "../../samples/safe.py?raw";
import safeTs from "../../samples/safe.ts?raw";
import vulnC from "../../samples/vulnerable.c?raw";
import vulnJava from "../../samples/vulnerable.java?raw";
import vulnJs from "../../samples/vulnerable.js?raw";
import vulnPy from "../../samples/vulnerable.py?raw";
import vulnTs from "../../samples/vulnerable.ts?raw";
import type { Language } from "./types";

export const SAMPLES: Record<Language, { vulnerable: string; safe: string }> = {
  python: { vulnerable: vulnPy, safe: safePy },
  javascript: { vulnerable: vulnJs, safe: safeJs },
  typescript: { vulnerable: vulnTs, safe: safeTs },
  java: { vulnerable: vulnJava, safe: safeJava },
  c: { vulnerable: vulnC, safe: safeC },
};
