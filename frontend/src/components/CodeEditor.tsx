import Prism from "prismjs";
import "prismjs/components/prism-c";
import "prismjs/components/prism-java";
import "prismjs/components/prism-python";
import "prismjs/components/prism-typescript";
import { useMemo } from "react";
import Editor from "react-simple-code-editor";
import type { Language, Severity } from "../types";

// react-simple-code-editor is CommonJS; depending on the bundler the component is on `.default`.
const SimpleEditor = ((Editor as unknown as { default?: typeof Editor }).default ?? Editor) as typeof Editor;

export const EDITOR_ID = "code-input";

/** Prism escapes the code it highlights, so its output is safe to use as markup. */
function highlight(code: string, language: Language, flagged: Map<number, Severity>): string {
  const grammar = Prism.languages[language];
  const html = grammar ? Prism.highlight(code, grammar, language) : escapeHtml(code);
  return html
    .split("\n")
    .map((line, i) => {
      const sev = flagged.get(i + 1);
      return `<span class="editor-ln${sev ? ` ln-${sev}` : ""}">${i + 1}</span>${line}`;
    })
    .join("\n");
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  language: Language;
  /** line number -> worst severity found there (only passed while the review is current) */
  flaggedLines?: Map<number, Severity>;
  disabled?: boolean;
}

export default function CodeEditor({ value, onChange, language, flaggedLines, disabled }: Props) {
  const flagged = useMemo(() => flaggedLines ?? new Map<number, Severity>(), [flaggedLines]);

  return (
    <div className="scroll-thin max-h-[540px] min-h-[340px] overflow-auto rounded-lg border border-ink-700 bg-ink-900 focus-within:border-accent-500/60">
      <SimpleEditor
        value={value}
        onValueChange={onChange}
        highlight={(code) => highlight(code, language, flagged)}
        padding={16}
        textareaId="code-input"
        placeholder="Paste or type code here, or load a sample above…"
        disabled={disabled}
        className="code-editor"
        style={{ minHeight: 340 }}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
      />
    </div>
  );
}
