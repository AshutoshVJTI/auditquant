import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";

/** Split GFM doc on `## ` headings into cards (first block may be untitled intro). */
export function splitMarkdownByH2(markdown: string): { title: string; body: string }[] {
  const t = markdown.trim();
  if (!t) return [];
  const parts = t.split(/\n(?=##\s+)/);
  return parts.map((block, idx) => {
    const m = block.match(/^##\s+(.+?)(?:\n|$)/);
    if (m) {
      return { title: m[1].trim(), body: block.slice(m[0].length).trim() };
    }
    return {
      title: idx === 0 ? "Overview" : "Additional notes",
      body: block.trim(),
    };
  });
}

const mdComponents: Components = {
  h2: ({ children }) => (
    <h4 className="mt-0 text-base font-semibold text-slate-900">{children}</h4>
  ),
  h3: ({ children }) => (
    <h5 className="mt-3 text-sm font-semibold text-slate-800">{children}</h5>
  ),
  p: ({ children }) => <p className="mb-2 text-sm leading-relaxed text-slate-700 last:mb-0">{children}</p>,
  ul: ({ children }) => (
    <ul className="mb-2 list-disc space-y-1 pl-5 text-sm text-slate-700">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mb-2 list-decimal space-y-1 pl-5 text-sm text-slate-700">{children}</ol>
  ),
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-slate-900">{children}</strong>,
  code: ({ className, children, ...props }) => {
    const inline = !className;
    if (inline) {
      return (
        <code
          className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[0.8rem] text-slate-800"
          {...props}
        >
          {children}
        </code>
      );
    }
    return (
      <code className={className} {...props}>
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">{children}</pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="mb-2 border-l-4 border-slate-300 pl-3 text-sm italic text-slate-600">
      {children}
    </blockquote>
  ),
  a: ({ href, children }) => (
    <a href={href} className="font-medium text-blue-700 underline decoration-blue-400/60 hover:text-blue-900">
      {children}
    </a>
  ),
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-lg border border-slate-200">
      <table className="min-w-full border-collapse text-left text-sm text-slate-800">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-slate-100">{children}</thead>,
  th: ({ children }) => (
    <th className="border border-slate-200 px-3 py-2 font-semibold text-slate-900">{children}</th>
  ),
  td: ({ children }) => <td className="border border-slate-200 px-3 py-2 text-slate-700">{children}</td>,
  hr: () => <hr className="my-4 border-slate-200" />,
};

function SectionBody({ markdown }: { markdown: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
      {markdown}
    </ReactMarkdown>
  );
}

export default function ExecutiveSummaryMarkdown({ markdown }: { markdown: string }) {
  const sections = splitMarkdownByH2(markdown);
  if (sections.length <= 1) {
    return (
      <div className="rounded-xl border border-slate-200 bg-gradient-to-b from-slate-50/80 to-white p-5 shadow-sm">
        <SectionBody markdown={markdown} />
      </div>
    );
  }
  return (
    <div className="grid gap-4 md:grid-cols-1">
      {sections.map((sec, i) => (
        <article
          key={`${sec.title}-${i}`}
          className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm ring-1 ring-slate-900/5"
        >
          <h4 className="border-b border-slate-100 pb-2 text-base font-semibold tracking-tight text-slate-900">
            {sec.title}
          </h4>
          <div className="pt-3">
            <SectionBody markdown={sec.body} />
          </div>
        </article>
      ))}
    </div>
  );
}
