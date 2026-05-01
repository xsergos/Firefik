import CodeMirror from "@uiw/react-codemirror";
import { javascript } from "@codemirror/lang-javascript";

type Props = {
  value: string;
  onChange: (value: string) => void;
  className?: string;
};

export default function PolicyEditor({ value, onChange, className }: Props) {
  return (
    <CodeMirror
      value={value}
      onChange={onChange}
      extensions={[javascript()]}
      height="260px"
      className={className ?? "font-mono text-xs border rounded w-full min-h-[260px]"}
      basicSetup={{
        lineNumbers: true,
        highlightActiveLine: true,
        foldGutter: false,
      }}
    />
  );
}
