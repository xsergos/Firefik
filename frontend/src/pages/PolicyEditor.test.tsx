import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import PolicyEditor from "./PolicyEditor";

vi.mock("@uiw/react-codemirror", () => ({
  default: ({
    value,
    onChange,
    className,
  }: {
    value: string;
    onChange: (v: string) => void;
    className?: string;
  }) => (
    <textarea
      data-testid="policy-editor-cm"
      className={className}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

vi.mock("@codemirror/lang-javascript", () => ({
  javascript: () => ({ __tag: "js-extension" }),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("PolicyEditor", () => {
  it("passes the value through to the editor", () => {
    render(<PolicyEditor value="policy 'p' {}" onChange={() => {}} />);
    const ta = screen.getByTestId("policy-editor-cm") as HTMLTextAreaElement;
    expect(ta.value).toBe("policy 'p' {}");
  });

  it("invokes onChange when the user edits", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<PolicyEditor value="" onChange={onChange} />);
    const ta = screen.getByTestId("policy-editor-cm");
    await user.type(ta, "abc");
    expect(onChange).toHaveBeenCalled();
    const last = onChange.mock.calls.at(-1)?.[0];
    expect(typeof last).toBe("string");
  });

  it("applies the default className when none is supplied", () => {
    render(<PolicyEditor value="" onChange={() => {}} />);
    const ta = screen.getByTestId("policy-editor-cm");
    expect(ta.className).toContain("font-mono");
    expect(ta.className).toContain("border");
  });

  it("uses a custom className when provided", () => {
    render(<PolicyEditor value="" onChange={() => {}} className="my-custom" />);
    const ta = screen.getByTestId("policy-editor-cm");
    expect(ta.className).toBe("my-custom");
  });
});
