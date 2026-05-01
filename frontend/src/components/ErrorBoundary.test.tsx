import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ErrorBoundary } from "@/components/ErrorBoundary";

function Boom(): never {
  throw new Error("kaboom");
}

function ConditionalBoom({ throwNow }: { throwNow: boolean }) {
  if (throwNow) throw new Error("kaboom");
  return <p>recovered</p>;
}

describe("ErrorBoundary", () => {
  it("renders children when no error", () => {
    render(
      <ErrorBoundary>
        <p>hello</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("hello")).toBeInTheDocument();
  });

  it("shows a fallback when a child throws and offers reload", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
      expect(screen.getByRole("alert")).toBeInTheDocument();
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /reload page/i })).toBeInTheDocument();
    } finally {
      spy.mockRestore();
    }
  });

  it("renders a custom fallback when provided", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      render(
        <ErrorBoundary fallback={<p>custom fallback</p>}>
          <Boom />
        </ErrorBoundary>,
      );
      expect(screen.getByText("custom fallback")).toBeInTheDocument();
    } finally {
      spy.mockRestore();
    }
  });

  it("clears the error state when the user clicks Try again", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { rerender } = render(
        <ErrorBoundary>
          <ConditionalBoom throwNow={true} />
        </ErrorBoundary>,
      );
      expect(screen.getByRole("alert")).toBeInTheDocument();

      rerender(
        <ErrorBoundary>
          <ConditionalBoom throwNow={false} />
        </ErrorBoundary>,
      );
      fireEvent.click(screen.getByRole("button", { name: /try again/i }));
      expect(screen.getByText("recovered")).toBeInTheDocument();
    } finally {
      spy.mockRestore();
    }
  });

  it("invokes window.location.reload when Reload page is clicked", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, reload },
    });
    try {
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      );
      fireEvent.click(screen.getByRole("button", { name: /reload page/i }));
      expect(reload).toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: original });
      spy.mockRestore();
    }
  });
});
