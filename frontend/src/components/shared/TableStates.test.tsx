import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TableEmpty, TableError, TableLoading } from "@/components/shared/TableStates";

function wrap(ui: React.ReactElement) {
  return render(
    <table>
      <tbody>{ui}</tbody>
    </table>,
  );
}

describe("TableLoading", () => {
  it("renders the default label", () => {
    render(<TableLoading />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
  });

  it("renders a custom label", () => {
    render(<TableLoading label="Please hold" />);
    expect(screen.getByRole("status")).toHaveTextContent("Please hold");
  });
});

describe("TableEmpty", () => {
  it("renders the label in a single row spanning the given colSpan", () => {
    wrap(<TableEmpty colSpan={3} label="Nothing here" />);
    const cell = screen.getByText("Nothing here").closest("td");
    expect(cell?.getAttribute("colspan")).toBe("3");
  });

  it("renders a hint when provided", () => {
    wrap(<TableEmpty colSpan={2} label="Empty" hint="Try refreshing" />);
    expect(screen.getByText("Try refreshing")).toBeInTheDocument();
  });

  it("omits the hint paragraph when not provided", () => {
    wrap(<TableEmpty colSpan={2} label="Empty" />);
    expect(screen.queryByText(/try/i)).not.toBeInTheDocument();
  });
});

describe("TableError", () => {
  it("renders an alert with the given label", () => {
    render(<TableError label="Something broke" />);
    expect(screen.getByRole("alert")).toHaveTextContent("Something broke");
  });
});
