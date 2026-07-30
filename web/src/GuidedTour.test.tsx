import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  GUIDED_TOUR_STORAGE_KEY,
  GuidedTour,
} from "./GuidedTour";

const originalScrollIntoView = Object.getOwnPropertyDescriptor(
  HTMLElement.prototype,
  "scrollIntoView",
);
let scrollIntoViewMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  window.localStorage.clear();
  scrollIntoViewMock = vi.fn();
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: scrollIntoViewMock,
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();

  if (originalScrollIntoView) {
    Object.defineProperty(
      HTMLElement.prototype,
      "scrollIntoView",
      originalScrollIntoView,
    );
  } else {
    Reflect.deleteProperty(HTMLElement.prototype, "scrollIntoView");
  }
});

describe("GuidedTour", () => {
  it("moves forward and back through the three passive steps", () => {
    render(<GuidedTour />);

    fireEvent.click(screen.getByRole("button", { name: "Start judge tour" }));
    const firstHeading = screen.getByRole("heading", {
      name: "Run a governed audit",
    });
    expect(firstHeading).toBeInTheDocument();
    expect(firstHeading).toHaveFocus();
    expect(screen.getByText("Step 1 of 3")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(
      screen.getByRole("heading", {
        name: "Inspect temporal provenance and blast radius",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("Step 2 of 3")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(
      screen.getByRole("heading", { name: "Run a governed audit" }),
    ).toBeInTheDocument();
  });

  it("persists dismissal and completion while keeping restart available", () => {
    const firstRender = render(<GuidedTour />);

    fireEvent.click(screen.getByRole("button", { name: "Start judge tour" }));
    fireEvent.click(screen.getByRole("button", { name: "Dismiss tour" }));

    expect(window.localStorage.getItem(GUIDED_TOUR_STORAGE_KEY)).toBe(
      "dismissed",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Restart judge tour" }),
    ).toBeInTheDocument();

    firstRender.unmount();
    const secondRender = render(<GuidedTour />);
    fireEvent.click(screen.getByRole("button", { name: "Restart judge tour" }));

    expect(window.localStorage.getItem(GUIDED_TOUR_STORAGE_KEY)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(
      screen.getByRole("heading", {
        name: "Review the exact plan and terminal proof",
      }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Finish tour" }));
    expect(window.localStorage.getItem(GUIDED_TOUR_STORAGE_KEY)).toBe(
      "completed",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Tour completed.")).toBeInTheDocument();

    secondRender.unmount();
    render(<GuidedTour />);
    expect(screen.getByText("Tour completed.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Restart judge tour" }),
    ).toBeInTheDocument();
  });

  it("never scrolls or calls an API automatically", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(
      <>
        <div id="custom-run-target">Run target</div>
        <GuidedTour targetIds={{ "run-audit": "custom-run-target" }} />
      </>,
    );

    expect(scrollIntoViewMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Start judge tour" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Back" }));

    expect(scrollIntoViewMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Show this area" }));
    expect(scrollIntoViewMock).toHaveBeenCalledOnce();
    expect(scrollIntoViewMock).toHaveBeenCalledWith({
      behavior: "smooth",
      block: "center",
      inline: "nearest",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("remains usable when localStorage access fails", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
      throw new Error("storage unavailable");
    });

    render(<GuidedTour />);
    fireEvent.click(screen.getByRole("button", { name: "Start judge tour" }));
    fireEvent.click(screen.getByRole("button", { name: "Dismiss tour" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Tour dismissed.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Restart judge tour" }),
    ).toBeInTheDocument();
  });

  it("dismisses with Escape and returns focus to the trigger", () => {
    render(<GuidedTour />);
    const trigger = screen.getByRole("button", { name: "Start judge tour" });

    fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog");
    expect(
      screen.getByRole("heading", { name: "Run a governed audit" }),
    ).toHaveFocus();

    fireEvent.keyDown(dialog, { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Restart judge tour" }),
    ).toHaveFocus();
    expect(window.localStorage.getItem(GUIDED_TOUR_STORAGE_KEY)).toBe(
      "dismissed",
    );
  });
});
