import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Threat Intelligence Dashboard", () => {
  it("loads and displays IOC data from the API", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify([
          {
            id: 1,
            type: "domain",
            value: "secure-login-example.com",
            severity: "high",
            confidence: 87,
            source: "analyst",
            created_at: "2026-09-04T12:00:00Z",
          },
        ]),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
          },
        }
      )
    );

    render(<App />);

    expect(
      screen.getByText("Loading threat intelligence...")
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(
        screen.getByText("secure-login-example.com")
      ).toBeInTheDocument();
    });

    expect(screen.getByText("87%")).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
  });

  it("loads correlated intelligence when Investigate is clicked", async () => {
    const user = userEvent.setup();

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              id: 1,
              type: "domain",
              value: "secure-login-example.com",
              severity: "high",
              confidence: 87,
              source: "analyst",
              created_at: "2026-09-04T12:00:00Z",
            },
          ]),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
            },
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ioc: {
              id: 1,
              type: "domain",
              value: "secure-login-example.com",
              severity: "high",
              confidence: 87,
            },
            risk: {
              score: 80,
              level: "high",
            },
            campaigns: [
              {
                campaign_id: 1,
                campaign_name: "Operation Shadow Login",
                threat_actor: "APT Example Group",
                techniques: [
                  {
                    technique_id: "T1566.002",
                    name: "Spearphishing Link",
                    tactic: "Initial Access",
                  },
                ],
              },
            ],
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
            },
          }
        )
      );

    render(<App />);

    const investigateButton = await screen.findByRole(
      "button",
      { name: "Investigate" }
    );

    await user.click(investigateButton);

    expect(
      await screen.findByText("Operation Shadow Login")
    ).toBeInTheDocument();

    expect(
      screen.getByText("APT Example Group")
    ).toBeInTheDocument();

    expect(
      screen.getByText("T1566.002")
    ).toBeInTheDocument();

    expect(
      screen.getByText("Spearphishing Link")
    ).toBeInTheDocument();

    expect(
      screen.getByText("Initial Access")
    ).toBeInTheDocument();
  });

  it("shows an error message when the IOC API fails", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(
      new Error("API unavailable")
    );

    render(<App />);

    expect(
      await screen.findByText(
        "Unable to connect to the threat intelligence API."
      )
    ).toBeInTheDocument();
  });
});