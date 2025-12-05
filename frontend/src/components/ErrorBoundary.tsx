import type { ReactNode } from "react";
import { Component } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

export default class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div className="card rounded-3xl border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-100">
            Something went wrong while rendering this section. Try refreshing the
            page.
          </div>
        )
      );
    }

    return this.props.children;
  }
}
