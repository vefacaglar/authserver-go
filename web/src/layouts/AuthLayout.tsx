import type { ReactNode } from "react";

// Centered 400px card, matching the former server-rendered auth pages.
export default function AuthLayout({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 bg-[#121212]">
      <div className="sm:mx-auto sm:w-full sm:max-w-[400px]">
        <div className="bg-[#1a1a1a] p-8 border border-zinc-800/60 shadow-lg">
          <div className="mb-6">
            <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">{heading}</h1>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}
